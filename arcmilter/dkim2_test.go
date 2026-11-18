package arcmilter

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/d--j/go-milter"
	"github.com/masa23/mmauth"
	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/dkim2"
)

type dkim2Records map[string][]string

func (r dkim2Records) LookupTXT(_ context.Context, name string) ([]string, error) {
	if records, ok := r[strings.TrimSuffix(name, ".")]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Name: name, IsNotFound: true}
}

func dkim2KeyRecords(t *testing.T, key crypto.Signer) dkim2Records {
	t.Helper()
	var kind string
	var public []byte
	switch key.Public().(type) {
	case ed25519.PublicKey:
		kind, public = "ed25519", key.Public().(ed25519.PublicKey)
	case *rsa.PublicKey:
		kind = "rsa"
		var err error
		public, err = x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported test key: %T", key.Public())
	}
	record := "v=DKIM1; k=" + kind + "; p=" + base64.StdEncoding.EncodeToString(public)
	return dkim2Records{
		"s._domainkey.example.jp":   {record},
		"dk2._domainkey.example.jp": {record},
		"example.jp":                {"v=spf1 -all"},
	}
}

// DKIM2の既定リゾルバはnet.DefaultResolverを使うため、ローカルでTXTだけを返す。
func useDKIM2DNS(t *testing.T, records dkim2Records) *atomic.Int64 {
	t.Helper()
	queries := &atomic.Int64{}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, address, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			offset := 12
			var labels []string
			for offset < n && buffer[offset] != 0 {
				length := int(buffer[offset])
				offset++
				if length > 63 || offset+length >= n {
					offset = n
					break
				}
				labels = append(labels, string(buffer[offset:offset+length]))
				offset += length
			}
			offset++
			if offset+4 > n {
				continue
			}
			var answers []string
			if binary.BigEndian.Uint16(buffer[offset:]) == 16 {
				queries.Add(1)
				answers = records[strings.Join(labels, ".")]
			}
			response := []byte{buffer[0], buffer[1], 0x81, 0x80, 0, 1, 0, byte(len(answers)), 0, 0, 0, 0}
			response = append(response, buffer[12:offset+4]...)
			for _, answer := range answers {
				var text []byte
				for len(answer) > 0 {
					length := min(len(answer), 255)
					text = append(text, byte(length))
					text = append(text, answer[:length]...)
					answer = answer[length:]
				}
				response = append(response, 0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0)
				response = binary.BigEndian.AppendUint16(response, uint16(len(text)))
				response = append(response, text...)
			}
			_, _ = conn.WriteTo(response, address)
		}
	}()
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
	}}
	t.Cleanup(func() {
		net.DefaultResolver = original
		_ = conn.Close()
		<-done
	})
	return queries
}

func newDKIM2Session(t *testing.T, key crypto.Signer, verify, sign bool) (*Session, *messageModifier) {
	t.Helper()
	s, m, _ := newMessageSession(t)
	s.conf.EnableDKIM2 = verify
	s.conf.DKIM2MaxMessageBytes = 32 << 20
	domain := s.conf.Domains["example.jp"]
	domain.PrivateKeySigner = key
	domain.DKIM2, domain.DKIM2Selector = sign, "dk2"
	s.conf.Domains["example.jp"] = domain
	return s, m
}

func dkim2TestWire(t *testing.T, key crypto.Signer, envelope dkim2.Envelope, signed bool) []byte {
	t.Helper()
	raw := []byte("From: Alice <alice@example.jp>\r\nTo: Bob <bob@example.jp>\r\nCc: Carol <carol@example.jp>\r\nSubject: DKIM2 test\r\n\r\nbody\r\n")
	if !signed {
		return raw
	}
	wire, err := dkim2.Sign(raw, dkim2.SignOptions{Domain: "example.jp", Selector: "s", Key: key, Envelope: envelope})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// MAIL/RCPTはgo-milterが除去する山括弧を除き、折り返しはMilterのLF形式で渡す。
func feedDKIM2Message(t *testing.T, s *Session, m *messageModifier, raw []byte, envelope dkim2.Envelope, authn string) *mmauth.MMAuth {
	t.Helper()
	parsed, err := dkim2.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	m.authn, m.headers = authn, nil
	check := expectContinue(t)
	check(s.MailFrom(milter.RemoveAngle(envelope.MailFrom), "", m))
	for _, recipient := range envelope.RcptTo {
		check(s.RcptTo(milter.RemoveAngle(recipient), "", m))
	}
	for _, field := range parsed.Headers {
		name, value, _ := strings.Cut(strings.TrimSuffix(field, "\r\n"), ":")
		value = strings.TrimPrefix(value, " ")
		check(s.Header(name, strings.ReplaceAll(value, "\r\n", "\n"), m))
	}
	check(s.Headers(m))
	middle := len(parsed.Body) / 2
	check(s.BodyChunk(parsed.Body[:middle], m))
	check(s.BodyChunk(parsed.Body[middle:], m))
	if s.mmauth == nil {
		t.Fatal("message processor was not initialized")
	}
	return s.mmauth
}

func insertedDKIM2Count(m *messageModifier) int {
	count := 0
	for _, field := range m.headers {
		if strings.HasPrefix(field, "DKIM2-Signature:") || strings.HasPrefix(field, "Message-Instance:") {
			count++
		}
	}
	return count
}

func TestDKIM2Receiving(t *testing.T) {
	key, _ := signingKey(t)
	useDKIM2DNS(t, dkim2KeyRecords(t, key))
	envelope := dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<bob@example.jp>", "<carol@example.jp>"}}
	for _, tc := range []struct {
		name, sender string
		enabled      bool
		signed       bool
		tampered     bool
		extraRCPT    bool
		want         dkim2.Status
	}{
		{name: "disabled", signed: true},
		{name: "unsigned", enabled: true, want: dkim2.None},
		{name: "signed multiple recipients", enabled: true, signed: true, want: dkim2.Pass},
		{name: "tampered body", enabled: true, signed: true, tampered: true, want: dkim2.Fail},
		{name: "second recipient mismatch", enabled: true, signed: true, extraRCPT: true, want: dkim2.Fail},
		{name: "null sender", sender: "<>", enabled: true, signed: true, want: dkim2.Pass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, m := newDKIM2Session(t, key, tc.enabled, false)
			incoming := envelope
			if tc.sender != "" {
				incoming.MailFrom = tc.sender
			}
			raw := dkim2TestWire(t, key, incoming, tc.signed)
			if tc.tampered {
				raw = bytes.Replace(raw, []byte("\r\nbody\r\n"), []byte("\r\nchanged\r\n"), 1)
			}
			if tc.extraRCPT {
				incoming.RcptTo = []string{envelope.RcptTo[0], "<unexpected@example.jp>"}
			}
			auth := feedDKIM2Message(t, s, m, raw, incoming, "")
			expectContinue(t)(s.EndOfMessage(m))
			result := auth.GetDKIM2Verification()
			if result.Enabled != tc.enabled || result.Checked != tc.enabled || result.Err != nil || result.Result.Status != tc.want {
				t.Fatalf("DKIM2 verification: %+v, want enabled=%v status=%s", result, tc.enabled, tc.want)
			}
			found := false
			for _, field := range m.headers {
				if !strings.HasPrefix(field, "ARC-Authentication-Results:") {
					continue
				}
				results, err := arc.ParseARCAuthenticationResults(field)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range results.Results {
					if strings.HasPrefix(entry, "dkim2="+string(tc.want)) && tc.enabled {
						found = true
					}
					if !tc.enabled && strings.HasPrefix(entry, "dkim2=") {
						t.Fatalf("disabled verification added result %q", entry)
					}
				}
			}
			if tc.enabled && !found {
				t.Fatalf("DKIM2 result missing from ARC authentication results: %v", m.headers)
			}
		})
	}
}

func TestDKIM2CaptureLimitKeepsLegacyARCSigning(t *testing.T) {
	key, _ := signingKey(t)
	useDKIM2DNS(t, dkim2KeyRecords(t, key))
	envelope := dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<bob@example.jp>"}}
	raw := dkim2TestWire(t, key, envelope, true)
	s, m := newDKIM2Session(t, key, true, false)
	s.conf.DKIM2MaxMessageBytes = 64
	auth := feedDKIM2Message(t, s, m, raw, envelope, "")
	expectContinue(t)(s.EndOfMessage(m))
	result := auth.GetDKIM2Verification()
	if result.Checked || !errors.Is(result.Err, mmauth.ErrDKIM2MessageTooLarge) {
		t.Fatalf("unexpected capture result: %+v", result)
	}
	counts := map[string]int{}
	for _, field := range m.headers {
		name, _, _ := strings.Cut(field, ":")
		counts[name]++
	}
	if counts["DKIM-Signature"] != 0 {
		t.Fatalf("untrusted incoming message received a DKIM signature: %v", counts)
	}
	for _, name := range []string{"ARC-Authentication-Results", "ARC-Message-Signature", "ARC-Seal"} {
		if counts[name] != 1 {
			t.Fatalf("capture limit interrupted %s signing: %v", name, counts)
		}
	}
}

func TestDKIM2VerificationSurvivesLegacyCloseError(t *testing.T) {
	key, _ := signingKey(t)
	records := dkim2KeyRecords(t, key)
	useDKIM2DNS(t, records)
	envelope := dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<bob@example.jp>"}}
	original := dkim2TestWire(t, key, envelope, false)
	original = bytes.Replace(original, []byte("body\r\n"), bytes.Repeat([]byte("body\r\n"), 4096), 1)
	raw, err := dkim2.Sign(original, dkim2.SignOptions{Domain: "example.jp", Selector: "s", Key: key, Envelope: envelope})
	if err != nil {
		t.Fatal(err)
	}
	// DKIM-SignatureはDKIM2のハッシュ対象外。多数の不正署名でlegacyだけを停止させる。
	raw = append([]byte(strings.Repeat("DKIM-Signature: invalid\r\n", 64)), raw...)
	legacy := mmauth.NewMMAuth()
	_, _ = legacy.Write(raw)
	if err := legacy.Close(); err == nil || !strings.Contains(err.Error(), "too many DKIM signatures") {
		t.Fatalf("fixture did not trigger the legacy Close error: %v", err)
	}
	s, m := newDKIM2Session(t, key, true, false)
	auth := feedDKIM2Message(t, s, m, raw, envelope, "")
	expectContinue(t)(s.EndOfMessage(m))
	if result := auth.GetDKIM2Verification(); !result.Checked || result.Err != nil || result.Result.Status != dkim2.Pass {
		t.Fatalf("legacy Close error suppressed DKIM2 verification: %+v", result)
	}
	if len(m.headers) != 0 {
		t.Fatalf("legacy Close error unexpectedly added signatures: %v", m.headers)
	}
}

func TestDKIM2InitialSigningFailsClosedOnLegacyParseError(t *testing.T) {
	key, _ := signingKey(t)
	envelope := dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<bob@example.jp>"}}
	raw := append([]byte(strings.Repeat("DKIM-Signature: invalid\r\n", 64)), dkim2TestWire(t, key, envelope, false)...)
	s, m := newDKIM2Session(t, key, false, true)
	feedDKIM2Message(t, s, m, raw, envelope, "login-user")
	response, err := s.EndOfMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	if response != milter.RespTempFail {
		t.Fatalf("legacy parse failure response=%v, want tempfail", response)
	}
	if got := insertedDKIM2Count(m); got != 0 {
		t.Fatalf("legacy parse failure inserted %d DKIM2 fields", got)
	}
}

func TestDKIM2OutgoingCaptureLimitKeepsDKIMSigning(t *testing.T) {
	key, publicKey := signingKey(t)
	envelope := dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<bob@example.jp>"}}
	raw := dkim2TestWire(t, key, envelope, false)
	s, m := newDKIM2Session(t, key, false, true)
	s.conf.DKIM2MaxMessageBytes = 64
	feedDKIM2Message(t, s, m, raw, envelope, "login-user")
	expectContinue(t)(s.EndOfMessage(m))
	if got := insertedDKIM2Count(m); got != 0 {
		t.Fatalf("capture limit added %d DKIM2 headers", got)
	}
	parsed, err := dkim2.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	checkMessageSignatures(t, m, parsed.Headers, string(parsed.Body), publicKey, true, false)
}

func TestDKIM2MessageStateIsolation(t *testing.T) {
	key, _ := signingKey(t)
	useDKIM2DNS(t, dkim2KeyRecords(t, key))
	s, m := newDKIM2Session(t, key, true, false)
	first := dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<bob@example.jp>"}}
	second := dkim2.Envelope{MailFrom: "<>", RcptTo: []string{"<carol@example.jp>"}}
	for _, aborted := range []bool{false, true} {
		auth := feedDKIM2Message(t, s, m, dkim2TestWire(t, key, first, true), first, "")
		if aborted {
			if err := s.Abort(m); err != nil {
				t.Fatal(err)
			}
		} else {
			expectContinue(t)(s.EndOfMessage(m))
			if result := auth.GetDKIM2Verification(); result.Result.Status != dkim2.Pass {
				t.Fatalf("first message: %+v", result)
			}
		}
		auth = feedDKIM2Message(t, s, m, dkim2TestWire(t, key, second, true), second, "")
		expectContinue(t)(s.EndOfMessage(m))
		if result := auth.GetDKIM2Verification(); !result.Checked || result.Result.Status != dkim2.Pass {
			t.Fatalf("new message retained old envelope after aborted=%v: %+v", aborted, result)
		}
	}
}

func TestDKIM2OutgoingMessageStateIsolation(t *testing.T) {
	key, _ := signingKey(t)
	for _, aborted := range []bool{false, true} {
		name := "next message"
		if aborted {
			name = "after abort"
		}
		t.Run(name, func(t *testing.T) {
			s, m := newDKIM2Session(t, key, false, true)
			first := dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<bob@example.jp>"}}
			second := dkim2.Envelope{MailFrom: "<>", RcptTo: []string{"<carol@example.jp>"}}
			firstRaw := dkim2TestWire(t, key, first, false)
			feedDKIM2Message(t, s, m, firstRaw, first, "first-user")
			if aborted {
				if err := s.Abort(m); err != nil {
					t.Fatal(err)
				}
			} else {
				expectContinue(t)(s.EndOfMessage(m))
				wire := append([]byte(strings.Join(m.headers, "")), firstRaw...)
				if result := dkim2.Verify(wire, first, dkim2.VerifyOptions{Resolver: dkim2KeyRecords(t, key)}); result.Status != dkim2.Pass {
					t.Fatalf("first outgoing message: %+v", result)
				}
			}
			secondRaw := bytes.Replace(dkim2TestWire(t, key, second, false), []byte("body\r\n"), []byte("second body\r\n"), 1)
			feedDKIM2Message(t, s, m, secondRaw, second, "second-user")
			expectContinue(t)(s.EndOfMessage(m))
			if got := insertedDKIM2Count(m); got != 2 {
				t.Fatalf("second outgoing message has %d DKIM2 headers", got)
			}
			wire := append([]byte(strings.Join(m.headers, "")), secondRaw...)
			if result := dkim2.Verify(wire, second, dkim2.VerifyOptions{Resolver: dkim2KeyRecords(t, key)}); result.Status != dkim2.Pass {
				t.Fatalf("second outgoing message retained old raw message or envelope: %+v", result)
			}
		})
	}
}

func TestDKIM2OutgoingSignatures(t *testing.T) {
	edKey, _ := signingKey(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	envelope := dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<bob@example.jp>", "<carol@example.jp>"}}
	for _, tc := range []struct {
		name string
		key  crypto.Signer
	}{
		{"Ed25519", edKey}, {"RSA", rsaKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, m := newDKIM2Session(t, tc.key, false, true)
			raw := dkim2TestWire(t, tc.key, envelope, false)
			feedDKIM2Message(t, s, m, raw, envelope, "login-user")
			expectContinue(t)(s.EndOfMessage(m))
			if count := insertedDKIM2Count(m); count != 2 {
				t.Fatalf("expected complete DKIM2 header pair, got %d: %v", count, m.headers)
			}
			wire := append([]byte(strings.Join(m.headers, "")), raw...)
			parsed, err := dkim2.Parse(wire)
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.Signatures) != 1 || parsed.Signatures[0].Values[0].Selector != "dk2" {
				t.Fatalf("wrong configured selector: %+v", parsed.Signatures)
			}
			options := dkim2.VerifyOptions{Resolver: dkim2KeyRecords(t, tc.key)}
			if result := dkim2.Verify(wire, envelope, options); result.Status != dkim2.Pass {
				t.Fatalf("outgoing DKIM2 verification: %+v", result)
			}
			wire = bytes.Replace(wire, []byte("\r\nbody\r\n"), []byte("\r\ntampered\r\n"), 1)
			if result := dkim2.Verify(wire, envelope, options); result.Status == dkim2.Pass {
				t.Fatal("tampered outgoing message passed DKIM2 verification")
			}
		})
	}
}

func TestDKIM2OutgoingEligibility(t *testing.T) {
	key, _ := signingKey(t)
	useDKIM2DNS(t, dkim2KeyRecords(t, key))
	base := dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<bob@example.jp>"}}
	for _, tc := range []struct {
		name, authn  string
		network      bool
		hidden       bool
		bcc          bool
		existing     bool
		disabled     bool
		want         bool
		wantTempFail bool
	}{
		{name: "SMTP authentication", authn: "login-user", want: true},
		{name: "trusted network", network: true, want: true},
		{name: "untrusted sender"},
		{name: "hidden recipient", authn: "login-user", hidden: true},
		{name: "populated Bcc field", authn: "login-user", bcc: true},
		{name: "existing DKIM2", authn: "login-user", existing: true, wantTempFail: true},
		{name: "disabled signing", authn: "login-user", disabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, m := newDKIM2Session(t, key, false, !tc.disabled)
			if tc.network {
				_, network, _ := net.ParseCIDR("192.0.2.0/24")
				s.conf.ParsedMyNetworks = []*net.IPNet{network}
			}
			envelope := base
			if tc.hidden {
				envelope.RcptTo = []string{base.RcptTo[0], "<hidden@example.jp>"}
			}
			raw := dkim2TestWire(t, key, envelope, tc.existing)
			if tc.bcc {
				raw = append([]byte("Bcc: hidden@example.jp\r\n"), raw...)
			}
			feedDKIM2Message(t, s, m, raw, envelope, tc.authn)
			response, err := s.EndOfMessage(m)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantTempFail {
				if response != milter.RespTempFail {
					t.Fatalf("response=%v, want tempfail", response)
				}
			} else if response != milter.RespContinue {
				t.Fatalf("response=%v, want continue", response)
			}
			wantCount := 0
			if tc.want {
				wantCount = 2
			}
			if got := insertedDKIM2Count(m); got != wantCount {
				t.Fatalf("DKIM2 inserted headers=%d, want %d: %v", got, wantCount, m.headers)
			}
			if tc.existing {
				wire := append([]byte(strings.Join(m.headers, "")), raw...)
				if result := dkim2.Verify(wire, envelope, dkim2.VerifyOptions{Resolver: dkim2KeyRecords(t, key)}); result.Status != dkim2.Pass {
					t.Fatalf("existing DKIM2 signature was not preserved: %+v", result)
				}
			}
		})
	}
}

func TestDKIM2InitialSigningErrorFailsClosed(t *testing.T) {
	key, _ := signingKey(t)
	s, m := newDKIM2Session(t, key, false, true)
	domain := s.conf.Domains["example.jp"]
	domain.DKIM2Selector = "invalid selector"
	s.conf.Domains["example.jp"] = domain
	envelope := dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<bob@example.jp>"}}
	feedDKIM2Message(t, s, m, dkim2TestWire(t, key, envelope, false), envelope, "login-user")
	response, err := s.EndOfMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	if response != milter.RespTempFail {
		t.Fatalf("invalid signing configuration response=%v, want tempfail", response)
	}
	if got := insertedDKIM2Count(m); got != 0 {
		t.Fatalf("failed signing inserted %d DKIM2 fields", got)
	}
}
