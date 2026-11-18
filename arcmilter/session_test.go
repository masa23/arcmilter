package arcmilter

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/d--j/go-milter"
	"github.com/masa23/arcmilter/config"
	"github.com/masa23/mmauth"
	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/dkim"
	"github.com/masa23/mmauth/domainkey"
)

type messageModifier struct {
	signingModifier
	authn string
}

func (m *messageModifier) Get(name milter.MacroName) string {
	if name == milter.MacroAuthAuthen {
		return m.authn
	}
	return ""
}

func expectContinue(t *testing.T) func(*milter.Response, error) {
	t.Helper()
	return func(response *milter.Response, err error) {
		t.Helper()
		if err != nil || response != milter.RespContinue {
			t.Fatalf("expected continue, got response=%v error=%v", response, err)
		}
	}
}

func newMessageSession(t *testing.T) (*Session, *messageModifier, *domainkey.DomainKey) {
	t.Helper()
	key, publicKey := signingKey(t)
	s := &Session{conf: &config.Config{
		ARCSignHeaders: []string{"From", "Subject"}, DKIMSignHeaders: []string{"From", "Subject"},
		Domains: map[string]config.Domain{
			"example.jp": {
				Domain: "example.jp", Pattern: "example.jp", DKIM: true, ARC: true,
				Selector: "s", ARCSelector: "s", PrivateKeySigner: key,
				HeaderCanonicalization: "relaxed", BodyCanonicalization: "relaxed", HashAlgo: crypto.SHA256,
			},
		},
	}}
	m := &messageModifier{}
	t.Cleanup(func() { s.Cleanup(m) })
	check := expectContinue(t)
	check(s.Connect("remote.example", "tcp4", 25, "192.0.2.1", m))
	check(s.Helo("remote.example", m))
	return s, m, publicKey
}

func TestNewSMTPConnectionClearsTrustAndMessageState(t *testing.T) {
	s, m, _ := newMessageSession(t)
	_, network, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	s.conf.ParsedMyNetworks = []*net.IPNet{network}
	domain := s.conf.Domains["example.jp"]
	domain.DKIM2 = true
	s.conf.Domains["example.jp"] = domain
	check := expectContinue(t)
	check(s.Connect("localhost", "tcp4", 25, "127.0.0.1", m))
	check(s.Helo("old-connection.example", m))
	m.authn = "old-login"
	check(s.MailFrom("sender@example.jp", "", m))
	check(s.RcptTo("recipient@example.jp", "", m))
	check(s.Header("From", "sender@example.jp", m))
	check(s.Headers(m))
	check(s.BodyChunk([]byte("unfinished body\r\n"), m))
	s.dkim2Result = "dkim2=pass"
	oldAuth, conf := s.mmauth, s.conf
	if !s.trustedSigningSender() || s.dkim2Message == nil {
		t.Fatal("fixture did not populate trusted connection and message state")
	}
	if err := s.NewConnection(m); err != nil {
		t.Fatal(err)
	}
	if s.conf != conf || s.remoteAddr != nil || s.helo != "" || s.authn != "" || s.mailFrom != "" ||
		s.from != "" || s.fromDomain != "" || s.rcptToDomain != "" || len(s.rcptTo) != 0 ||
		s.mmauth != nil || s.dkim2Message != nil || s.dkim2Result != "" || s.isDKIMSign || s.isARCSign {
		t.Fatal("new SMTP connection inherited previous connection or message state")
	}
	if _, err := oldAuth.Write([]byte("later bytes")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("old message parser was not closed: %v", err)
	}
	check(s.Connect("unknown", "unknown", 0, "", m))
	if s.trustedSigningSender() || s.conf.IsMyNetwork(s.remoteAddr) {
		t.Fatal("unknown SMTP connection inherited trust")
	}
	m.authn = "new-login"
	check(s.MailFrom("new@example.jp", "", m))
	if s.authn != "new-login" || !s.trustedSigningSender() {
		t.Fatal("current MAIL FROM authentication macro was not used")
	}
}

func TestConnectDoesNotRetainOrInferSMTPClientTrust(t *testing.T) {
	_, network, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, family, address string
		wantIP                string
		trusted               bool
	}{
		{"new IPv4 client", "tcp4", "192.0.2.1", "192.0.2.1", false},
		{"current loopback", "tcp4", "127.0.0.1", "127.0.0.1", true},
		{"new IPv6 client", "tcp6", "2001:db8::1", "2001:db8::1", false},
		{"invalid IP", "tcp4", "not-an-IP", "", false},
		{"empty IP", "tcp6", "", "", false},
		{"unknown family", "unknown", "", "", false},
		{"Unix client", "unix", "/run/client.sock", "", false},
		{"IP-shaped Unix path", "unix", "127.0.0.1", "", false},
		{"unknown IP-shaped address", "unknown", "127.0.0.1", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{remoteAddr: net.ParseIP("127.0.0.1"), conf: &config.Config{ParsedMyNetworks: []*net.IPNet{network}}}
			expectContinue(t)(s.Connect("client", tc.family, 0, tc.address, nil))
			if tc.wantIP == "" {
				if s.remoteAddr != nil {
					t.Fatalf("unexpected SMTP-client IP: %s", s.remoteAddr)
				}
			} else if !s.remoteAddr.Equal(net.ParseIP(tc.wantIP)) {
				t.Fatalf("SMTP-client IP=%s, want %s", s.remoteAddr, tc.wantIP)
			}
			if s.trustedSigningSender() != tc.trusted {
				t.Fatalf("trusted=%v, want %v", s.trustedSigningSender(), tc.trusted)
			}
		})
	}
}

func startMessage(t *testing.T, s *Session, m *messageModifier, authn, from, subject string, recipients []string) []string {
	t.Helper()
	m.authn, m.headers = authn, nil
	check := expectContinue(t)
	// 不正なエンベロープ送信元を使い、SPFの外部DNSへの問い合わせを避ける。
	check(s.MailFrom("invalid-"+subject, "", m))
	if s.isDKIMSign || s.isARCSign || s.rcptToDomain != "" || s.from != "" || s.fromDomain != "" {
		t.Fatalf("previous message state survived MAIL FROM: %+v", s)
	}
	if s.authn != authn || s.mailFrom != "invalid-"+subject || s.mmauth == nil {
		t.Fatal("MAIL FROM did not initialize the new message")
	}
	if s.remoteAddr.String() != "192.0.2.1" || s.helo != "remote.example" {
		t.Fatal("connection state was lost between messages")
	}
	for _, recipient := range recipients {
		check(s.RcptTo(recipient, "", m))
	}
	var headers []string
	if from != "" {
		check(s.Header("From", from, m))
		headers = append(headers, "From: "+from+"\r\n")
	}
	check(s.Header("Subject", subject, m))
	return append(headers, "Subject: "+subject+"\r\n")
}

func finishMessage(t *testing.T, s *Session, m *messageModifier, body string) {
	t.Helper()
	check := expectContinue(t)
	check(s.Headers(m))
	// チャンク境界にも依存せず、メール単位で本文ハッシュを計算できることを確認する。
	check(s.BodyChunk([]byte(body[:len(body)/2]), m))
	check(s.BodyChunk([]byte(body[len(body)/2:]), m))
	check(s.EndOfMessage(m))
	if s.mmauth != nil {
		t.Fatal("message processing resources remained after end of message")
	}
}

func checkMessageSignatures(t *testing.T, m *messageModifier, headers []string, body string, key *domainkey.DomainKey, wantDKIM, wantARC bool) {
	t.Helper()
	counts := map[string]int{}
	for _, header := range m.headers {
		name, _, _ := strings.Cut(header, ":")
		counts[name]++
	}
	wanted := map[string]bool{
		"DKIM-Signature": wantDKIM, "ARC-Authentication-Results": wantARC,
		"ARC-Message-Signature": wantARC, "ARC-Seal": wantARC,
	}
	wantCount := 0
	for name, enabled := range wanted {
		want := 0
		if enabled {
			want = 1
		}
		wantCount += want
		if counts[name] != want {
			t.Fatalf("%s count: got %d, want %d; headers=%v", name, counts[name], want, m.headers)
		}
	}
	if len(m.headers) != wantCount {
		t.Fatalf("unexpected inserted headers: %v", m.headers)
	}
	// 署名に含まれるbh=からではなく、今回の本文から期待値を計算する。
	digest := sha256.Sum256([]byte(body))
	bodyHash := base64.StdEncoding.EncodeToString(digest[:])
	all := append(append([]string(nil), headers...), m.headers...)
	for _, header := range m.headers {
		switch {
		case strings.HasPrefix(header, "DKIM-Signature:"):
			sig, err := dkim.ParseSignature(header)
			if err != nil {
				t.Fatal(err)
			}
			sig.Verify(headers, bodyHash, key)
			if sig.VerifyResult.Status() != dkim.VerifyStatusPass {
				t.Fatalf("DKIM verification failed: %v", sig.VerifyResult.Error())
			}
		case strings.HasPrefix(header, "ARC-Message-Signature:"):
			sig, err := arc.ParseARCMessageSignature(header)
			if err != nil {
				t.Fatal(err)
			}
			if sig.InstanceNumber != 1 {
				t.Fatalf("ARC instance carried over from previous message: %d", sig.InstanceNumber)
			}
			if result := sig.Verify(all, bodyHash, key); result.Status() != arc.VerifyStatusPass {
				t.Fatalf("ARC message signature verification failed: %v", result.Error())
			}
		case strings.HasPrefix(header, "ARC-Seal:"):
			seal, err := arc.ParseARCSeal(header)
			if err != nil {
				t.Fatal(err)
			}
			if seal.InstanceNumber != 1 || seal.ChainValidation != arc.ChainValidationResultNone {
				t.Fatalf("unexpected new ARC chain: i=%d cv=%s", seal.InstanceNumber, seal.ChainValidation)
			}
			if result := seal.Verify(all, key); result.Status() != arc.VerifyStatusPass {
				t.Fatalf("ARC seal verification failed: %v", result.Error())
			}
		}
	}
}

func TestSessionMessagesIndependent(t *testing.T) {
	for _, tc := range []struct {
		name      string
		from      string
		recipient string
		dkim, arc bool
	}{
		{"ARC signed again", "b@example.jp", "<b@example.jp>", false, true},
		{"neither domain matches", "b@outside.example", "<b@outside.example>", false, false},
		{"only From matches", "b@example.jp", "<b@outside.example>", false, false},
		{"only recipient matches", "b@outside.example", "<b@example.jp>", false, true},
		{"no From header", "", "<b@outside.example>", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, m, key := newMessageSession(t)
			headers := startMessage(t, s, m, "", "a@example.jp", "first", []string{"<a@example.jp>"})
			finishMessage(t, s, m, "first body\r\n")
			checkMessageSignatures(t, m, headers, "first body\r\n", key, false, true)
			headers = startMessage(t, s, m, "", tc.from, "second", []string{tc.recipient})
			finishMessage(t, s, m, "second body\r\n")
			checkMessageSignatures(t, m, headers, "second body\r\n", key, tc.dkim, tc.arc)
		})
	}
}

func TestSessionAuthenticationIsPerMessage(t *testing.T) {
	s, m, key := newMessageSession(t)
	for _, authn := range []string{"login-user", "", "other-user", ""} {
		headers := startMessage(t, s, m, authn, "a@example.jp", "authentication", []string{"<a@example.jp>"})
		finishMessage(t, s, m, "body\r\n")
		checkMessageSignatures(t, m, headers, "body\r\n", key, authn != "", authn == "")
	}
}

func TestDKIMSigningRequiresTrustedOriginOutsideForwardSend(t *testing.T) {
	for _, tc := range []struct {
		name, authn, mode string
		myNetwork         bool
		wantDKIM          bool
	}{
		{"external spoofed From", "", "disabled", false, false},
		{"authenticated sender", "login-user", "disabled", false, true},
		{"trusted network", "", "disabled", true, true},
		{"forward send stage with authentication", "login-user", "send", false, false},
		{"forward send stage from trusted network", "", "send", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, m, key := newMessageSession(t)
			s.conf.DKIM2Forwarding.Mode = tc.mode
			if tc.myNetwork {
				_, network, err := net.ParseCIDR("192.0.2.0/24")
				if err != nil {
					t.Fatal(err)
				}
				s.conf.ParsedMyNetworks = []*net.IPNet{network}
			}
			headers := startMessage(t, s, m, tc.authn, "alice@example.jp", "origin trust", []string{"<bob@outside.example>"})
			finishMessage(t, s, m, "body\r\n")
			checkMessageSignatures(t, m, headers, "body\r\n", key, tc.wantDKIM, false)
		})
	}
}

func checkClosedMessage(t *testing.T, auth *mmauth.MMAuth) {
	t.Helper()
	if _, err := auth.Write([]byte("must not be processed\r\n")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("expected closed message writer, got %v", err)
	}
}

func TestSessionAbort(t *testing.T) {
	for _, stage := range []string{"headers", "body"} {
		for _, signNext := range []bool{false, true} {
			name := stage + "/unsigned next"
			if signNext {
				name = stage + "/signed next"
			}
			t.Run(name, func(t *testing.T) {
				s, m, key := newMessageSession(t)
				startMessage(t, s, m, "", "a@example.jp", "aborted", []string{"<a@example.jp>"})
				if stage == "body" {
					check := expectContinue(t)
					check(s.Headers(m))
					check(s.BodyChunk([]byte("aborted body\r\n"), m))
				}
				old := s.mmauth
				for i := 0; i < 2; i++ {
					if err := s.Abort(m); err != nil {
						t.Fatal(err)
					}
				}
				if s.mmauth != nil || s.isDKIMSign || s.isARCSign || s.rcptToDomain != "" || s.mailFrom != "" || s.from != "" || s.fromDomain != "" || s.authn != "" {
					t.Fatal("aborted message state was retained")
				}
				checkClosedMessage(t, old)
				expectContinue(t)(s.EndOfMessage(m))
				if len(m.headers) != 0 {
					t.Fatal("aborted message produced signatures")
				}
				from, recipient := "b@outside.example", "<b@outside.example>"
				if signNext {
					from, recipient = "b@example.jp", "<b@example.jp>"
				}
				headers := startMessage(t, s, m, "", from, "after abort", []string{recipient})
				finishMessage(t, s, m, "new body\r\n")
				checkMessageSignatures(t, m, headers, "new body\r\n", key, false, signNext)
			})
		}
	}
}

func TestSessionMailFromClosesUnfinishedMessage(t *testing.T) {
	s, m, key := newMessageSession(t)
	startMessage(t, s, m, "login-user", "a@example.jp", "unfinished", []string{"<a@example.jp>"})
	old := s.mmauth
	headers := startMessage(t, s, m, "", "b@example.jp", "replacement", []string{"<b@example.jp>"})
	checkClosedMessage(t, old)
	finishMessage(t, s, m, "replacement body\r\n")
	checkMessageSignatures(t, m, headers, "replacement body\r\n", key, false, true)
}

func TestSessionCleanup(t *testing.T) {
	s, m, _ := newMessageSession(t)
	s.Cleanup(m) // MAIL FROM前でも安全に呼べる。
	startMessage(t, s, m, "", "a@example.jp", "unfinished", []string{"<a@example.jp>"})
	old := s.mmauth
	s.Cleanup(m)
	s.Cleanup(m)
	if s.mmauth != nil {
		t.Fatal("cleanup retained message processing resources")
	}
	checkClosedMessage(t, old)
	if len(m.headers) != 0 {
		t.Fatal("cleanup produced signatures")
	}
}

func TestSessionRecipientOrder(t *testing.T) {
	for _, recipients := range [][]string{
		{"<a@example.jp>", "<a@outside.example>"},
		{"<a@outside.example>", "<a@example.jp>"},
		{"<a@example.jp>", "<b@example.jp>"},
		{"invalid", "<a@example.jp>", "<a@outside.example>"},
	} {
		t.Run(strings.Join(recipients, ","), func(t *testing.T) {
			s, m, key := newMessageSession(t)
			headers := startMessage(t, s, m, "", "a@outside.example", "recipients", recipients)
			finishMessage(t, s, m, "body\r\n")
			checkMessageSignatures(t, m, headers, "body\r\n", key, false, true)
		})
	}
}
