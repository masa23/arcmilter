package arcmilter

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/d--j/go-milter"
	"github.com/masa23/arcmilter/config"
	"github.com/masa23/mmauth"
	"github.com/masa23/mmauth/dkim2"
)

// Apply modifications to a separate MTA view of the message, including the
// per-name, one-based deletion of the private forwarding context field.
type dkim2ForwardModifier struct {
	milter.Modifier
	fields     []string
	body       []byte
	failInsert string
	failChange bool
}

func (m *dkim2ForwardModifier) Get(milter.MacroName) string { return "" }

func (m *dkim2ForwardModifier) InsertHeader(index int, name, value string) error {
	if strings.EqualFold(name, m.failInsert) {
		return errors.New("test insertion failure")
	}
	index = min(max(index, 0), len(m.fields))
	field := name + ": " + normalizeHeaderValue(strings.TrimSuffix(value, "\r\n")) + "\r\n"
	m.fields = slices.Insert(m.fields, index, field)
	return nil
}

func (m *dkim2ForwardModifier) ChangeHeader(index int, name, value string) error {
	if m.failChange {
		return errors.New("test header change failure")
	}
	count := 0
	for i, field := range m.fields {
		fieldName, _, _ := strings.Cut(field, ":")
		if !strings.EqualFold(fieldName, name) {
			continue
		}
		count++
		if count != index {
			continue
		}
		if value == "" {
			m.fields = slices.Delete(m.fields, i, i+1)
		} else {
			m.fields[i] = name + ": " + normalizeHeaderValue(value) + "\r\n"
		}
		return nil
	}
	return errors.New("test header to change was not found")
}

func (m *dkim2ForwardModifier) wire() []byte {
	return append([]byte(strings.Join(m.fields, "")+"\r\n"), m.body...)
}

type dkim2ForwardFixture struct {
	key        ed25519.PrivateKey
	records    dkim2Records
	store      string
	incoming   dkim2.Envelope
	original   []byte
	received   []byte
	id         string
	dnsQueries *atomic.Int64
}

func newDKIM2ForwardFixture(t *testing.T, nullSender bool) *dkim2ForwardFixture {
	t.Helper()
	key, _ := signingKey(t)
	record := "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	f := &dkim2ForwardFixture{
		key: key, store: t.TempDir(),
		records: dkim2Records{
			"s._domainkey.example.jp":      {record},
			"dk2._domainkey.relay.example": {record},
		},
		incoming: dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<bob@relay.example>"}},
	}
	if nullSender {
		f.incoming.MailFrom = "<>"
	}
	if err := os.Chmod(f.store, 0700); err != nil {
		t.Fatal(err)
	}
	f.dnsQueries = useDKIM2DNS(t, f.records)
	var err error
	f.original, err = dkim2.Sign([]byte("From: alice@example.jp\r\nTo: bob@relay.example\r\nCc: carol@destination.example\r\nSubject: original\r\n\r\nfirst\r\nlast\r\n"), dkim2.SignOptions{
		Domain: "example.jp", Selector: "s", Key: key, Envelope: f.incoming,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := f.session(t, "receive", "192.0.2.1")
	if s.conf.EnableDKIM2 {
		t.Fatal("fixture must verify receiving contexts even with EnableDKIM2 disabled")
	}
	m, response := feedDKIM2ForwardCallbacks(t, s, f.original, f.incoming, nil)
	if response != milter.RespContinue {
		t.Fatalf("receiving context failed: %v", response)
	}
	f.received = m.wire()
	for _, field := range m.fields {
		name, value, _ := strings.Cut(field, ":")
		if strings.EqualFold(name, dkim2ContextHeader) {
			if f.id != "" {
				t.Fatal("receiver emitted more than one context")
			}
			f.id = strings.TrimSpace(value)
		}
	}
	if !validDKIM2ContextID(f.id) {
		t.Fatalf("receiver did not emit an opaque context ID: %q", f.id)
	}
	return f
}

func (f *dkim2ForwardFixture) session(t *testing.T, mode, source string) *Session {
	t.Helper()
	_, trusted, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	s := &Session{conf: &config.Config{
		ParsedMyNetworks: []*net.IPNet{trusted},
		DKIM2Forwarding: config.DKIM2ForwardingConfig{
			Mode: mode, StoreDirectory: f.store, AllowRecipeDisclosure: true,
			ForwardRecipients: []string{"*@relay.example", "*@relay2.example", "*@xn--bcher-kva.example"},
		},
		Domains: map[string]config.Domain{"relay.example": {
			Domain: "relay.example", Pattern: "relay.example", DKIM2: true,
			Selector: "s", DKIM2Selector: "dk2", PrivateKeySigner: f.key,
			HashAlgo: crypto.SHA256, HeaderCanonicalization: "relaxed", BodyCanonicalization: "relaxed",
		}},
		DKIMSignHeaders: []string{"From", "Subject"}, ARCSignHeaders: []string{"From", "Subject"},
	}}
	s.remoteAddr = net.ParseIP(source)
	t.Cleanup(func() { s.Cleanup(nil) })
	return s
}

func TestDKIM2ReceiveUsesOneVerification(t *testing.T) {
	for _, tc := range []struct {
		name     string
		enabled  bool
		selected bool
	}{
		{"adapter verification for selected recipient", true, true},
		{"adapter verification for unselected recipient", true, false},
		{"standalone verification when adapter disabled", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDKIM2ForwardFixture(t, false)
			s := f.session(t, "receive", "192.0.2.1")
			s.conf.EnableDKIM2 = tc.enabled
			if !tc.selected {
				s.conf.DKIM2Forwarding.ForwardRecipients = []string{"*@other.example"}
			}
			before := f.dnsQueries.Load()
			m, response := feedDKIM2ForwardCallbacks(t, s, f.original, f.incoming, nil)
			if response != milter.RespContinue {
				t.Fatalf("receive response=%v", response)
			}
			if got := f.dnsQueries.Load() - before; got != 1 {
				t.Fatalf("DNS TXT queries=%d, want one DKIM2 verification", got)
			}
			if selected := bytes.Contains(m.wire(), []byte(dkim2ContextHeader+":")); selected != tc.selected {
				t.Fatalf("forwarding context present=%t, want %t", selected, tc.selected)
			}
		})
	}
}

func TestDKIM2ForwardingRecipeDisclosurePolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		modify    func([]byte) []byte
		wantReply *milter.Response
	}{
		{
			name: "removed content rejected by default",
			modify: func(wire []byte) []byte {
				return bytes.Replace(wire, []byte("Subject: original\r\n"), []byte("Subject: [redacted]\r\n"), 1)
			},
			wantReply: milter.RespTempFail,
		},
		{
			name: "non-disclosing footer accepted",
			modify: func(wire []byte) []byte {
				return append(wire, []byte("forwarding footer\r\n")...)
			},
			wantReply: milter.RespContinue,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDKIM2ForwardFixture(t, false)
			s := f.session(t, "send", "127.0.0.1")
			s.conf.DKIM2Forwarding.AllowRecipeDisclosure = false
			outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.example>", RcptTo: []string{"<carol@destination.example>"}}
			m, response := feedDKIM2ForwardCallbacks(t, s, tc.modify(bytes.Clone(f.received)), outgoing, nil)
			if response != tc.wantReply {
				t.Fatalf("response=%v, want %v", response, tc.wantReply)
			}
			parsed, err := dkim2.Parse(m.wire())
			if err != nil {
				t.Fatal(err)
			}
			wantSignatures := 1
			if tc.wantReply == milter.RespContinue {
				wantSignatures = 2
			}
			if len(parsed.Signatures) != wantSignatures {
				t.Fatalf("signatures=%d, want %d", len(parsed.Signatures), wantSignatures)
			}
		})
	}
}

func feedDKIM2ForwardCallbacks(t *testing.T, s *Session, raw []byte, envelope dkim2.Envelope, setup func(*dkim2ForwardModifier)) (*dkim2ForwardModifier, *milter.Response) {
	t.Helper()
	parsed, err := dkim2.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := &dkim2ForwardModifier{fields: slices.Clone(parsed.Headers), body: bytes.Clone(parsed.Body)}
	if setup != nil {
		setup(m)
	}
	check := expectContinue(t)
	check(s.MailFrom(milter.RemoveAngle(envelope.MailFrom), "", m))
	for _, recipient := range envelope.RcptTo {
		check(s.RcptTo(milter.RemoveAngle(recipient), "", m))
	}
	for _, field := range parsed.Headers {
		name, value, _ := strings.Cut(strings.TrimSuffix(field, "\r\n"), ":")
		check(s.Header(name, strings.ReplaceAll(strings.TrimPrefix(value, " "), "\r\n", "\n"), m))
	}
	check(s.Headers(m))
	check(s.BodyChunk(parsed.Body[:len(parsed.Body)/2], m))
	check(s.BodyChunk(parsed.Body[len(parsed.Body)/2:], m))
	response, err := s.EndOfMessage(m)
	if err != nil {
		t.Fatalf("end of message: %v", err)
	}
	return m, response
}

func TestDKIM2ForwardingCallbacks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		revised bool
		null    bool
	}{
		{name: "unchanged alias forwarding"},
		{name: "subject and footer revised", revised: true},
		{name: "null sender", null: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDKIM2ForwardFixture(t, tc.null)
			wire := bytes.Clone(f.received)
			if tc.revised {
				wire = bytes.Replace(wire, []byte("Subject: original\r\n"), []byte("Subject: changed\r\n"), 1)
				wire = append(wire, []byte("forwarding footer\r\n")...)
			}
			outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.example>", RcptTo: []string{"<carol@destination.example>"}}
			if tc.null {
				outgoing.MailFrom = "<>"
			}
			m, response := feedDKIM2ForwardCallbacks(t, f.session(t, "send", "127.0.0.1"), wire, outgoing, nil)
			if response != milter.RespContinue {
				t.Fatalf("forwarding failed: %v", response)
			}
			final := m.wire()
			if bytes.Contains(bytes.ToLower(final), []byte(strings.ToLower(dkim2ContextHeader)+":")) {
				t.Fatal("private context reference survived outgoing delivery")
			}
			parsed, err := dkim2.Parse(final)
			if err != nil {
				t.Fatal(err)
			}
			wantInstances := 1
			if tc.revised {
				wantInstances = 2
			}
			if len(parsed.Signatures) != 2 || len(parsed.Instances) != wantInstances {
				t.Fatalf("unexpected forwarded chain: signatures=%d instances=%d", len(parsed.Signatures), len(parsed.Instances))
			}
			original, err := dkim2.Parse(f.original)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Signatures[0].Raw != original.Signatures[0].Raw || parsed.Instances[0].Raw != original.Instances[0].Raw {
				t.Fatal("forwarding changed the prior DKIM2 fields")
			}
			if result := dkim2.Verify(final, outgoing, dkim2.VerifyOptions{Resolver: f.records}); result.Status != dkim2.Pass {
				t.Fatalf("forwarded authentication: %s: %v", result.Status, result.Err)
			}
		})
	}
}

func TestDKIM2ForwardingReceiveStoresOnlyConfiguredRecipients(t *testing.T) {
	f := newDKIM2ForwardFixture(t, false)
	receiver := f.session(t, "receive", "192.0.2.1")
	receiver.conf.DKIM2Forwarding.ForwardRecipients = []string{"forward@relay.example"}
	m, response := feedDKIM2ForwardCallbacks(t, receiver, f.original, f.incoming, nil)
	if response != milter.RespContinue {
		t.Fatalf("ordinary local delivery failed: %v", response)
	}
	for _, field := range m.fields {
		name, _, _ := strings.Cut(field, ":")
		if strings.EqualFold(name, dkim2ContextHeader) {
			t.Fatal("ordinary local delivery received a forwarding context")
		}
	}
	entries, err := os.ReadDir(f.store)
	if err != nil {
		t.Fatal(err)
	}
	contexts := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".ctx") {
			contexts++
		}
	}
	if contexts != 1 {
		t.Fatalf("non-forward recipient changed stored context count to %d", contexts)
	}
}

func TestDKIM2ForwardingReceiveRejectsMixedRecipientTransaction(t *testing.T) {
	f := newDKIM2ForwardFixture(t, false)
	receiver := f.session(t, "receive", "192.0.2.1")
	receiver.conf.DKIM2Forwarding.ForwardRecipients = []string{"forward@relay.example"}
	relay2 := receiver.conf.Domains["relay.example"]
	relay2.Domain, relay2.Pattern = "relay2.example", "relay2.example"
	receiver.conf.Domains["relay2.example"] = relay2

	envelope := dkim2.Envelope{
		MailFrom: "<alice@example.jp>",
		RcptTo:   []string{"<forward@relay.example>", "<ordinary@relay2.example>"},
	}
	receiver.rcptTo = slices.Clone(envelope.RcptTo)
	if got := receiver.dkim2ForwardSigningDomains(); !slices.Equal(got, []string{"relay.example"}) {
		t.Fatalf("signing domains include an unselected recipient: %v", got)
	}
	raw, err := dkim2.Sign([]byte("From: alice@example.jp\r\nTo: forward@relay.example\r\nSubject: mixed\r\n\r\nbody\r\n"), dkim2.SignOptions{
		Domain: "example.jp", Selector: "s", Key: f.key, Envelope: envelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	m, response := feedDKIM2ForwardCallbacks(t, receiver, raw, envelope, nil)
	if response != milter.RespContinue {
		t.Fatalf("mixed local delivery failed: %v", response)
	}
	for _, field := range m.fields {
		name, _, _ := strings.Cut(field, ":")
		if strings.EqualFold(name, dkim2ContextHeader) {
			t.Fatal("mixed local delivery received a forwarding context")
		}
	}
	entries, err := os.ReadDir(f.store)
	if err != nil {
		t.Fatal(err)
	}
	contexts := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".ctx") {
			contexts++
		}
	}
	if contexts != 1 {
		t.Fatalf("mixed recipient transaction changed stored context count to %d", contexts)
	}
}

func TestDKIM2ForwardingFanoutContextReuse(t *testing.T) {
	f := newDKIM2ForwardFixture(t, false)
	for _, recipient := range []string{"<carol@destination.example>", "<hidden@another.example>"} {
		s := f.session(t, "send", "127.0.0.1")
		s.conf.DKIM2Forwarding.MultipleDeliveries = true
		outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.example>", RcptTo: []string{recipient}}
		m, response := feedDKIM2ForwardCallbacks(t, s, f.received, outgoing, nil)
		if response != milter.RespContinue {
			t.Fatalf("fanout recipient %s: %v", recipient, response)
		}
		final := m.wire()
		parsed, err := dkim2.Parse(final)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(parsed.Signatures[1].Flags, "exploded") || !slices.Equal(parsed.Signatures[1].Recipients, outgoing.RcptTo) {
			t.Fatalf("fanout signature did not record only this delivery: %+v", parsed.Signatures[1])
		}
		if result := dkim2.Verify(final, outgoing, dkim2.VerifyOptions{Resolver: f.records}); result.Status != dkim2.Pass {
			t.Fatalf("fanout authentication: %s: %v", result.Status, result.Err)
		}
	}
}

func TestDKIM2ForwardingInfersObservedFanout(t *testing.T) {
	for _, tc := range []struct {
		name       string
		recipients []string
		exploded   bool
	}{
		{"distinct recipients", []string{"<bob@relay.example>", "<carol@destination.example>"}, true},
		{"single recipient", []string{"<carol@destination.example>"}, false},
		{"duplicate with domain case", []string{"<carol@destination.example>", "<carol@DESTINATION.EXAMPLE>"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDKIM2ForwardFixture(t, false)
			s := f.session(t, "send", "127.0.0.1")
			if s.conf.DKIM2Forwarding.MultipleDeliveries {
				t.Fatal("fixture must exercise the default fanout setting")
			}
			outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.example>", RcptTo: tc.recipients}
			m, response := feedDKIM2ForwardCallbacks(t, s, f.received, outgoing, nil)
			if response != milter.RespContinue {
				t.Fatalf("observed fanout was rejected: %v", response)
			}
			parsed, err := dkim2.Parse(m.wire())
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.Signatures) != 2 || slices.Contains(parsed.Signatures[1].Flags, "exploded") != tc.exploded {
				t.Fatalf("unexpected observed fanout signature: %+v", parsed.Signatures)
			}
			if result := dkim2.Verify(m.wire(), outgoing, dkim2.VerifyOptions{Resolver: f.records}); result.Status != dkim2.Pass {
				t.Fatalf("observed fanout authentication: %s: %v", result.Status, result.Err)
			}
		})
	}
}

func TestDKIM2ForwardingReceivingDomainCase(t *testing.T) {
	f := newDKIM2ForwardFixture(t, false)
	incoming := dkim2.Envelope{MailFrom: f.incoming.MailFrom, RcptTo: []string{"<bob@RELAY.EXAMPLE>"}}
	received, response := feedDKIM2ForwardCallbacks(t, f.session(t, "receive", "192.0.2.1"), f.original, incoming, nil)
	if response != milter.RespContinue {
		t.Fatalf("case-equivalent receiving domain was rejected: %v", response)
	}
	parsed, err := dkim2.Parse(received.wire())
	if err != nil {
		t.Fatal(err)
	}
	contextID := ""
	for _, field := range parsed.Headers {
		name, value, _ := strings.Cut(field, ":")
		if strings.EqualFold(name, dkim2ContextHeader) {
			contextID = strings.TrimSpace(value)
		}
	}
	if !validDKIM2ContextID(contextID) {
		t.Fatal("case-equivalent receiving domain did not save forwarding context")
	}
	context, err := loadDKIM2ForwardContext(f.session(t, "send", "127.0.0.1").conf.DKIM2Forwarding, contextID)
	if err != nil || !slices.Equal(context.SigningDomains, []string{"relay.example"}) {
		t.Fatalf("receiving domain was not normalized: context=%+v error=%v", context, err)
	}
	outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.example>", RcptTo: []string{"<carol@destination.example>"}}
	forwarded, response := feedDKIM2ForwardCallbacks(t, f.session(t, "send", "127.0.0.1"), received.wire(), outgoing, nil)
	if response != milter.RespContinue {
		t.Fatalf("case-equivalent domain forwarding failed: %v", response)
	}
	if result := dkim2.Verify(forwarded.wire(), outgoing, dkim2.VerifyOptions{Resolver: f.records}); result.Status != dkim2.Pass {
		t.Fatalf("case-equivalent domain authentication: %s: %v", result.Status, result.Err)
	}
}

func TestDKIM2ForwardingNullSenderSigningDomain(t *testing.T) {
	f := newDKIM2ForwardFixture(t, true)
	// Existing DNS goroutines retain their record map; register a clone rather
	// than mutating the map that a resolver may still be reading.
	f.records = dkim2Records{
		"s._domainkey.example.jp":       slices.Clone(f.records["s._domainkey.example.jp"]),
		"dk2._domainkey.relay.example":  slices.Clone(f.records["dk2._domainkey.relay.example"]),
		"dk2._domainkey.relay2.example": slices.Clone(f.records["dk2._domainkey.relay.example"]),
	}
	useDKIM2DNS(t, f.records)
	incoming := dkim2.Envelope{MailFrom: "<>", RcptTo: []string{"<bob@relay.example>", "<bob@relay2.example>"}}
	original, err := dkim2.Sign([]byte("From: alice@example.jp\r\nTo: bob@relay.example, bob@relay2.example\r\nCc: carol@destination.example\r\nSubject: null sender\r\n\r\nbody\r\n"), dkim2.SignOptions{
		Domain: "example.jp", Selector: "s", Key: f.key, Envelope: incoming,
	})
	if err != nil {
		t.Fatal(err)
	}
	addDomain := func(s *Session, name string) {
		domain := s.conf.Domains["relay.example"]
		domain.Domain, domain.Pattern = name, name
		s.conf.Domains[name] = domain
	}
	receiver := f.session(t, "receive", "192.0.2.1")
	addDomain(receiver, "relay2.example")
	received, response := feedDKIM2ForwardCallbacks(t, receiver, original, incoming, nil)
	if response != milter.RespContinue {
		t.Fatalf("multiple receiving domains failed: %v", response)
	}
	for _, tc := range []struct {
		name, preferred, want string
	}{
		{"first receiving domain", "relay.example", "relay.example"},
		{"second receiving domain", "RELAY2.EXAMPLE", "relay2.example"},
		{"ambiguous without selection", "", ""},
		{"enabled but not received domain", "relay3.example", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := f.session(t, "send", "127.0.0.1")
			addDomain(sender, "relay2.example")
			addDomain(sender, "relay3.example")
			sender.conf.DKIM2Forwarding.SigningDomain = tc.preferred
			outgoing := dkim2.Envelope{MailFrom: "<>", RcptTo: []string{"<carol@destination.example>"}}
			forwarded, response := feedDKIM2ForwardCallbacks(t, sender, received.wire(), outgoing, nil)
			if tc.want == "" {
				if response != milter.RespTempFail {
					t.Fatalf("unbound signing domain was accepted: %v", response)
				}
				parsed, err := dkim2.Parse(forwarded.wire())
				if err != nil || len(parsed.Signatures) != 1 {
					t.Fatalf("rejected selection added a signature: %+v, %v", parsed, err)
				}
				return
			}
			if response != milter.RespContinue {
				t.Fatalf("explicit receiving signing domain failed: %v", response)
			}
			parsed, err := dkim2.Parse(forwarded.wire())
			if err != nil || len(parsed.Signatures) != 2 || parsed.Signatures[1].Domain != tc.want {
				t.Fatalf("wrong explicitly selected signing domain: %+v, %v", parsed, err)
			}
			if result := dkim2.Verify(forwarded.wire(), outgoing, dkim2.VerifyOptions{Resolver: f.records}); result.Status != dkim2.Pass {
				t.Fatalf("explicit null-sender authentication: %s: %v", result.Status, result.Err)
			}
		})
	}
}

func TestDKIM2ForwardingReceiveInsertionFailureReleasesCapacity(t *testing.T) {
	f := newDKIM2ForwardFixture(t, false)
	info, err := os.Stat(filepath.Join(f.store, f.id+".ctx"))
	if err != nil {
		t.Fatal(err)
	}
	options := f.session(t, "receive", "192.0.2.1").conf.DKIM2Forwarding
	options.MaxStoredBytes = 2 * info.Size()
	options.MaxStoredBytesPerRecipient = options.MaxStoredBytes
	for attempt := 0; attempt < 3; attempt++ {
		receiver := f.session(t, "receive", "192.0.2.1")
		receiver.conf.DKIM2Forwarding = options
		_, response := feedDKIM2ForwardCallbacks(t, receiver, f.original, f.incoming, func(m *dkim2ForwardModifier) {
			m.failInsert = dkim2ContextHeader
		})
		if response != milter.RespTempFail {
			t.Fatalf("insertion failure attempt %d was accepted: %v", attempt, response)
		}
		paths, err := filepath.Glob(filepath.Join(f.store, "*.ctx"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("insertion failure attempt %d leaked a context: %v, %v", attempt, paths, err)
		}
		stored, err := loadDKIM2ForwardContext(options, f.id)
		if err != nil || !bytes.Equal(stored.Raw, f.original) {
			t.Fatalf("insertion rollback removed the previously accepted context: %+v, %v", stored, err)
		}
	}
	receiver := f.session(t, "receive", "192.0.2.1")
	receiver.conf.DKIM2Forwarding = options
	_, response := feedDKIM2ForwardCallbacks(t, receiver, f.original, f.incoming, nil)
	if response != milter.RespContinue {
		t.Fatalf("successful receiving context was blocked by failed attempts: %v", response)
	}
	paths, err := filepath.Glob(filepath.Join(f.store, "*.ctx"))
	if err != nil || len(paths) != 2 {
		t.Fatalf("expected the two accepted contexts: %v, %v", paths, err)
	}
}

func TestDKIM2ForwardingRejectsInvalidContext(t *testing.T) {
	for _, name := range []string{"invalid ID", "empty context", "duplicate", "untrusted", "untrusted missing", "sender domain mismatch", "hidden mixed recipients", "prior signature changed", "valid prior signature swapped", "stored bytes changed", "expired corrupt context", "linked context", "unsafe context permissions", "DNS failure", "insert failure", "context deletion failure"} {
		t.Run(name, func(t *testing.T) {
			f := newDKIM2ForwardFixture(t, false)
			s := f.session(t, "send", "127.0.0.1")
			wire := bytes.Clone(f.received)
			outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.example>", RcptTo: []string{"<carol@destination.example>"}}
			var setup func(*dkim2ForwardModifier)
			switch name {
			case "untrusted missing":
				wire = bytes.Replace(wire, []byte(dkim2ContextHeader+": "+f.id+"\r\n"), nil, 1)
				s.remoteAddr = net.ParseIP("192.0.2.2")
			case "invalid ID":
				wire = bytes.Replace(wire, []byte(f.id), []byte("../invalid-context"), 1)
			case "empty context":
				wire = bytes.Replace(wire, []byte(f.id), nil, 1)
			case "duplicate":
				wire = append([]byte(dkim2ContextHeader+": "+f.id+"\r\n"), wire...)
			case "untrusted":
				s.remoteAddr = net.ParseIP("192.0.2.2")
			case "sender domain mismatch":
				outgoing.MailFrom = "<bounce@unrelated.example>"
			case "hidden mixed recipients":
				outgoing.RcptTo = append(outgoing.RcptTo, "<hidden@destination.example>")
			case "prior signature changed":
				parsed, err := dkim2.Parse(wire)
				if err != nil {
					t.Fatal(err)
				}
				oldSignature := parsed.Signatures[0].Values[0].Value
				replacement := "A" + oldSignature[1:]
				if replacement == oldSignature {
					replacement = "B" + oldSignature[1:]
				}
				wire = bytes.Replace(wire, []byte(oldSignature[:32]), []byte(replacement[:32]), 1)
			case "valid prior signature swapped":
				parsed, err := dkim2.Parse(wire)
				if err != nil {
					t.Fatal(err)
				}
				var retained []string
				for _, field := range parsed.Headers {
					fieldName, _, _ := strings.Cut(field, ":")
					if !strings.EqualFold(fieldName, "DKIM2-Signature") && !strings.EqualFold(fieldName, "Message-Instance") {
						retained = append(retained, field)
					}
				}
				unsigned := append([]byte(strings.Join(retained, "")+"\r\n"), parsed.Body...)
				wire, err = dkim2.Sign(unsigned, dkim2.SignOptions{Domain: "example.jp", Selector: "s", Key: f.key, Envelope: f.incoming, Nonce: "replacement-nonce"})
				if err != nil {
					t.Fatal(err)
				}
				if result := dkim2.Verify(wire, f.incoming, dkim2.VerifyOptions{Resolver: f.records}); result.Status != dkim2.Pass {
					t.Fatalf("replacement must be cryptographically valid: %+v", result)
				}
			case "stored bytes changed", "expired corrupt context":
				if name == "expired corrupt context" {
					rewriteDKIM2ForwardMetadata(t, f, func(metadata *dkim2ContextMetadata) { metadata.Created = 1 })
				}
				path := filepath.Join(f.store, f.id+".ctx")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-3] ^= 1
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "linked context":
				path := filepath.Join(f.store, f.id+".ctx")
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "unsafe context permissions":
				if err := os.Chmod(filepath.Join(f.store, f.id+".ctx"), 0644); err != nil {
					t.Fatal(err)
				}
			case "DNS failure":
				original := net.DefaultResolver
				net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
					return nil, &net.DNSError{Err: "test resolver failure", IsTemporary: true}
				}}
				t.Cleanup(func() { net.DefaultResolver = original })
			case "insert failure":
				setup = func(m *dkim2ForwardModifier) { m.failInsert = "DKIM2-Signature" }
			case "context deletion failure":
				setup = func(m *dkim2ForwardModifier) { m.failChange = true }
			}
			m, response := feedDKIM2ForwardCallbacks(t, s, wire, outgoing, setup)
			if response != milter.RespTempFail {
				t.Fatalf("invalid forwarding context was accepted: %v", response)
			}
			if parsed, err := dkim2.Parse(m.wire()); err != nil || len(parsed.Signatures) != 1 {
				t.Fatalf("failed forwarding added a signature: parsed=%+v error=%v", parsed, err)
			}
		})
	}
}

func TestDKIM2ForwardingCacheMissContinuesWithoutSigning(t *testing.T) {
	for _, action := range []string{"", "skip-signing", "tempfail"} {
		for _, reason := range []string{"not saved", "evicted", "not found", "expired", "capture limit"} {
			t.Run(action+"/"+reason, func(t *testing.T) {
				f := newDKIM2ForwardFixture(t, false)
				s := f.session(t, "send", "127.0.0.1")
				s.conf.EnableDKIM2 = true
				s.conf.DKIM2Forwarding.CacheFailureAction = action
				// A local From would enter initial signing if a cache miss were
				// incorrectly represented as an unhandled forwarding message.
				wire := bytes.Replace(bytes.Clone(f.received), []byte("From: alice@example.jp\r\n"), []byte("From: author@relay.example\r\n"), 1)
				switch reason {
				case "not saved":
					wire = bytes.Replace(wire, []byte(dkim2ContextHeader+": "+f.id+"\r\n"), nil, 1)
				case "evicted":
					if err := os.Remove(filepath.Join(f.store, f.id+".ctx")); err != nil {
						t.Fatal(err)
					}
				case "not found":
					wire = bytes.Replace(wire, []byte(f.id), []byte(strings.Repeat("f", 64)), 1)
				case "expired":
					rewriteDKIM2ForwardMetadata(t, f, func(metadata *dkim2ContextMetadata) { metadata.Created = 1 })
				case "capture limit":
					s.conf.DKIM2MaxMessageBytes = 1
				}
				outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.example>", RcptTo: []string{"<carol@destination.example>"}}
				m, response := feedDKIM2ForwardCallbacks(t, s, wire, outgoing, nil)
				want := milter.RespContinue
				if action == "tempfail" {
					want = milter.RespTempFail
				}
				if response != want {
					t.Fatalf("response=%v, want %v", response, want)
				}
				assertDKIM2ForwardingSkipped(t, wire, m.wire(), action == "tempfail")
			})
		}
	}
}

func TestDKIM2ForwardingCacheMissSurvivesLegacyParseError(t *testing.T) {
	for _, action := range []string{"skip-signing", "tempfail"} {
		t.Run(action, func(t *testing.T) {
			f := newDKIM2ForwardFixture(t, false)
			s := f.session(t, "send", "127.0.0.1")
			s.conf.DKIM2Forwarding.CacheFailureAction = action
			wire := bytes.Replace(bytes.Clone(f.received), []byte("From: alice@example.jp\r\n"), []byte("From: author@relay.example\r\n"), 1)
			wire = bytes.Replace(wire, []byte(dkim2ContextHeader+": "+f.id+"\r\n"), nil, 1)
			wire = append([]byte(strings.Repeat("DKIM-Signature: invalid\r\n", 64)), wire...)
			outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.example>", RcptTo: []string{"<carol@destination.example>"}}
			m, response := feedDKIM2ForwardCallbacks(t, s, wire, outgoing, nil)
			want := milter.RespContinue
			if action == "tempfail" {
				want = milter.RespTempFail
			}
			if response != want {
				t.Fatalf("legacy parse failure cache miss response=%v, want %v", response, want)
			}
			assertDKIM2ForwardingSkipped(t, wire, m.wire(), action == "tempfail")
		})
	}
}

func assertDKIM2ForwardingSkipped(t *testing.T, before, after []byte, tempfail bool) {
	t.Helper()
	original, err := dkim2.Parse(before)
	if err != nil {
		t.Fatal(err)
	}
	final, err := dkim2.Parse(after)
	if err != nil {
		t.Fatal(err)
	}
	if tempfail {
		if len(final.Signatures) != len(original.Signatures) || len(final.Instances) != len(original.Instances) {
			t.Fatalf("temporary failure changed DKIM2 field counts: before=%d/%d after=%d/%d",
				len(original.Signatures), len(original.Instances), len(final.Signatures), len(final.Instances))
		}
		for i := range original.Signatures {
			if original.Signatures[i].Raw != final.Signatures[i].Raw {
				t.Fatal("temporary failure changed a prior DKIM2 signature")
			}
		}
		for i := range original.Instances {
			if original.Instances[i].Raw != final.Instances[i].Raw {
				t.Fatal("temporary failure changed a prior Message-Instance")
			}
		}
	} else if len(final.Signatures) != 0 || len(final.Instances) != 0 {
		t.Fatalf("skipped forwarding retained unverifiable DKIM2 fields: signatures=%d instances=%d",
			len(final.Signatures), len(final.Instances))
	}
	for _, field := range final.Headers {
		name, _, _ := strings.Cut(field, ":")
		if strings.EqualFold(name, dkim2ContextHeader) {
			t.Fatal("forwarding context reference survived skipped delivery")
		}
	}
}

func TestDKIM2ForwardingCacheFailureClassification(t *testing.T) {
	for _, action := range []string{"skip-signing", "tempfail"} {
		for _, tc := range []struct {
			name string
			err  error
			skip bool
		}{
			{"cache miss", errDKIM2CacheMiss, true},
			{"expired", errDKIM2CacheExpired, true},
			{"capacity", errDKIM2CacheCapacity, true},
			{"capture limit", errDKIM2CaptureLimit, true},
			{"disk full", &os.PathError{Op: "write", Path: "context", Err: syscall.ENOSPC}, true},
			{"filesystem quota", syscall.EDQUOT, true},
			{"I/O failure", syscall.EIO, true},
			{"read-only filesystem", syscall.EROFS, true},
			{"permissions", syscall.EACCES, false},
			{"linked path", syscall.ELOOP, false},
			{"corrupt", errors.New("checksum mismatch"), false},
		} {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				s := &Session{conf: &config.Config{EnableDKIM2: true, DKIM2Forwarding: config.DKIM2ForwardingConfig{
					Mode: "send", CacheFailureAction: action,
				}}}
				s.mmauth = mmauth.NewMMAuth()
				t.Cleanup(func() { s.Cleanup(nil) })
				result, err := s.handleDKIM2CacheFailure(&dkim2ForwardModifier{}, "load", tc.err)
				if tc.skip && action == "skip-signing" {
					if err != nil || result != dkim2ForwardSkipped || s.dkim2Result != "dkim2=temperror" {
						t.Fatalf("availability failure did not skip signing: result=%d err=%v auth=%q", result, err, s.dkim2Result)
					}
				} else if !errors.Is(err, tc.err) || result != dkim2ForwardNotApplicable || s.dkim2Result != "" {
					t.Fatalf("strict failure was downgraded: result=%d err=%v auth=%q", result, err, s.dkim2Result)
				}
			})
		}
	}
}

func TestRemoveDKIM2FieldsAllOccurrences(t *testing.T) {
	fields := []string{
		"DKIM2-Signature: first\r\n", "From: alice@example.jp\r\n",
		"Message-Instance: first\r\n", "dkim2-signature: second\r\n",
		"Subject: preserved\r\n", "message-instance: second\r\n",
	}
	s := &Session{conf: &config.Config{}, mmauth: mmauth.NewMMAuth()}
	t.Cleanup(func() { s.Cleanup(nil) })
	s.mmauth.Headers = append(s.mmauth.Headers, fields...)
	m := &dkim2ForwardModifier{fields: slices.Clone(fields)}
	if err := s.removeDKIM2Fields(m); err != nil {
		t.Fatal(err)
	}
	want := []string{"From: alice@example.jp\r\n", "Subject: preserved\r\n"}
	if !slices.Equal(m.fields, want) || !slices.Equal([]string(s.mmauth.Headers), want) {
		t.Fatalf("unverified fields remain: milter=%q parser=%q", m.fields, s.mmauth.Headers)
	}
}

func TestDKIM2ForwardingReceiveCacheFailureContinues(t *testing.T) {
	for _, action := range []string{"", "skip-signing", "tempfail"} {
		for _, reason := range []string{"capacity", "capture limit"} {
			t.Run(action+"/"+reason, func(t *testing.T) {
				f := newDKIM2ForwardFixture(t, false)
				s := f.session(t, "receive", "192.0.2.1")
				s.conf.DKIM2Forwarding.CacheFailureAction = action
				if reason == "capacity" {
					s.conf.DKIM2Forwarding.MaxStoredBytes = 1
				} else {
					s.conf.DKIM2MaxMessageBytes = 1
				}
				m, response := feedDKIM2ForwardCallbacks(t, s, f.original, f.incoming, nil)
				want := milter.RespContinue
				if action == "tempfail" {
					want = milter.RespTempFail
				}
				if response != want {
					t.Fatalf("response=%v, want %v", response, want)
				}
				assertDKIM2ForwardingSkipped(t, f.original, m.wire(), action == "tempfail")
				if _, err := os.Stat(filepath.Join(f.store, f.id+".ctx")); err != nil {
					t.Fatalf("oversized new entry evicted an existing context: %v", err)
				}
			})
		}
	}
}

func rewriteDKIM2ForwardMetadata(t *testing.T, f *dkim2ForwardFixture, modify func(*dkim2ContextMetadata)) {
	t.Helper()
	path := filepath.Join(f.store, f.id+".ctx")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line, raw, ok := bytes.Cut(data, []byte("\n"))
	if !ok {
		t.Fatal("missing forwarding metadata")
	}
	var metadata dkim2ContextMetadata
	if err := json.Unmarshal(line, &metadata); err != nil {
		t.Fatal(err)
	}
	modify(&metadata)
	line, err = json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append(line, '\n'), raw...), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDKIM2ForwardingReceiveDoesNotCacheInvalidAuthentication(t *testing.T) {
	f := newDKIM2ForwardFixture(t, false)
	wrong := f.incoming
	wrong.RcptTo = []string{"<another@relay.example>"}
	for _, tc := range []struct {
		name     string
		raw      []byte
		envelope dkim2.Envelope
	}{
		{"different actual envelope", f.original, wrong},
		{"modified signed body", bytes.Replace(bytes.Clone(f.original), []byte("first\r\n"), []byte("other\r\n"), 1), f.incoming},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, response := feedDKIM2ForwardCallbacks(t, f.session(t, "receive", "192.0.2.1"), tc.raw, tc.envelope, nil)
			if response != milter.RespContinue {
				t.Fatalf("unauthenticated incoming message held delivery in TEMPFAIL: %v", response)
			}
			assertDKIM2ForwardingSkipped(t, tc.raw, m.wire(), false)
			for _, field := range m.fields {
				name, _, _ := strings.Cut(field, ":")
				if strings.EqualFold(name, dkim2ContextHeader) {
					t.Fatal("receiver emitted a context for unauthenticated mail")
				}
			}
			entries, err := os.ReadDir(f.store)
			if err != nil {
				t.Fatal(err)
			}
			contexts := 0
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".ctx") {
					contexts++
				}
			}
			if contexts != 1 {
				t.Fatalf("unauthenticated mail changed context count to %d", contexts)
			}
		})
	}
}

func TestDKIM2ForwardingReceiveStripsMalformedFields(t *testing.T) {
	f := newDKIM2ForwardFixture(t, false)
	for _, name := range []string{"DKIM2-Signature", "Message-Instance"} {
		t.Run(name, func(t *testing.T) {
			s := f.session(t, "receive", "192.0.2.1")
			fields := []string{
				name + ": malformed\r\n", "From: alice@example.jp\r\n", "To: bob@relay.example\r\n",
			}
			m := &dkim2ForwardModifier{fields: slices.Clone(fields), body: []byte("body\r\n")}
			check := expectContinue(t)
			check(s.MailFrom("alice@example.jp", "", m))
			check(s.RcptTo("bob@relay.example", "", m))
			for _, field := range fields {
				fieldName, value, _ := strings.Cut(strings.TrimSuffix(field, "\r\n"), ": ")
				check(s.Header(fieldName, value, m))
			}
			check(s.Headers(m))
			check(s.BodyChunk(m.body, m))
			check(s.EndOfMessage(m))
			if !slices.Equal(m.fields, fields[1:]) {
				t.Fatalf("malformed DKIM2 field survived delivery: %q", m.fields)
			}
		})
	}
}

func TestDKIM2ForwardingReceiveDNSFailureDoesNotHoldDelivery(t *testing.T) {
	f := newDKIM2ForwardFixture(t, false)
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.DNSError{Err: "test resolver failure", IsTemporary: true}
	}}
	t.Cleanup(func() { net.DefaultResolver = original })
	m, response := feedDKIM2ForwardCallbacks(t, f.session(t, "receive", "192.0.2.1"), f.original, f.incoming, nil)
	if response != milter.RespContinue {
		t.Fatalf("temporary DNS error held an external message in TEMPFAIL: %v", response)
	}
	assertDKIM2ForwardingSkipped(t, f.original, m.wire(), false)
}
