package arcmilter

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/d--j/go-milter"
	"github.com/masa23/arcmilter/config"
	"github.com/masa23/mmauth/dkim2"
)

const dkim2EAIDomain = "xn--bcher-kva.example"

func newDKIM2EAIFixture(t *testing.T) *dkim2ForwardFixture {
	t.Helper()
	key, _ := signingKey(t)
	f := &dkim2ForwardFixture{key: key, store: t.TempDir(), records: dkim2KeyRecords(t, key)}
	if err := os.Chmod(f.store, 0700); err != nil {
		t.Fatal(err)
	}
	f.records["dk2._domainkey."+dkim2EAIDomain] = f.records["dk2._domainkey.example.jp"]
	useDKIM2DNS(t, f.records)
	return f
}

func dkim2EAISession(t *testing.T, f *dkim2ForwardFixture, mode, source string) *Session {
	t.Helper()
	s := f.session(t, mode, source)
	domain := s.conf.Domains["relay.example"]
	s.conf.Domains = map[string]config.Domain{dkim2EAIDomain: domain}
	return s
}

func TestDKIM2EAIInitialSigning(t *testing.T) {
	for _, tc := range []struct {
		name, fromDomain, senderDomain, headerDomain, recipientDomain string
	}{
		{"U-label From and recipient", "bücher.example", "bücher.example", "bücher.example", dkim2EAIDomain},
		{"A-label From and recipient", "XN--BCHER-KVA.EXAMPLE", "bücher.EXAMPLE", dkim2EAIDomain, "bücher.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDKIM2EAIFixture(t)
			s := dkim2EAISession(t, f, "disabled", "127.0.0.1")
			envelope := dkim2.Envelope{
				MailFrom: "<送信者@" + tc.senderDomain + ">",
				RcptTo:   []string{"<受信者@" + tc.recipientDomain + ">"},
			}
			from := "From: 送信者@" + tc.fromDomain + "\r\n"
			to := "To: 受信者@" + tc.headerDomain + "\r\n"
			raw := []byte(from + to + "Subject: EAI\r\n\r\nbody\r\n")
			m, response := feedDKIM2ForwardCallbacks(t, s, raw, envelope, nil)
			if response != milter.RespContinue {
				t.Fatalf("initial EAI signing failed: %v", response)
			}
			parsed, err := dkim2.Parse(m.wire())
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.Signatures) != 1 || len(parsed.Instances) != 1 {
				t.Fatalf("initial EAI signature missing: signatures=%d instances=%d", len(parsed.Signatures), len(parsed.Instances))
			}
			sig := parsed.Signatures[0]
			if sig.Domain != dkim2EAIDomain || sig.MailFrom != "<送信者@"+dkim2EAIDomain+">" || !slices.Equal(sig.Recipients, []string{"<受信者@" + dkim2EAIDomain + ">"}) {
				t.Fatalf("signature did not normalize only the domains: %+v", sig)
			}
			if !slices.Contains(parsed.Headers, from) || !slices.Contains(parsed.Headers, to) || !bytes.Equal(parsed.Body, []byte("body\r\n")) {
				t.Fatal("IDNA normalization changed the original message")
			}
			if result := dkim2.Verify(m.wire(), envelope, dkim2.VerifyOptions{Resolver: f.records}); result.Status != dkim2.Pass {
				t.Fatalf("initial EAI authentication: %s: %v", result.Status, result.Err)
			}
		})
	}
}

func TestDKIM2EAIForwarding(t *testing.T) {
	for _, revised := range []bool{false, true} {
		name := "unchanged"
		if revised {
			name = "revised"
		}
		t.Run(name, func(t *testing.T) {
			f := newDKIM2EAIFixture(t)
			receive := dkim2EAISession(t, f, "receive", "192.0.2.1")
			incoming := dkim2.Envelope{MailFrom: "<alice@example.jp>", RcptTo: []string{"<Bob@bücher.EXAMPLE>"}}
			original, err := dkim2.Sign([]byte("From: alice@example.jp\r\nTo: Bob@bücher.example\r\nCc: 受信者@bücher.example\r\nSubject: original\r\n\r\nfirst\r\nlast\r\n"), dkim2.SignOptions{
				Domain: "example.jp", Selector: "s", Key: f.key, Envelope: incoming,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result := dkim2.Verify(original, incoming, dkim2.VerifyOptions{Resolver: f.records}); result.Status != dkim2.Pass {
				t.Fatalf("original EAI authentication: %s: %v", result.Status, result.Err)
			}
			received, response := feedDKIM2ForwardCallbacks(t, receive, original, incoming, nil)
			if response != milter.RespContinue {
				t.Fatalf("receiving EAI context: %v", response)
			}
			id := ""
			for _, field := range received.fields {
				fieldName, value, _ := strings.Cut(field, ":")
				if strings.EqualFold(fieldName, dkim2ContextHeader) {
					id = strings.TrimSpace(value)
				}
			}
			if !validDKIM2ContextID(id) {
				t.Fatal("U-label receiving domain did not select the A-label configuration")
			}
			context, err := loadDKIM2ForwardContext(receive.conf.DKIM2Forwarding, id)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(context.SigningDomains, []string{dkim2EAIDomain}) || context.Envelope.MailFrom != incoming.MailFrom || !slices.Equal(context.Envelope.RcptTo, incoming.RcptTo) || !bytes.Equal(context.Raw, original) {
				t.Fatal("context must normalize signer lookup while preserving the received envelope and message")
			}
			wire := received.wire()
			if revised {
				wire = bytes.Replace(wire, []byte("Subject: original\r\n"), []byte("Subject: changed\r\n"), 1)
				wire = append(wire, []byte("footer\r\n")...)
			}
			outgoing := dkim2.Envelope{
				MailFrom: "<SRS0=AbC@bücher.example>",
				RcptTo:   []string{"<受信者@" + dkim2EAIDomain + ">", "<受信者@bücher.EXAMPLE>"},
			}
			forwarded, response := feedDKIM2ForwardCallbacks(t, dkim2EAISession(t, f, "send", "127.0.0.1"), wire, outgoing, nil)
			if response != milter.RespContinue {
				t.Fatalf("U-label outgoing sender rejected by A-label configuration: %v", response)
			}
			final := forwarded.wire()
			if bytes.Contains(bytes.ToLower(final), []byte(strings.ToLower(dkim2ContextHeader)+":")) {
				t.Fatal("private context header survived outgoing delivery")
			}
			parsed, err := dkim2.Parse(final)
			if err != nil {
				t.Fatal(err)
			}
			wantInstances := 1
			if revised {
				wantInstances = 2
			}
			if len(parsed.Signatures) != 2 || len(parsed.Instances) != wantInstances {
				t.Fatalf("unexpected EAI chain: signatures=%d instances=%d", len(parsed.Signatures), len(parsed.Instances))
			}
			sig := parsed.Signatures[1]
			if sig.Domain != dkim2EAIDomain || sig.MailFrom != "<SRS0=AbC@"+dkim2EAIDomain+">" || slices.Contains(sig.Flags, "exploded") {
				t.Fatalf("outgoing EAI signature changed local part or counted equivalent recipients twice: %+v", sig)
			}
			if result := dkim2.Verify(final, outgoing, dkim2.VerifyOptions{Resolver: f.records}); result.Status != dkim2.Pass {
				t.Fatalf("forwarded EAI authentication: %s: %v", result.Status, result.Err)
			}
		})
	}
}

func TestDKIM2EAIVisibleRecipients(t *testing.T) {
	for _, tc := range []struct {
		name, header, recipient string
		visible                 bool
	}{
		{"U-label header", "Bob@bücher.example", "Bob@xn--bcher-kva.example", true},
		{"U-label envelope", "Bob@xn--bcher-kva.example", "Bob@bücher.example", true},
		{"ASCII domain case", "Bob@XN--BCHER-KVA.EXAMPLE", "Bob@bücher.example", true},
		{"Unicode local part", "受信者@bücher.example", "受信者@xn--bcher-kva.example", true},
		{"local part case", "Bob@bücher.example", "bob@xn--bcher-kva.example", false},
		{"local part normalization", "é@bücher.example", "e\u0301@xn--bcher-kva.example", false},
		{"uppercase U-label", "Bob@bücher.example", "Bob@BÜCHER.example", false},
		{"Unicode case folding", "Bob@i.example", "Bob@İ.example", false},
		{"compatibility domain", "Bob@example.jp", "Bob@ｅxample.jp", false},
		{"ignored character", "Bob@example.jp", "Bob@exam\u200bple.jp", false},
		{"invalid A-label", "Bob@example.jp", "Bob@xn--example-.jp", false},
		{"quoted less-than differs from unquoted", `"<bob"@example.test`, "bob@example.test", false},
		{"unquoted differs from quoted less-than", "bob@example.test", `"<bob"@example.test`, false},
		{"same quoted less-than", `"<bob"@example.test`, `"<bob"@example.test`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := visibleDKIM2Recipients([]string{"To: " + tc.header + "\r\n"}, []string{"<" + tc.recipient + ">"})
			if got != tc.visible {
				t.Fatalf("visibleDKIM2Recipients(%q, %q)=%v, want %v", tc.header, tc.recipient, got, tc.visible)
			}
		})
	}
}

func TestDKIM2EAIPostmasterRecipients(t *testing.T) {
	for _, tc := range []struct {
		name       string
		recipients []string
		multiple   bool
	}{
		{"single domainless Postmaster", []string{"<Postmaster>"}, false},
		{"domainless Postmaster case", []string{"<Postmaster>", "<postmaster>"}, false},
		{"domainless Postmaster and another mailbox", []string{"<Postmaster>", "<bob@example.test>"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := multipleDKIM2Recipients(tc.recipients); got != tc.multiple {
				t.Fatalf("multipleDKIM2Recipients(%q)=%v, want %v", tc.recipients, got, tc.multiple)
			}
		})
	}
}
