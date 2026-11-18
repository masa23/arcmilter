package arcmilter

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/d--j/go-milter"
	"github.com/masa23/arcmilter/config"
	"github.com/masa23/mmauth/dkim2"
)

func startDKIM2ProtocolServer(t *testing.T, conf *config.Config) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- New(nil).Serve(listener, conf) }()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("Milter server exit: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Milter server did not stop after listener close")
		}
	})
	return listener.Addr().String()
}

// 受け取ったMilter命令をMTAと同じ順序で適用して、配送されるメールを復元する。
func applyDKIM2ProtocolHeaders(t *testing.T, original []string, changes []milter.ModifyAction) []string {
	t.Helper()
	fields := append([]string(nil), original...)
	for _, change := range changes {
		raw := change.HeaderName + ": " + strings.ReplaceAll(change.HeaderValue, "\n", "\r\n") + "\r\n"
		switch change.Type {
		case milter.ActionInsertHeader:
			index := int(change.HeaderIndex)
			if index < 0 || index > len(fields) {
				t.Fatalf("invalid Milter insertion index %d for %d headers", index, len(fields))
			}
			fields = slices.Insert(fields, index, raw)
		case milter.ActionChangeHeader:
			occurrence, found := uint32(0), false
			for index, field := range fields {
				name, _, _ := strings.Cut(field, ":")
				if !strings.EqualFold(name, change.HeaderName) {
					continue
				}
				occurrence++
				if occurrence != change.HeaderIndex {
					continue
				}
				if change.HeaderValue == "" {
					fields = slices.Delete(fields, index, index+1)
				} else {
					fields[index] = raw
				}
				found = true
				break
			}
			if !found {
				t.Fatalf("Milter changed missing header %s occurrence %d", change.HeaderName, change.HeaderIndex)
			}
		default:
			t.Fatalf("unexpected forwarding modification: %v", change)
		}
	}
	return fields
}

func exchangeDKIM2ProtocolMessage(t *testing.T, address, remote string, raw []byte, envelope dkim2.Envelope) []byte {
	t.Helper()
	parsed, err := dkim2.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	client := milter.NewClient("tcp", address)
	session, err := client.Session(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			t.Error(err)
		}
	}()
	if session.ProtocolOption(milter.OptRcptRej) {
		t.Fatal("forwarding Milter must not request rejected recipients")
	}
	check := func(action *milter.Action, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if action.StopProcessing() || action.Type == milter.ActionDiscard {
			t.Fatalf("unexpected Milter action: %v", action)
		}
	}
	check(session.Conn("smtp.example", milter.FamilyInet, 25, remote))
	check(session.Helo("smtp.example"))
	check(session.Mail(envelope.MailFrom, ""))
	for _, recipient := range envelope.RcptTo {
		check(session.Rcpt(recipient, ""))
	}
	check(session.DataStart())
	for _, field := range parsed.Headers {
		name, value, _ := strings.Cut(strings.TrimSuffix(field, "\r\n"), ":")
		check(session.HeaderField(name, strings.ReplaceAll(strings.TrimPrefix(value, " "), "\r\n", "\n"), nil))
	}
	check(session.HeaderEnd())
	changes, action, err := session.BodyReadFrom(bytes.NewReader(parsed.Body))
	check(action, err)
	fields := applyDKIM2ProtocolHeaders(t, parsed.Headers, changes)
	return append([]byte(strings.Join(fields, "")+"\r\n"), parsed.Body...)
}

func TestDKIM2ForwardProtocol(t *testing.T) {
	originPublic, originKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relayPublic, relayKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	record := func(public ed25519.PublicKey) []string {
		return []string{"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(public)}
	}
	records := dkim2Records{
		"origin._domainkey.origin.test": record(originPublic),
		"relay._domainkey.relay.test":   record(relayPublic),
		"arc._domainkey.relay.test":     record(relayPublic),
		"origin.test":                   {"v=spf1 -all"},
		"relay.test":                    {"v=spf1 -all"},
	}
	useDKIM2DNS(t, records)
	_, network, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	base := config.Config{
		EnableDKIM2: true, DKIM2MaxMessageBytes: config.DefaultDKIM2MaxMessageBytes,
		ParsedMyNetworks: []*net.IPNet{network},
		DKIMSignHeaders:  []string{"From", "Subject"}, ARCSignHeaders: []string{"From", "Subject"},
		DKIM2Forwarding: config.DKIM2ForwardingConfig{
			StoreDirectory: filepath.Join(t.TempDir(), "contexts"), MaxAgeSeconds: config.DefaultDKIM2ForwardingMaxAgeSeconds,
			MaxStoredBytes: config.DefaultDKIM2ForwardingMaxStoredBytes, ForwardRecipients: []string{"*@relay.test"},
			AllowRecipeDisclosure: true,
		},
		Domains: map[string]config.Domain{
			"relay.test": {
				Domain: "relay.test", Pattern: "relay.test", DKIM2: true, ARC: true,
				PrivateKeySigner: relayKey, Selector: "relay", DKIM2Selector: "relay", ARCSelector: "arc",
				HeaderCanonicalization: "relaxed", BodyCanonicalization: "relaxed", HashAlgo: crypto.SHA256,
			},
		},
	}
	receive, send, outbound := base, base, base
	receive.DKIM2Forwarding.Mode, send.DKIM2Forwarding.Mode = "receive", "send"
	receiveAddress := startDKIM2ProtocolServer(t, &receive)
	sendAddress := startDKIM2ProtocolServer(t, &send)
	outboundAddress := startDKIM2ProtocolServer(t, &outbound)
	t.Run("unsigned external message with local From remains unsigned", func(t *testing.T) {
		unsigned := []byte("From: alice@relay.test\r\nTo: bob@relay.test\r\nCc: carol@destination.test\r\nSubject: new message\r\n\r\nbody\r\n")
		incoming := dkim2.Envelope{MailFrom: "<alice@relay.test>", RcptTo: []string{"<bob@relay.test>"}}
		received := exchangeDKIM2ProtocolMessage(t, receiveAddress, "192.0.2.10", unsigned, incoming)
		parsed, err := dkim2.Parse(received)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.Signatures) != 0 || len(parsed.Instances) != 0 {
			t.Fatal("receive stage signed before the MTA finalized the envelope")
		}
		outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.test>", RcptTo: []string{"<carol@destination.test>"}}
		final := exchangeDKIM2ProtocolMessage(t, sendAddress, "127.0.0.1", received, outgoing)
		parsed, err = dkim2.Parse(final)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.Signatures) != 0 || len(parsed.Instances) != 0 {
			t.Fatalf("send stage signed external mail without a receiving context: %+v", parsed.Signatures)
		}
	})
	t.Run("separate outbound route initially signs local mail", func(t *testing.T) {
		unsigned := []byte("From: alice@relay.test\r\nTo: bob@relay.test\r\nCc: carol@destination.test\r\nSubject: new message\r\n\r\nbody\r\n")
		outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.test>", RcptTo: []string{"<carol@destination.test>"}}
		final := exchangeDKIM2ProtocolMessage(t, outboundAddress, "127.0.0.1", unsigned, outgoing)
		parsed, err := dkim2.Parse(final)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.Signatures) != 1 || len(parsed.Instances) != 1 || parsed.Signatures[0].MailFrom != outgoing.MailFrom || !slices.Equal(parsed.Signatures[0].Recipients, outgoing.RcptTo) {
			t.Fatalf("outbound signing did not use the final envelope: %+v", parsed.Signatures)
		}
		if result := dkim2.Verify(final, outgoing, dkim2.VerifyOptions{Resolver: records}); result.Status != dkim2.Pass {
			t.Fatalf("outbound signature did not verify: %+v", result)
		}
	})
	t.Run("invalid incoming DKIM2 chain is removed before forwarding", func(t *testing.T) {
		incoming := dkim2.Envelope{MailFrom: "<alice@origin.test>", RcptTo: []string{"<bob@relay.test>"}}
		original, err := dkim2.Sign([]byte("From: alice@origin.test\r\nTo: bob@relay.test\r\nSubject: original\r\n\r\nbody\r\n"), dkim2.SignOptions{
			Domain: "origin.test", Selector: "origin", Key: originKey, Envelope: incoming,
		})
		if err != nil {
			t.Fatal(err)
		}
		changed := bytes.Replace(original, []byte("body\r\n"), []byte("evil\r\n"), 1)
		received := exchangeDKIM2ProtocolMessage(t, receiveAddress, "192.0.2.10", changed, incoming)
		if bytes.Contains(received, []byte(dkim2ContextHeader+":")) {
			t.Fatal("unauthenticated incoming mail received a forwarding context")
		}
		outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.test>", RcptTo: []string{"<hidden@destination.test>"}}
		final := exchangeDKIM2ProtocolMessage(t, sendAddress, "127.0.0.1", received, outgoing)
		parsed, err := dkim2.Parse(final)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.Signatures) != 0 || len(parsed.Instances) != 0 {
			t.Fatal("unverified DKIM2 chain survived outbound delivery")
		}
		if bytes.Contains(final, []byte("DKIM-Signature:")) {
			t.Fatal("send stage made an initial DKIM signature for external mail")
		}
	})
	for _, recipients := range []struct {
		name string
		to   []string
	}{
		{"unselected recipient", []string{"<other@local.test>"}},
		{"mixed recipients", []string{"<bob@relay.test>", "<other@local.test>"}},
	} {
		t.Run("invalid incoming chain with "+recipients.name+" is removed at receive", func(t *testing.T) {
			incoming := dkim2.Envelope{MailFrom: "<alice@origin.test>", RcptTo: recipients.to}
			original, err := dkim2.Sign([]byte("From: alice@origin.test\r\nTo: other@local.test\r\nSubject: original\r\n\r\nbody\r\n"), dkim2.SignOptions{
				Domain: "origin.test", Selector: "origin", Key: originKey, Envelope: incoming,
			})
			if err != nil {
				t.Fatal(err)
			}
			changed := bytes.Replace(original, []byte("body\r\n"), []byte("evil\r\n"), 1)
			received := exchangeDKIM2ProtocolMessage(t, receiveAddress, "192.0.2.10", changed, incoming)
			parsed, err := dkim2.Parse(received)
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.Signatures) != 0 || len(parsed.Instances) != 0 || bytes.Contains(received, []byte(dkim2ContextHeader+":")) {
				t.Fatal("receive stage left an unverified chain or context on an unselected delivery")
			}
		})
	}
	t.Run("unselected oversized chain is removed in strict cache mode", func(t *testing.T) {
		strict := receive
		strict.DKIM2MaxMessageBytes = 128
		strict.DKIM2Forwarding.CacheFailureAction = "tempfail"
		address := startDKIM2ProtocolServer(t, &strict)
		incoming := dkim2.Envelope{MailFrom: "<alice@origin.test>", RcptTo: []string{"<other@local.test>"}}
		original, err := dkim2.Sign([]byte("From: alice@origin.test\r\nTo: other@local.test\r\nSubject: original\r\n\r\nbody\r\n"), dkim2.SignOptions{
			Domain: "origin.test", Selector: "origin", Key: originKey, Envelope: incoming,
		})
		if err != nil {
			t.Fatal(err)
		}
		received := exchangeDKIM2ProtocolMessage(t, address, "192.0.2.10", original, incoming)
		parsed, err := dkim2.Parse(received)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.Signatures) != 0 || len(parsed.Instances) != 0 {
			t.Fatal("unverified oversized chain remained on an unselected delivery")
		}
	})
	t.Run("mixed receive recipients have no context and send removes the old chain", func(t *testing.T) {
		incoming := dkim2.Envelope{MailFrom: "<alice@origin.test>", RcptTo: []string{"<bob@relay.test>", "<other@local.test>"}}
		original, err := dkim2.Sign([]byte("From: alice@origin.test\r\nTo: bob@relay.test\r\nCc: other@local.test\r\nSubject: mixed\r\n\r\nbody\r\n"), dkim2.SignOptions{
			Domain: "origin.test", Selector: "origin", Key: originKey, Envelope: incoming,
		})
		if err != nil {
			t.Fatal(err)
		}
		received := exchangeDKIM2ProtocolMessage(t, receiveAddress, "192.0.2.10", original, incoming)
		if bytes.Contains(received, []byte(dkim2ContextHeader+":")) {
			t.Fatal("mixed recipient transaction received a forwarding context")
		}
		outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.test>", RcptTo: []string{"<hidden@destination.test>"}}
		final := exchangeDKIM2ProtocolMessage(t, sendAddress, "127.0.0.1", received, outgoing)
		parsed, err := dkim2.Parse(final)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.Signatures) != 0 || len(parsed.Instances) != 0 {
			t.Fatal("chain with no receiving context survived outbound delivery")
		}
	})
	incoming := dkim2.Envelope{MailFrom: "<alice@origin.test>", RcptTo: []string{"<bob@relay.test>"}}
	// alias転送でToにない宛先へ配送し、SRS相当の送信元書換えもMTA側で完了させる。
	outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.test>", RcptTo: []string{"<hidden@destination.test>"}}
	for _, tc := range []struct {
		name      string
		modified  bool
		instances int
	}{
		{"unchanged forwarding", false, 1},
		{"subject and footer revised", true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unsigned := []byte("From: Alice <alice@origin.test>\r\nTo: Bob <bob@relay.test>\r\nSubject: original\r\n\r\noriginal body\r\n")
			original, err := dkim2.Sign(unsigned, dkim2.SignOptions{
				Domain: "origin.test", Selector: "origin", Key: originKey, Envelope: incoming,
			})
			if err != nil {
				t.Fatal(err)
			}
			before, err := dkim2.Parse(original)
			if err != nil {
				t.Fatal(err)
			}
			received := exchangeDKIM2ProtocolMessage(t, receiveAddress, "192.0.2.10", original, incoming)
			if !bytes.Contains(received, []byte("X-ARCMilter-DKIM2-Context: ")) {
				t.Fatal("receive stage did not add its forwarding context")
			}
			if tc.modified {
				received = bytes.Replace(received, []byte("Subject: original\r\n"), []byte("Subject: changed by mailing list\r\n"), 1)
				received = append(received, []byte("forwarding footer\r\n")...)
			}
			forwarded := exchangeDKIM2ProtocolMessage(t, sendAddress, "127.0.0.1", received, outgoing)
			after, err := dkim2.Parse(forwarded)
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Signatures) != 2 || len(after.Instances) != tc.instances {
				t.Fatalf("forwarded DKIM2 structure: signatures=%d instances=%d", len(after.Signatures), len(after.Instances))
			}
			latest := after.Signatures[1]
			if latest.Index != 2 || latest.Instance != tc.instances || latest.Domain != "relay.test" || latest.MailFrom != outgoing.MailFrom || !slices.Equal(latest.Recipients, outgoing.RcptTo) {
				t.Fatalf("forwarding signature does not record the outgoing SMTP transaction: %+v", latest)
			}
			if after.Signatures[0].Raw != before.Signatures[0].Raw || after.Instances[0].Raw != before.Instances[0].Raw {
				t.Fatal("forwarding changed prior DKIM2 fields")
			}
			for _, field := range after.Headers {
				name, _, _ := strings.Cut(field, ":")
				if strings.EqualFold(name, "X-ARCMilter-DKIM2-Context") {
					t.Fatal("internal forwarding context was exposed to the destination")
				}
			}
			if result := dkim2.Verify(forwarded, outgoing, dkim2.VerifyOptions{Resolver: records}); result.Status != dkim2.Pass {
				t.Fatalf("forwarded message failed complete DKIM2 verification: %+v", result)
			}
		})
	}
}
