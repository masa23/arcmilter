package arcmilter

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/d--j/go-milter"
	"github.com/masa23/mmauth/dkim2"
)

func TestDKIM2ForwardingEvictedOriginalStillDelivers(t *testing.T) {
	f := newDKIM2ForwardFixture(t, false)
	info, err := os.Stat(filepath.Join(f.store, f.id+".ctx"))
	if err != nil {
		t.Fatal(err)
	}
	receiver := f.session(t, "receive", "192.0.2.1")
	receiver.conf.DKIM2Forwarding.MaxStoredBytes = info.Size()
	receiver.conf.DKIM2Forwarding.MaxStoredBytesPerRecipient = info.Size()
	newCopy, response := feedDKIM2ForwardCallbacks(t, receiver, f.original, f.incoming, nil)
	if response != milter.RespContinue {
		t.Fatalf("replacement message did not receive a context: %v", response)
	}
	if _, err := loadDKIM2ForwardContext(receiver.conf.DKIM2Forwarding, f.id); !errors.Is(err, errDKIM2CacheMiss) {
		t.Fatalf("oldest context was not evicted: %v", err)
	}

	outgoing := dkim2.Envelope{MailFrom: "<bounce@relay.example>", RcptTo: []string{"<carol@destination.example>"}}
	oldSender := f.session(t, "send", "127.0.0.1")
	oldSender.conf.EnableDKIM2 = true
	oldCopy, response := feedDKIM2ForwardCallbacks(t, oldSender, f.received, outgoing, nil)
	if response != milter.RespContinue {
		t.Fatalf("evicted original prevented delivery: %v", response)
	}
	assertDKIM2ForwardingSkipped(t, f.received, oldCopy.wire(), false)

	newSender := f.session(t, "send", "127.0.0.1")
	signedCopy, response := feedDKIM2ForwardCallbacks(t, newSender, newCopy.wire(), outgoing, nil)
	if response != milter.RespContinue {
		t.Fatalf("replacement original could not be signed: %v", response)
	}
	parsed, err := dkim2.Parse(signedCopy.wire())
	if err != nil || len(parsed.Signatures) != 2 {
		t.Fatalf("replacement message did not receive an additional signature: parsed=%+v err=%v", parsed, err)
	}
	if result := dkim2.Verify(signedCopy.wire(), outgoing, dkim2.VerifyOptions{Resolver: f.records}); result.Status != dkim2.Pass {
		t.Fatalf("replacement signature did not verify: %s: %v", result.Status, result.Err)
	}
}
