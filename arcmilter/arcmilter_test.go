package arcmilter

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/d--j/go-milter"
	"github.com/masa23/arcmilter/config"
	"github.com/masa23/mmauth"
	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/dkim"
	"github.com/masa23/mmauth/domainkey"
)

type signingModifier struct {
	milter.Modifier
	headers []string
}

func (m *signingModifier) InsertHeader(index int, name, value string) error {
	m.headers = append(m.headers, name+": "+value+"\r\n")
	return nil
}

func newSigningSession(t *testing.T, headers []string, key ed25519.PrivateKey) *Session {
	t.Helper()
	auth := mmauth.NewMMAuth()
	auth.AddBodyHash(createBodyHashConfig("relaxed", crypto.SHA256, 0))
	t.Cleanup(func() { auth.Close() })
	raw := strings.Join(headers, "") + "\r\nbody\r\n"
	if _, err := auth.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := auth.Close(); err != nil {
		t.Fatal(err)
	}
	return &Session{
		isARCSign: true, isDKIMSign: true,
		rcptToDomain: "example.jp", fromDomain: "example.jp", mailFrom: "invalid",
		mmauth: auth,
		conf: &config.Config{
			ARCSignHeaders:  []string{"From", "Subject"},
			DKIMSignHeaders: []string{"From", "Subject"},
			Domains: map[string]config.Domain{
				"example.jp": {
					Domain: "example.jp", Pattern: "example.jp", DKIM: true, ARC: true,
					Selector: "s", ARCSelector: "s", PrivateKeySigner: key,
					HeaderCanonicalization: "relaxed", BodyCanonicalization: "relaxed", HashAlgo: crypto.SHA256,
				},
			},
		},
	}
}

func signingKey(t *testing.T) (ed25519.PrivateKey, *domainkey.DomainKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, &domainkey.DomainKey{KeyType: domainkey.KeyTypeED25519, PublicKey: base64.StdEncoding.EncodeToString(pub)}
}

func TestDKIMSignRepeatedHeaders(t *testing.T) {
	key, publicKey := signingKey(t)
	headers := []string{
		"From: a@example.jp\r\n", "Received: by unselected.example.jp\r\n",
		"Received: by last.example.jp\r\n", "Subject: test\r\n", "Received: by first.example.jp\r\n",
	}
	for _, canon := range []string{"simple", "relaxed"} {
		for _, names := range [][]string{
			{"From", "Received", "Subject"},
			{"From", "Received", "Subject", "received"},
		} {
			t.Run(canon+"/"+strings.Join(names, ":"), func(t *testing.T) {
				s := newSigningSession(t, headers, key)
				s.conf.DKIMSignHeaders = names
				domain := s.conf.Domains["example.jp"]
				domain.HeaderCanonicalization = canon
				s.conf.Domains["example.jp"] = domain
				m := &signingModifier{}
				DKIMSign(s, m)
				if len(m.headers) != 1 {
					t.Fatalf("expected one DKIM signature, got %d", len(m.headers))
				}
				sig, err := dkim.ParseSignature(m.headers[0])
				if err != nil {
					t.Fatal(err)
				}
				if !strings.EqualFold(sig.Headers, strings.Join(names, ":")) {
					t.Fatalf("unexpected h= value: %s", sig.Headers)
				}
				sig.Verify(headers, sig.BodyHash, publicKey)
				if sig.VerifyResult.Status() != dkim.VerifyStatusPass {
					t.Fatalf("DKIM verification: %s: %v", sig.VerifyResult.Status(), sig.VerifyResult.Error())
				}
			})
		}
	}
}

func addARCSet(t *testing.T, headers []string, instance int, cv arc.ChainValidationResult, key ed25519.PrivateKey) []string {
	t.Helper()
	body := sha256.Sum256([]byte("body\r\n"))
	ams := &arc.ARCMessageSignature{
		InstanceNumber: instance, Domain: "example.jp", Selector: "s", Canonicalization: "relaxed/relaxed",
		BodyHash: base64.StdEncoding.EncodeToString(body[:]),
	}
	if err := ams.Sign(mmauth.ExtractHeadersDKIM(headers, []string{"From", "Subject"}), key); err != nil {
		t.Fatal(err)
	}
	result := fmt.Sprintf("ARC-Authentication-Results: i=%d; example.jp; dkim=pass\r\n", instance)
	current := append(append([]string(nil), headers...), result, "ARC-Message-Signature: "+ams.String()+"\r\n")
	seal := &arc.ARCSeal{InstanceNumber: instance, Domain: "example.jp", Selector: "s", ChainValidation: cv}
	if err := seal.Sign(current, key); err != nil {
		t.Fatal(err)
	}
	return append(current, "ARC-Seal: "+seal.String()+"\r\n")
}

func useARCResolver(t *testing.T, key *domainkey.DomainKey) {
	t.Helper()
	original := domainkey.DefaultResolver
	t.Cleanup(func() { domainkey.DefaultResolver = original })
	domainkey.DefaultResolver = func(name string) ([]string, error) {
		if name != "s._domainkey.example.jp" {
			return nil, fmt.Errorf("unexpected DNS query: %s", name)
		}
		return []string{"v=DKIM1; k=ed25519; p=" + key.PublicKey}, nil
	}
}

func checkARCSet(t *testing.T, m *signingModifier, headers []string, instance int, cv arc.ChainValidationResult, publicKey *domainkey.DomainKey) {
	t.Helper()
	if len(m.headers) != 3 {
		t.Fatalf("expected complete ARC set, got %d headers", len(m.headers))
	}
	ams, err := arc.ParseARCMessageSignature(m.headers[1])
	if err != nil {
		t.Fatal(err)
	}
	seal, err := arc.ParseARCSeal(m.headers[2])
	if err != nil {
		t.Fatal(err)
	}
	if seal.InstanceNumber != instance || seal.ChainValidation != cv || ams.InstanceNumber != instance {
		t.Fatalf("unexpected ARC instance or cv: i=%d cv=%s AMS i=%d", seal.InstanceNumber, seal.ChainValidation, ams.InstanceNumber)
	}
	body := sha256.Sum256([]byte("body\r\n"))
	if result := ams.Verify(headers, base64.StdEncoding.EncodeToString(body[:]), publicKey); result.Status() != arc.VerifyStatusPass {
		t.Fatalf("AMS verification: %s: %v", result.Status(), result.Error())
	}
	if cv == arc.ChainValidationResultFail {
		// cv=fail は Verify が即座に fail を返すため、新しいセットだけを
		// 対象にして Ed25519 署名を直接検証する。
		relaxed := func(raw string) string {
			name, value, _ := strings.Cut(raw, ":")
			return strings.ToLower(strings.TrimSpace(name)) + ":" + strings.Join(strings.Fields(value), " ") + "\r\n"
		}
		raw := relaxed(m.headers[0]) + relaxed(m.headers[1]) + strings.TrimSuffix(relaxed("ARC-Seal: "+seal.StringWithoutSignature()), "\r\n")
		digest := sha256.Sum256([]byte(raw))
		signature, err := base64.StdEncoding.DecodeString(seal.Signature)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := base64.StdEncoding.DecodeString(publicKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), digest[:], signature) {
			t.Fatal("cv=fail seal does not sign exactly the new ARC set")
		}
	} else {
		all := append(append([]string(nil), headers...), m.headers...)
		if result := seal.Verify(all, publicKey); result.Status() != arc.VerifyStatusPass {
			t.Fatalf("seal verification: %s: %v", result.Status(), result.Error())
		}
	}
}

func TestARCSignChainValidation(t *testing.T) {
	key, publicKey := signingKey(t)
	useARCResolver(t, publicKey)
	base := []string{"From: a@example.jp\r\n", "Subject: test\r\n"}
	valid := addARCSet(t, base, 1, arc.ChainValidationResultNone, key)
	broken := append([]string(nil), valid...)
	broken[1] = "Subject: modified\r\n"
	failed := addARCSet(t, valid, 2, arc.ChainValidationResultFail, key)
	for _, tc := range []struct {
		name     string
		headers  []string
		instance int
		cv       arc.ChainValidationResult
	}{
		{"no chain", base, 1, arc.ChainValidationResultNone},
		{"valid chain", valid, 2, arc.ChainValidationResultPass},
		{"failed verification", broken, 2, arc.ChainValidationResultFail},
		{"incomplete set", valid[:len(valid)-1], 2, arc.ChainValidationResultFail},
		{"duplicate seal", append(append([]string(nil), valid...), valid[len(valid)-1]), 2, arc.ChainValidationResultFail},
		{"malformed with instance", append(append([]string(nil), base...), "ARC-Seal: i=7; broken\r\n"), 8, arc.ChainValidationResultFail},
		{"malformed without instance", append(append([]string(nil), base...), "ARC-Seal: broken\r\n"), 1, arc.ChainValidationResultFail},
		{"earlier declared failure", append(append([]string(nil), failed...), "ARC-Message-Signature: i=3; broken\r\n"), 4, arc.ChainValidationResultFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSigningSession(t, tc.headers, key)
			s.mmauth.Verify()
			m := &signingModifier{}
			ARCSign(s, m)
			checkARCSet(t, m, tc.headers, tc.instance, tc.cv, publicKey)
		})
	}
}

func TestARCSignStopsForDeclaredFailureOrInstanceLimit(t *testing.T) {
	key, publicKey := signingKey(t)
	useARCResolver(t, publicKey)
	base := []string{"From: a@example.jp\r\n", "Subject: test\r\n"}
	valid := addARCSet(t, base, 1, arc.ChainValidationResultNone, key)
	failed := addARCSet(t, valid, 2, arc.ChainValidationResultFail, key)
	limit := valid
	for instance := 2; instance <= 50; instance++ {
		limit = addARCSet(t, limit, instance, arc.ChainValidationResultPass, key)
	}
	for _, tc := range []struct {
		name    string
		headers []string
	}{
		{"declared failure", failed},
		{"declared failure in incomplete set", append(append([]string(nil), base...), failed[len(failed)-1])},
		{"valid chain at limit", limit},
		{"malformed chain at limit", append(append([]string(nil), base...), "ARC-Seal: i=50; broken\r\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSigningSession(t, tc.headers, key)
			s.mmauth.Verify()
			m := &signingModifier{}
			ARCSign(s, m)
			if len(m.headers) != 0 {
				t.Fatalf("unexpected ARC headers: %v", m.headers)
			}
		})
	}
}
