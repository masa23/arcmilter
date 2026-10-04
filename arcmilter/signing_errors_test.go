package arcmilter

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/masa23/mmauth/arc"
	"github.com/masa23/mmauth/dkim"
	"github.com/masa23/mmauth/domainkey"
)

func TestRSASignaturesVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	publicKey := &domainkey.DomainKey{KeyType: domainkey.KeyTypeRSA, PublicKey: base64.StdEncoding.EncodeToString(pub)}
	headers := []string{"From: a@example.jp\r\n", "Subject: RSA\r\n"}
	s := newSigningSession(t, headers, key)
	m := &signingModifier{}
	DKIMSign(s, m)
	if len(m.headers) != 1 {
		t.Fatalf("expected one DKIM signature, got %v", m.headers)
	}
	sig, err := dkim.ParseSignature(m.headers[0])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("body\r\n"))
	bodyHash := base64.StdEncoding.EncodeToString(digest[:])
	sig.Verify(headers, bodyHash, publicKey)
	if sig.Algorithm != dkim.SignatureAlgorithmRSA_SHA256 || sig.VerifyResult.Status() != dkim.VerifyStatusPass {
		t.Fatalf("RSA DKIM verification failed: %v", sig.VerifyResult.Error())
	}
	modified := append([]string(nil), headers...)
	modified[1] = "Subject: tampered\r\n"
	sig.Verify(modified, bodyHash, publicKey)
	if sig.VerifyResult.Status() == dkim.VerifyStatusPass {
		t.Fatal("tampered RSA message passed verification")
	}
	s = newSigningSession(t, headers, key)
	s.mmauth.Verify()
	m = &signingModifier{}
	ARCSign(s, m)
	checkARCSet(t, m, headers, 1, arc.ChainValidationResultNone, publicKey)
}

type errorSigner struct {
	crypto.Signer
	failAt, calls int
}

func (s *errorSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	if s.calls == s.failAt {
		return nil, errors.New("injected signing failure")
	}
	return s.Signer.Sign(random, digest, opts)
}

type errorModifier struct {
	signingModifier
	failAt, calls int
}

func (m *errorModifier) InsertHeader(index int, name, value string) error {
	m.calls++
	if m.calls == m.failAt {
		return errors.New("injected insertion failure")
	}
	return m.signingModifier.InsertHeader(index, name, value)
}

func TestSigningFailuresDoNotInsertHeaders(t *testing.T) {
	key, _ := signingKey(t)
	for _, tc := range []struct {
		name   string
		sign   func(*Session, *errorModifier)
		failAt int
	}{
		{"DKIM signing", func(s *Session, m *errorModifier) { DKIMSign(s, m) }, 1},
		{"ARC message signing", func(s *Session, m *errorModifier) { ARCSign(s, m) }, 1},
		{"ARC seal signing", func(s *Session, m *errorModifier) { ARCSign(s, m) }, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := &errorSigner{Signer: key, failAt: tc.failAt}
			s := newSigningSession(t, []string{"From: a@example.jp\r\n", "Subject: failure\r\n"}, signer)
			s.mmauth.Verify()
			m := &errorModifier{}
			tc.sign(s, m)
			if signer.calls != tc.failAt || m.calls != 0 {
				t.Fatalf("failure was not handled: signing calls=%d, insertion calls=%d", signer.calls, m.calls)
			}
		})
	}
}

func TestHeaderInsertionFailuresStopSigning(t *testing.T) {
	key, _ := signingKey(t)
	for _, kind := range []string{"DKIM", "ARC"} {
		limit := 1
		if kind == "ARC" {
			limit = 3
		}
		for failAt := 1; failAt <= limit; failAt++ {
			t.Run(kind+"/"+strconv.Itoa(failAt), func(t *testing.T) {
				s := newSigningSession(t, []string{"From: a@example.jp\r\n", "Subject: failure\r\n"}, key)
				s.mmauth.Verify()
				m := &errorModifier{failAt: failAt}
				if kind == "DKIM" {
					DKIMSign(s, m)
				} else {
					ARCSign(s, m)
				}
				if m.calls != failAt || len(m.headers) != failAt-1 {
					t.Fatalf("insertion continued after error: calls=%d, headers=%v", m.calls, m.headers)
				}
				if kind == "DKIM" {
					for _, h := range s.mmauth.Headers {
						if strings.HasPrefix(h, "DKIM-Signature:") {
							t.Fatal("failed insertion was recorded as successful")
						}
					}
				}
			})
		}
	}
}

func TestSigningSkipsUnavailableInputs(t *testing.T) {
	key, _ := signingKey(t)
	unsupported, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		change  func(*Session)
		arcOnly bool
	}{
		{"disabled", func(s *Session) { s.isDKIMSign, s.isARCSign = false, false }, false},
		{"no matching domain", func(s *Session) { s.fromDomain, s.rcptToDomain = "outside.example", "outside.example" }, false},
		{"domain signing disabled", func(s *Session) {
			d := s.conf.Domains["example.jp"]
			d.DKIM, d.ARC = false, false
			s.conf.Domains["example.jp"] = d
		}, false},
		{"missing body hash", func(s *Session) {
			d := s.conf.Domains["example.jp"]
			d.BodyCanonicalization = "simple"
			s.conf.Domains["example.jp"] = d
		}, false},
		{"unsupported key", func(s *Session) {
			d := s.conf.Domains["example.jp"]
			d.PrivateKeySigner = unsupported
			s.conf.Domains["example.jp"] = d
		}, false},
		{"missing authentication headers", func(s *Session) { s.mmauth.AuthenticationHeaders = nil }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSigningSession(t, []string{"From: a@example.jp\r\n", "Subject: skip\r\n"}, key)
			s.mmauth.Verify()
			tc.change(s)
			m := &signingModifier{}
			if !tc.arcOnly {
				DKIMSign(s, m)
			}
			ARCSign(s, m)
			if len(m.headers) != 0 {
				t.Fatalf("unexpected signatures: %v", m.headers)
			}
		})
	}
	t.Run("existing DKIM signature", func(t *testing.T) {
		s := newSigningSession(t, []string{"From: a@example.jp\r\n", "DKIM-Signature: existing\r\n"}, key)
		m := &signingModifier{}
		DKIMSign(s, m)
		if len(m.headers) != 0 {
			t.Fatal("existing DKIM signature was signed again")
		}
	})
}
