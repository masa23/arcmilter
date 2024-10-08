package arc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"os"
	"testing"
)

var testRSAPrivateKey = `
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCgUTPX3OM3V/Au
mWjNEgXP5/s91oBA4blrWQ7j3o1Oos2++RsMMAgkbeMAAUD+k+RcDnBHMiYO5S8y
ae6u/ggVkl++VMQdp0FuClCOAKBKepRchhrVTgQt4F8QcVUFXSVQhNtn2QEaMn3Y
jeogWvc9CTKxLr9h8mWkEnQKsLc+VQZ+qO2cRDWklz36hk2YiLLDYKsw51mqKKNs
3xm5zaOo8GXehb0Ilppy/41lS6gG45E6yYfr+ZUABgVrZFeKg4q3bXiE8fSgWwTO
P0IsOrCp1tVoGkxTiH06kbU+0/kMiRs0vy9Mp+MMcqhu8NNjfnUlly1RNandXCi8
BZp0KOclAgMBAAECggEAHlDcteA+U1PcxmMaL1VOJg+fMgVjAWHt9z/DEhIetJUS
xR9EHxziHUluWKzkBoAe+c19K+luyvhJ4YWorgy5qKKiWlKbN2ROeimXLBMwPIVL
kueFIXr8TVSVhX1472e6y6wj9VJS5ApSQ+YqNO4evLsFi/3kEPiOgeU/bloWfMG4
twwe5scyVlcDiiBwVFBSnoSQKR3szoGIsvr4gH4QQGHWnn+9S8o+ujOCmdcHpOjF
5QJMjmBQjTgujBFQJA5B0ITSsT9wfSOKEdyBKphzfU2cbFUUfUwWF6WS8g1vVC76
3+NmiB06UcNGVFl4vID+zG6Y2CHiScfXBAmpXgepoQKBgQDLcnzDcZTAPdAQnU5U
QvcTavNSh3rh7W0/vMmOeXooqKSqTLzGXSnIQjuNIo2oIVP2cLsv3p1d73Qupk9g
S9USC3Zac2i6tSbKUxPBAyBlzwCl4aFLpq1MV/+G+/3E7+3EOWOzqTXlvMOxpTZT
pSWsXL4fpdkaJr/XPWnWxl06OQKBgQDJup9uS4cXwMXGaFpmQ0YqGcAlQOtIErLa
mTlPxU2T8gUl9z5xcV5EmXMSWU6bpoH5pmCw52VI8Ue02KBKsNfz9M8J8oG7ttvq
jTZOtutw450d0tSejCpMbRT3rD2ajosfes3kdhE0DVJLrLW0cInBYW5/8tGykXzX
b5j87OGETQKBgBCmyjdk8Hvbk1AI0ARthrN8KXYzyIb9W9e/p++VWb5CL1gQ99J0
hZrycNVYYqfEMo8VIv0EB3VMyAGZcx26lzHm5kT49TVy5j3hFtjRXLF4g+EP2pfK
iJybBzsRHPAlgxxwZgyqaNLo5EuB7jRia/bzkEwe0uolCcagLC18Bt1hAoGAXb/e
QgrVsINFJozuniHbpMss0eNWtLsD5bVZvinKgNvz6o35tgziq2zI3pkkgA+kzdm1
i+Et3/VJxtD5xVxkMBrwcQYDprI3h8yylWhLCL6vEOIfL8OiELyNBwFD6+Uc4LdY
ojkAi7k5KrQMCdxXGMjn6ox1SdB1PUW+yqRnte0CgYB/QZbQFNh4QNwvu8iEX+Hf
DPWNXHRThsvznuZTQdg6mmI3uNb7rdS5RF0raw8S8cmtTtFsJ9xjhlZAyC1fwpO6
Xh472j/rkZiJrHbqPzzl3oyUCwCtTVrjBp/fuHa9HMbJQHAhUIEtzAKT0mg5mylY
1BG8h/cStiof/9746AZMIw==
-----END PRIVATE KEY-----
`

var testRSAPublicKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoFEz19zjN1fwLplozRIF
z+f7PdaAQOG5a1kO496NTqLNvvkbDDAIJG3jAAFA/pPkXA5wRzImDuUvMmnurv4I
FZJfvlTEHadBbgpQjgCgSnqUXIYa1U4ELeBfEHFVBV0lUITbZ9kBGjJ92I3qIFr3
PQkysS6/YfJlpBJ0CrC3PlUGfqjtnEQ1pJc9+oZNmIiyw2CrMOdZqiijbN8Zuc2j
qPBl3oW9CJaacv+NZUuoBuOROsmH6/mVAAYFa2RXioOKt214hPH0oFsEzj9CLDqw
qdbVaBpMU4h9OpG1PtP5DIkbNL8vTKfjDHKobvDTY351JZctUTWp3VwovAWadCjn
JQIDAQAB
-----END PUBLIC KEY-----
`

var testED25519PrivateKey = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIL0sK/kwzKr3mdeGnWgN/rtX4UKYgK90oA8DNL9ebBME
-----END PRIVATE KEY-----
`

var testED25519PublicKey = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAZdKSZdQcxdjw4oB9CfnK6RveEgcSFwr+5q2g5WfsDFU=
-----END PUBLIC KEY-----
`

type testKey struct {
	RSAPrivateKey          *rsa.PrivateKey
	RSAPublicKeyBase64     string
	ED25519PrivateKey      ed25519.PrivateKey
	ED25519PublicKeyBase64 string
}

func (k *testKey) getPrivateKey(keyType string) crypto.Signer {
	switch keyType {
	case "rsa":
		return k.RSAPrivateKey
	case "ed25519":
		return k.ED25519PrivateKey
	default:
		return nil
	}
}

func (k *testKey) getPublicKeyBase64(keyType string) string {
	switch keyType {
	case "rsa":
		return k.RSAPublicKeyBase64
	case "ed25519":
		return k.ED25519PublicKeyBase64
	default:
		return ""
	}
}

var testKeys = testKey{}

func TestMain(m *testing.M) {
	// RSA
	block, _ := pem.Decode([]byte(testRSAPrivateKey))
	if block == nil {
		log.Fatal("failed to decode RSA private key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse RSA private key: %v", err)
	}
	testKeys.RSAPrivateKey = priv.(*rsa.PrivateKey)
	block, _ = pem.Decode([]byte(testRSAPublicKey))
	if block == nil {
		log.Fatal("failed to decode RSA public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse RSA public key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatalf("failed to marshal RSA public key: %v", err)
	}
	testKeys.RSAPublicKeyBase64 = base64.StdEncoding.EncodeToString(der)

	// ed25519
	block, _ = pem.Decode([]byte(testED25519PrivateKey))
	if block == nil {
		log.Fatal("failed to decode ed25519 private key")
	}
	priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse ed25519 private key: %v", err)
	}
	testKeys.ED25519PrivateKey = priv.(ed25519.PrivateKey)
	block, _ = pem.Decode([]byte(testED25519PublicKey))
	if block == nil {
		log.Fatal("failed to decode ed25519 public key")
	}
	pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse ed25519 public key: %v", err)
	}
	der, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatalf("failed to marshal ed25519 public key: %v", err)
	}
	testKeys.ED25519PublicKeyBase64 = base64.StdEncoding.EncodeToString(der)

	os.Exit(m.Run())
}

func Test_hashAlgo(t *testing.T) {
	testCases := []struct {
		name   string
		input  SignatureAlgorithm
		expect crypto.Hash
	}{
		{
			name:   "rsa-sha1",
			input:  SignatureAlgorithmRSA_SHA1,
			expect: crypto.SHA1,
		},
		{
			name:   "rsa-sha256",
			input:  SignatureAlgorithmRSA_SHA256,
			expect: crypto.SHA256,
		},
		{
			name:   "ed25519-sha256",
			input:  SignatureAlgorithmED25519_SHA256,
			expect: crypto.SHA256,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := hashAlgo(tc.input)
			if got != tc.expect {
				t.Errorf("unexpected result: got=%s, expect=%s", got, tc.expect)
			}
		})
	}
}
