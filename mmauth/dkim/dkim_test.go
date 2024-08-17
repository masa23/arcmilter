package dkim

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/masa23/arcmilter/mmauth/domainkey"
	"github.com/masa23/arcmilter/mmauth/internal/header"
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

func TestParseDKIMSignature(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		expected  *Signature
		expectErr bool
	}{
		{
			name:  "valid1",
			input: "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector; t=1609459200; c=relaxed/relaxed; bh=base64hash; i=hoge@example.com; h=from:to:subject; b=base64signature",
			expected: &Signature{
				Version:          1,
				Algorithm:        SignatureAlgorithmRSA_SHA256,
				Signature:        "base64signature",
				BodyHash:         "base64hash",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.com",
				Headers:          "from:to:subject",
				Identity:         "hoge@example.com",
				Selector:         "selector",
				Timestamp:        1609459200,
				raw:              "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector; t=1609459200; c=relaxed/relaxed; bh=base64hash; i=hoge@example.com; h=from:to:subject; b=base64signature",
				canonnAndAlog: &CanonicalizationAndAlgorithm{
					Header:    CanonicalizationRelaxed,
					Body:      CanonicalizationRelaxed,
					Algorithm: SignatureAlgorithmRSA_SHA256,
					HashAlgo:  crypto.SHA256,
				},
			},
		},
		{
			name: "valid2",
			input: "DKIM-Signature: v=1; a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=selector; t=1706971004; v=1; " +
				"b=kd8wPYuBn0/CA5IJccxBQx/0Hn4dHUR5t/l7yITnT9WZxxyulqecojaRQB33CsohPe8g05AImS6VBHWO83Oho7YnW19k8jel/nnXe5khlQ7Y/D2OdS/AlpZ2ad8yFSYBda1rWAoTKdMNTWm5mTnsr5jcY8U1JMaKWByXCcuh0" +
				"d5YcXtEPmX+Hlwz/qUykrRPB3mAceuR3UNMvqQ0Q5ttKuJDYRJCO6TD/y/JI7yMEMhKGwc/9alrqh/qYzzhcJQkomNSSWcU6Ji65f67JVZKeqe8ROK5BLNDljzDQpc0Qk2xcbjugQAkLpdsJjPaAqfMNPPdKuTcDjFMjUpnyfuQYA=",
			expected: &Signature{
				Version:   1,
				Algorithm: SignatureAlgorithmRSA_SHA256,
				Signature: "kd8wPYuBn0/CA5IJccxBQx/0Hn4dHUR5t/l7yITnT9WZxxyulqecojaRQB33CsohPe8g05AImS6VBHWO83Oho7YnW19k8jel/nnXe5khlQ7Y/D2OdS/AlpZ2ad8yFSYBda1rWAoTKdMNTWm5mTnsr5jcY8U" +
					"1JMaKWByXCcuh0d5YcXtEPmX+Hlwz/qUykrRPB3mAceuR3UNMvqQ0Q5ttKuJDYRJCO6TD/y/JI7yMEMhKGwc/9alrqh/qYzzhcJQkomNSSWcU6Ji65f67JVZKeqe8ROK5BLNDljzDQpc0Qk2xcbjugQAkLpdsJjPaAqfMNPPdKuTcDjFMjUpnyfuQYA=",
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject:Message-Id",
				Selector:         "selector",
				Timestamp:        1706971004,
				raw: "DKIM-Signature: v=1; a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=selector; t=1706971004; v=1; " +
					"b=kd8wPYuBn0/CA5IJccxBQx/0Hn4dHUR5t/l7yITnT9WZxxyulqecojaRQB33CsohPe8g05AImS6VBHWO83Oho7YnW19k8jel/nnXe5khlQ7Y/D2OdS/AlpZ2ad8yFSYBda1rWAoTKdMNTWm5mTnsr5jcY8U1JMaKWByXCcuh0" +
					"d5YcXtEPmX+Hlwz/qUykrRPB3mAceuR3UNMvqQ0Q5ttKuJDYRJCO6TD/y/JI7yMEMhKGwc/9alrqh/qYzzhcJQkomNSSWcU6Ji65f67JVZKeqe8ROK5BLNDljzDQpc0Qk2xcbjugQAkLpdsJjPaAqfMNPPdKuTcDjFMjUpnyfuQYA=",
				canonnAndAlog: &CanonicalizationAndAlgorithm{
					Header:    CanonicalizationRelaxed,
					Body:      CanonicalizationRelaxed,
					Algorithm: SignatureAlgorithmRSA_SHA256,
					Limit:     0,
					HashAlgo:  crypto.SHA256,
				},
			},
		},
		{
			name: "valid3",
			input: "DKIM-Signature: v=1; a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; l=100; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=selector; t=1706971004; v=1; " +
				"b=kd8wPYuBn0/CA5IJccxBQx/0Hn4dHUR5t/l7yITnT9WZxxyulqecojaRQB33CsohPe8g05AImS6VBHWO83Oho7YnW19k8jel/nnXe5khlQ7Y/D2OdS/AlpZ2ad8yFSYBda1rWAoTKdMNTWm5mTnsr5jcY8U1JMaKWByXCcuh0" +
				"d5YcXtEPmX+Hlwz/qUykrRPB3mAceuR3UNMvqQ0Q5ttKuJDYRJCO6TD/y/JI7yMEMhKGwc/9alrqh/qYzzhcJQkomNSSWcU6Ji65f67JVZKeqe8ROK5BLNDljzDQpc0Qk2xcbjugQAkLpdsJjPaAqfMNPPdKuTcDjFMjUpnyfuQYA=",
			expected: &Signature{
				Version:   1,
				Algorithm: SignatureAlgorithmRSA_SHA256,
				Signature: "kd8wPYuBn0/CA5IJccxBQx/0Hn4dHUR5t/l7yITnT9WZxxyulqecojaRQB33CsohPe8g05AImS6VBHWO83Oho7YnW19k8jel/nnXe5khlQ7Y/D2OdS/AlpZ2ad8yFSYBda1rWAoTKdMNTWm5mTnsr5jcY8U" +
					"1JMaKWByXCcuh0d5YcXtEPmX+Hlwz/qUykrRPB3mAceuR3UNMvqQ0Q5ttKuJDYRJCO6TD/y/JI7yMEMhKGwc/9alrqh/qYzzhcJQkomNSSWcU6Ji65f67JVZKeqe8ROK5BLNDljzDQpc0Qk2xcbjugQAkLpdsJjPaAqfMNPPdKuTcDjFMjUpnyfuQYA=",
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject:Message-Id",
				Selector:         "selector",
				Timestamp:        1706971004,
				raw: "DKIM-Signature: v=1; a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; l=100; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=selector; t=1706971004; v=1; " +
					"b=kd8wPYuBn0/CA5IJccxBQx/0Hn4dHUR5t/l7yITnT9WZxxyulqecojaRQB33CsohPe8g05AImS6VBHWO83Oho7YnW19k8jel/nnXe5khlQ7Y/D2OdS/AlpZ2ad8yFSYBda1rWAoTKdMNTWm5mTnsr5jcY8U1JMaKWByXCcuh0" +
					"d5YcXtEPmX+Hlwz/qUykrRPB3mAceuR3UNMvqQ0Q5ttKuJDYRJCO6TD/y/JI7yMEMhKGwc/9alrqh/qYzzhcJQkomNSSWcU6Ji65f67JVZKeqe8ROK5BLNDljzDQpc0Qk2xcbjugQAkLpdsJjPaAqfMNPPdKuTcDjFMjUpnyfuQYA=",
				canonnAndAlog: &CanonicalizationAndAlgorithm{
					Header:    CanonicalizationRelaxed,
					Body:      CanonicalizationRelaxed,
					Algorithm: SignatureAlgorithmRSA_SHA256,
					Limit:     100,
					HashAlgo:  crypto.SHA256,
				},
			},
		},
		{
			name: "invalid limit1",
			input: "DKIM-Signature: v=1; a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; l=hoge; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=selector; t=1706971004; v=1; " +
				"b=kd8wPYuBn0/CA5IJccxBQx/0Hn4dHUR5t/l7yITnT9WZxxyulqecojaRQB33CsohPe8g05AImS6VBHWO83Oho7YnW19k8jel/nnXe5khlQ7Y/D2OdS/AlpZ2ad8yFSYBda1rWAoTKdMNTWm5mTnsr5jcY8U1JMaKWByXCcuh0" +
				"d5YcXtEPmX+Hlwz/qUykrRPB3mAceuR3UNMvqQ0Q5ttKuJDYRJCO6TD/y/JI7yMEMhKGwc/9alrqh/qYzzhcJQkomNSSWcU6Ji65f67JVZKeqe8ROK5BLNDljzDQpc0Qk2xcbjugQAkLpdsJjPaAqfMNPPdKuTcDjFMjUpnyfuQYA=",
			expectErr: true,
		},
		{
			name: "invalid limit2",
			input: "DKIM-Signature: v=1; a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; l=-1; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=selector; t=1706971004; v=1; " +
				"b=kd8wPYuBn0/CA5IJccxBQx/0Hn4dHUR5t/l7yITnT9WZxxyulqecojaRQB33CsohPe8g05AImS6VBHWO83Oho7YnW19k8jel/nnXe5khlQ7Y/D2OdS/AlpZ2ad8yFSYBda1rWAoTKdMNTWm5mTnsr5jcY8U1JMaKWByXCcuh0" +
				"d5YcXtEPmX+Hlwz/qUykrRPB3mAceuR3UNMvqQ0Q5ttKuJDYRJCO6TD/y/JI7yMEMhKGwc/9alrqh/qYzzhcJQkomNSSWcU6Ji65f67JVZKeqe8ROK5BLNDljzDQpc0Qk2xcbjugQAkLpdsJjPaAqfMNPPdKuTcDjFMjUpnyfuQYA=",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := ParseSignature(tc.input)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if actual.Version != tc.expected.Version {
				t.Errorf("want %v, but got %v", tc.expected.Version, actual.Version)
			}
			if actual.Algorithm != tc.expected.Algorithm {
				t.Errorf("want %v, but got %v", tc.expected.Algorithm, actual.Algorithm)
			}
			if actual.Signature != tc.expected.Signature {
				t.Errorf("want %v, but got %v", tc.expected.Signature, actual.Signature)
			}
			if actual.BodyHash != tc.expected.BodyHash {
				t.Errorf("want %v, but got %v", tc.expected.BodyHash, actual.BodyHash)
			}
			if actual.Canonicalization != tc.expected.Canonicalization {
				t.Errorf("want %v, but got %v", tc.expected.Canonicalization, actual.Canonicalization)
			}
			if actual.Domain != tc.expected.Domain {
				t.Errorf("want %v, but got %v", tc.expected.Domain, actual.Domain)
			}
			if actual.Headers != tc.expected.Headers {
				t.Errorf("want %v, but got %v", tc.expected.Headers, actual.Headers)
			}
			if actual.Selector != tc.expected.Selector {
				t.Errorf("want %v, but got %v", tc.expected.Selector, actual.Selector)
			}
			if actual.Timestamp != tc.expected.Timestamp {
				t.Errorf("want %v, but got %v", tc.expected.Timestamp, actual.Timestamp)
			}
			if actual.raw != tc.expected.raw {
				t.Errorf("want %v, but got %v", tc.expected.raw, actual.raw)
			}
			if actual.canonnAndAlog.Header != tc.expected.canonnAndAlog.Header {
				t.Errorf("want %v, but got %v", tc.expected.canonnAndAlog.Header, actual.canonnAndAlog.Header)
			}
			if actual.canonnAndAlog.Body != tc.expected.canonnAndAlog.Body {
				t.Errorf("want %v, but got %v", tc.expected.canonnAndAlog.Body, actual.canonnAndAlog.Body)
			}
			if actual.canonnAndAlog.Algorithm != tc.expected.canonnAndAlog.Algorithm {
				t.Errorf("want %v, but got %v", tc.expected.canonnAndAlog.Algorithm, actual.canonnAndAlog.Algorithm)
			}
			if actual.canonnAndAlog.Limit != tc.expected.canonnAndAlog.Limit {
				t.Errorf("want %v, but got %v", tc.expected.canonnAndAlog.Limit, actual.canonnAndAlog.Limit)
			}
			if actual.canonnAndAlog.HashAlgo != tc.expected.canonnAndAlog.HashAlgo {
				t.Errorf("want %v, but got %v", tc.expected.canonnAndAlog.HashAlgo, actual.canonnAndAlog.HashAlgo)
			}
		})
	}
}

func TestSign(t *testing.T) {
	block, _ := pem.Decode([]byte(testRSAPrivateKey))
	if block == nil {
		t.Fatal("failed to decode pem")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse pkcs8 private key: %s", err)
	}
	privateKey := priv.(*rsa.PrivateKey)

	testCase := []struct {
		name     string
		input    *Signature
		headers  []string
		expected string
	}{
		{
			name: "valid",
			expected: "kd8wPYuBn0/CA5IJccxBQx/0Hn4dHUR5t/l7yITnT9WZxxyulqecojaRQB33CsohPe8g05AImS6VBHWO83Oho7YnW19k8jel/nnXe5khlQ7Y/D2OdS/AlpZ2ad8yFSYBda1rWAoTKdMNTWm5mTnsr5jcY8U" +
				"1JMaKWByXCcuh0d5YcXtEPmX+Hlwz/qUykrRPB3mAceuR3UNMvqQ0Q5ttKuJDYRJCO6TD/y/JI7yMEMhKGwc/9alrqh/qYzzhcJQkomNSSWcU6Ji65f67JVZKeqe8ROK5BLNDljzDQpc0Qk2xcbjugQAkLpdsJjPaAqfMNPPdKuTcDjFMjUpnyfuQYA==",
			input: &Signature{
				Version:          1,
				Algorithm:        SignatureAlgorithmRSA_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject:Message-Id",
				Selector:         "selector",
				Timestamp:        1706971004,
			},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
			},
		},
	}

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.Sign(tc.headers, privateKey)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.input.Signature != tc.expected {
				t.Errorf("want %v, but got %v", tc.expected, tc.input.Signature)
			}
		})
	}

}

func TestVerify(t *testing.T) {
	block, _ := pem.Decode([]byte(testRSAPublicKey))
	if block == nil {
		t.Fatal("failed to decode pem")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse pkix public key: %s", err)
	}
	publicKey := pub.(*rsa.PublicKey)
	//derに変換
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("failed to marshal pkix public key: %s", err)
	}

	publicKeyB64 := base64.StdEncoding.EncodeToString(der)

	testCase := []struct {
		name      string
		bodyHash  string
		input     *Signature
		headers   []string
		domainKey domainkey.DomainKey
	}{
		{
			name:     "valid",
			bodyHash: "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
			input: &Signature{
				Version:   1,
				Algorithm: SignatureAlgorithmRSA_SHA256,
				Signature: "kd8wPYuBn0/CA5IJccxBQx/0Hn4dHUR5t/l7yITnT9WZxxyulqecojaRQB33CsohPe8g05AImS6VBHWO83Oho7YnW19k8jel/nnXe5khlQ7Y/D2OdS/AlpZ2ad8yFSYBda1rWAoTKdMNTWm5mTnsr5jcY8U" +
					"1JMaKWByXCcuh0d5YcXtEPmX+Hlwz/qUykrRPB3mAceuR3UNMvqQ0Q5ttKuJDYRJCO6TD/y/JI7yMEMhKGwc/9alrqh/qYzzhcJQkomNSSWcU6Ji65f67JVZKeqe8ROK5BLNDljzDQpc0Qk2xcbjugQAkLpdsJjPaAqfMNPPdKuTcDjFMjUpnyfuQYA==",
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject:Message-Id",
				Selector:         "selector",
				Timestamp:        1706971004,
				raw: "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=selector; t=1706971004; v=1; " +
					"b=kd8wPYuBn0/CA5IJccxBQx/0Hn4dHUR5t/l7yITnT9WZxxyulqecojaRQB33CsohPe8g05AImS6VBHWO83Oho7YnW19k8jel/nnXe5khlQ7Y/D2OdS/AlpZ2ad8yFSYBda1rWAoTKdMNTWm5mTnsr5jcY8U1JMaKWByXCcuh0" +
					"d5YcXtEPmX+Hlwz/qUykrRPB3mAceuR3UNMvqQ0Q5ttKuJDYRJCO6TD/y/JI7yMEMhKGwc/9alrqh/qYzzhcJQkomNSSWcU6Ji65f67JVZKeqe8ROK5BLNDljzDQpc0Qk2xcbjugQAkLpdsJjPaAqfMNPPdKuTcDjFMjUpnyfuQYA=",
				canonnAndAlog: &CanonicalizationAndAlgorithm{
					Algorithm: SignatureAlgorithmRSA_SHA256,
					Header:    CanonicalizationRelaxed,
					Body:      CanonicalizationRelaxed,
					HashAlgo:  crypto.SHA256,
				},
			},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
			},
			domainKey: domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{"rsa-sha256"},
				KeyType:   "rsa",
				PublicKey: publicKeyB64,
			},
		},
	}

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			tc.input.Verify(tc.headers, tc.bodyHash, &tc.domainKey)
			if tc.input.VerifyResult == nil {
				t.Errorf("verifyResult is nil")
			}
			if tc.input.VerifyResult.Error() != nil {
				t.Errorf("unexpected error: %v", tc.input.VerifyResult.Error())
			}
			if tc.input.VerifyResult.Status() != VerifyStatusPass {
				t.Errorf("want %v, but got %v", VerifyStatusPass, tc.input.VerifyResult.Status())
			}

		})
	}

}

func Test_parseHeaderField(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		key   string
		value string
	}{
		{
			name:  "test1",
			input: "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.jp; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1; b=vDvbBykNqmtMvcBwipmsEi1+Yh6+n9xOnML4JTAEVkSao99XlwM5OGmglQyaRqKOCR2aDbxTggLYiFS3WGy6KLEo/GWurkqEfvN1HBcjJrKvGFt+hXS98lGOh9C2RTc3VWjYS8ctgZJrd7ZXUK/3rqdlu7EJAo5oIc0npphAUooFqsxgpWfSJ0w8gOFcChOtm1e/PJTyPCQJ3BbPRRtvp4vDfg9R5LBUlNTrA84fccFucQPYNuyzpXgB5kshA5HSSy23rmFtCosOxBjF8rCIz3fVAogKxbHqlAdPazw98eyCeRMVJqxoG1OH3ywYGW2fmEQqloKikD20p0UcaWB0yw==",
			key:   "DKIM-Signature",
			value: "a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.jp; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1; b=vDvbBykNqmtMvcBwipmsEi1+Yh6+n9xOnML4JTAEVkSao99XlwM5OGmglQyaRqKOCR2aDbxTggLYiFS3WGy6KLEo/GWurkqEfvN1HBcjJrKvGFt+hXS98lGOh9C2RTc3VWjYS8ctgZJrd7ZXUK/3rqdlu7EJAo5oIc0npphAUooFqsxgpWfSJ0w8gOFcChOtm1e/PJTyPCQJ3BbPRRtvp4vDfg9R5LBUlNTrA84fccFucQPYNuyzpXgB5kshA5HSSy23rmFtCosOxBjF8rCIz3fVAogKxbHqlAdPazw98eyCeRMVJqxoG1OH3ywYGW2fmEQqloKikD20p0UcaWB0yw==",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, gotValue := header.ParseHeaderField(tc.input)
			if gotKey != tc.key {
				t.Errorf("unexpected key: got=%s, expect=%s", gotKey, tc.key)
			}
			if gotValue != tc.value {
				t.Errorf("unexpected value: got=%s, expect=%s", gotValue, tc.value)
			}
		})
	}
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
