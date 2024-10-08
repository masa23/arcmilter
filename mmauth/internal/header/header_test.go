package header

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"reflect"
	"testing"

	"github.com/masa23/arcmilter/mmauth/internal/canonical"
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

var testED25519PrivateKey = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIL0sK/kwzKr3mdeGnWgN/rtX4UKYgK90oA8DNL9ebBME
-----END PRIVATE KEY-----
`

type testKey struct {
	RSAPrivateKey     *rsa.PrivateKey
	ED25519PrivateKey ed25519.PrivateKey
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

var testKeys = testKey{}

func TestMain(m *testing.M) {
	// RSA
	block, _ := pem.Decode([]byte(testRSAPrivateKey))
	if block == nil {
		log.Fatalf("failed to decode RSA private key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse RSA private key: %s", err)
	}
	testKeys.RSAPrivateKey = priv.(*rsa.PrivateKey)
	// ED25519
	block, _ = pem.Decode([]byte(testED25519PrivateKey))
	if block == nil {
		log.Fatalf("failed to decode ED25519 private key")
	}
	priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse ED25519 private key: %s", err)
	}
	testKeys.ED25519PrivateKey = priv.(ed25519.PrivateKey)

	os.Exit(m.Run())
}

func TestSigner(t *testing.T) {
	cases := []struct {
		name    string
		keyType string
		headers []string
		canon   canonical.Canonicalization
		want    string
		wantErr error
	}{
		{
			name:    "relaxed rsa",
			keyType: "rsa",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=selector; t=1706971004; v=1; b=",
			},
			canon: canonical.Relaxed,
			want: "kd8wPYuBn0/CA5IJccxBQx/0Hn4dHUR5t/l7yITnT9WZxxyulqecojaRQB33CsohPe8g05AImS6VBHWO83Oho7YnW19k8jel/nnXe5khlQ7Y/D2OdS/AlpZ2ad8yFSYBda1rWAoTKdMNTWm5mTnsr5jcY8U" +
				"1JMaKWByXCcuh0d5YcXtEPmX+Hlwz/qUykrRPB3mAceuR3UNMvqQ0Q5ttKuJDYRJCO6TD/y/JI7yMEMhKGwc/9alrqh/qYzzhcJQkomNSSWcU6Ji65f67JVZKeqe8ROK5BLNDljzDQpc0Qk2xcbjugQAkLpdsJjPaAqfMNPPdKuTcDjFMjUpnyfuQYA==",
			wantErr: nil,
		},
		{
			name:    "simple rsa",
			keyType: "rsa",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=simple/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=selector; t=1706971004; v=1; b=",
			},
			canon: canonical.Simple,
			want: "bb3TE6yxGwxxEsxHSKv1FWMMx+YBk+XGnUlz9Wn4NeJemIXFvPA6J+/Fx1ux2buQyuxv16sqDC233ZwZFLSaQk/KMVTGOegqJCC2pQkNu1dR7pEVN2ZXDXD53SnDj0TyDPGiICeSmzj7q4K4NxSHq0183u" +
				"zoeD+KY6O5vSDhreH7U95AU3o7qh9vbVjwQ8f8AUW9m7YcN+fcPx4y8O3l7I+Aoc8X1DHAqQCtKgA9//sP6GSdU7OZz8sI7DwhuWIy46um1Pd+hAcCQfp2OnBiQslIXu9NuK3C+YonynNBZ24wAsVujoPAy+x8IerPzt5IJgTfyF35f4+KqjLBCvdj+Q==",
			wantErr: nil,
		},
		{
			name:    "relaxed ed25519",
			keyType: "ed25519",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com;\n\ts=selector; t=1728300596;\n\tbh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=;\n\th=Date:From:To:Subject;\n\tb=",
			},
			canon:   canonical.Relaxed,
			want:    "sbFgoCyENUFzV79FuAw2UiG14GTYLOvDeQS9Wv7NY4jfIPYdQRm9Kn/BiyW2W9Ikrwf6AUZkf2UKLJmAUoP4DQ==",
			wantErr: nil,
		},
		{
			name:    "simple ed25519",
			keyType: "ed25519",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"DKIM-Signature: v=1; a=ed25519-sha256; c=simple/simple; d=example.com;\n\ts=selector; t=1728300288;\n\tbh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=;\n\th=Date:From:To:Subject;\n\tb=",
			},
			canon:   canonical.Relaxed,
			want:    "bvm5NplaBo4igE699kkI3OTefoo334DeLirTSNcjh6Grxw7sv9+xh+J08eATT5IoH/+c7sastMm19aM4Tt/iAw==",
			wantErr: nil,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Signer(tt.headers, testKeys.getPrivateKey(tt.keyType), tt.canon)
			if err != tt.wantErr {
				t.Errorf("headerSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("headerSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHeaderParams(t *testing.T) {
	testCases := []struct {
		name   string
		input  string
		expect map[string]string
	}{
		{
			name:  "normal",
			input: "a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.jp; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1; b=vDvbBykNqmtMvcBwipmsEi1+Yh6+n9xOnML4JTAEVkSao99XlwM5OGmglQyaRqKOCR2aDbxTggLYiFS3WGy6KLEo/GWurkqEfvN1HBcjJrKvGFt+hXS98lGOh9C2RTc3VWjYS8ctgZJrd7ZXUK/3rqdlu7EJAo5oIc0npphAUooFqsxgpWfSJ0w8gOFcChOtm1e/PJTyPCQJ3BbPRRtvp4vDfg9R5LBUlNTrA84fccFucQPYNuyzpXgB5kshA5HSSy23rmFtCosOxBjF8rCIz3fVAogKxbHqlAdPazw98eyCeRMVJqxoG1OH3ywYGW2fmEQqloKikD20p0UcaWB0yw==",
			expect: map[string]string{
				"a":  "rsa-sha256",
				"bh": "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				"c":  "relaxed/relaxed",
				"d":  "example.jp",
				"h":  "Date:From:To:Subject:Message-Id",
				"s":  "rs20240124",
				"t":  "1706971004",
				"v":  "1",
				"b":  "vDvbBykNqmtMvcBwipmsEi1+Yh6+n9xOnML4JTAEVkSao99XlwM5OGmglQyaRqKOCR2aDbxTggLYiFS3WGy6KLEo/GWurkqEfvN1HBcjJrKvGFt+hXS98lGOh9C2RTc3VWjYS8ctgZJrd7ZXUK/3rqdlu7EJAo5oIc0npphAUooFqsxgpWfSJ0w8gOFcChOtm1e/PJTyPCQJ3BbPRRtvp4vDfg9R5LBUlNTrA84fccFucQPYNuyzpXgB5kshA5HSSy23rmFtCosOxBjF8rCIz3fVAogKxbHqlAdPazw98eyCeRMVJqxoG1OH3ywYGW2fmEQqloKikD20p0UcaWB0yw==",
			},
		},
		{
			name:   "empty",
			input:  "",
			expect: map[string]string{},
		},
		{
			name:  "no-value",
			input: "a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.jp; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1; b=",
			expect: map[string]string{
				"a":  "rsa-sha256",
				"bh": "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				"c":  "relaxed/relaxed",
				"d":  "example.jp",
				"h":  "Date:From:To:Subject:Message-Id",
				"s":  "rs20240124",
				"t":  "1706971004",
				"v":  "1",
				"b":  "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseHeaderParams(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.expect) {
				t.Errorf("unexpected result: got=%v, expect=%v", got, tc.expect)
			}
		})
	}
}

func TestDeleteSignature(t *testing.T) {
	testCases := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "test1",
			input:  "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1; b=signature!!",
			expect: "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1; b=",
		},
		{
			name:   "test2",
			input:  "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; b=signature!!!; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1",
			expect: "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; b=; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1",
		},
		{
			name:   "test3",
			input:  "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; b=sig\r\n\tnatu\r\n re!!!; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1",
			expect: "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; b=; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1",
		},
		{
			name:   "test4",
			input:  "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1\r\nEvx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; b=sig\r\n\tnatu\r\n re!!!; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1\r\n",
			expect: "DKIM-Signature: a=rsa-sha256; bh=XgF6uYzcgcROQtd83d1\r\nEvx8x2uW+SniFx69skZp5azo=; c=relaxed/relaxed; d=example.com; b=; h=Date:From:To:Subject:Message-Id; s=rs20240124; t=1706971004; v=1\r\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeleteSignature(tc.input)
			if got != tc.expect {
				t.Errorf("unexpected result: got=%s, expect=%s", got, tc.expect)
			}
		})
	}
}

func TestExtractHeadersDKIM(t *testing.T) {
	testCases := []struct {
		name    string
		list    []string
		headers []string
		expect  []string
	}{
		{
			name: "test1",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
			},
		},
		{
			name: "test2",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"Hoge: hoge\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
				"Hoge: hoge\r\n",
			},
		},
		{
			name: "test3",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"Hoge: hoge1\r\n",
				"Hoge: hoge2\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
				"Hoge: hoge2\r\n",
				"Hoge: hoge1\r\n",
			},
		},
		{
			name: "test4",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Hoge: hoge1\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"Hoge: hoge2\r\n",
			},
			expect: []string{"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Hoge: hoge2\r\n",
				"Hoge: hoge1\r\n",
				"Subject: test\r\n",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractHeadersDKIM(tc.headers, tc.list)
			if !reflect.DeepEqual(got, tc.expect) {
				t.Errorf("unexpected result: got=%v, expect=%v", got, tc.expect)
			}
		})
	}
}

func TestExtractHeadersARC(t *testing.T) {
	testCases := []struct {
		name    string
		list    []string
		headers []string
		expect  []string
	}{
		{
			name: "test1",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
			},
		},
		{
			name: "test2",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"Hoge: hoge\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
				"Hoge: hoge\r\n",
			},
		},
		{
			name: "test3",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"Hoge: hoge1\r\n",
				"Hoge: hoge2\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
				"Hoge: hoge2\r\n",
			},
		},
		{
			name: "test4",
			list: []string{"Date", "Subject", "Hoge"},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Hoge: hoge1\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
				"Hoge: hoge2\r\n",
			},
			expect: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"Subject: test\r\n",
				"Hoge: hoge2\r\n",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractHeadersARC(tc.headers, tc.list)
			if !reflect.DeepEqual(got, tc.expect) {
				t.Errorf("unexpected result: got=%v, expect=%v", got, tc.expect)
			}
		})
	}
}
func TestRemoveDuplicates(t *testing.T) {
	testCases := []struct {
		input  []string
		expect []string
	}{
		{
			input:  []string{"a", "b", "c", "d", "e"},
			expect: []string{"a", "b", "c", "d", "e"},
		},
		{
			input:  []string{"a", "b", "c", "d", "e", "a", "b", "c", "d", "e"},
			expect: []string{"a", "b", "c", "d", "e"},
		},
		{
			input:  []string{"a", "b", "b", "c", "d", "e", "e"},
			expect: []string{"a", "b", "c", "d", "e"},
		},
	}

	for _, tc := range testCases {
		got := RemoveDuplicates(tc.input)
		if !reflect.DeepEqual(got, tc.expect) {
			t.Errorf("unexpected result: got=%v, expect=%v", got, tc.expect)
		}
	}
}

func TestParseAddress(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedDomain string
	}{
		{
			name:           "Valid input",
			input:          "John Doe <john.doe@example.com>",
			expectedDomain: "john.doe@example.com",
		},
		{
			name:           "Valid input with multibyte username",
			input:          "John Doe <テスト@example.com>",
			expectedDomain: "テスト@example.com",
		},
		{
			name:           "Vaild input with ISO-2022-JP",
			input:          "=?ISO-2022-JP?B?GyRCRnxLXDhsJDUkTxsoQg==?= <test@example.jp>",
			expectedDomain: "test@example.jp",
		},
		{
			name:           "Valid input with simple address",
			input:          "test@example.net",
			expectedDomain: "test@example.net",
		},
		{
			name:           "Valid input with simple address",
			input:          "<test@example.net>",
			expectedDomain: "test@example.net",
		},
		{
			name:           "Invalid input with duble quote address",
			input:          "\"John Doe\" <john.doe@example.com>",
			expectedDomain: "john.doe@example.com",
		},
		{
			name:           "Invalid input with duble quote address",
			input:          "\"John<aaa@aa.com>Doe\" <john.doe@example.com>",
			expectedDomain: "john.doe@example.com",
		},
		{
			name:           "Invalid input with duble quote address",
			input:          "hoge <\"ho ge\"@example.com>",
			expectedDomain: "\"ho ge\"@example.com",
		},
		{
			name:           "Invalid input with duble quote address and atmark",
			input:          "John Doe <\"john.doe@aa\"@example.com>",
			expectedDomain: "\"john.doe@aa\"@example.com",
		},
		{
			name:           "Valid input if the string is empty",
			input:          "",
			expectedDomain: "",
		},
		{
			name:           "Valid input if the string is empty2",
			input:          "Maria <>",
			expectedDomain: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			domain := ParseAddress(tc.input)

			if domain != tc.expectedDomain {
				t.Errorf("Expected domain: %s, but got: %s", tc.expectedDomain, domain)
			}
		})
	}
}

func TestParseAddressDomain(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedDomain string
		expectedErr    error
	}{
		{
			name:           "Valid input",
			input:          "John Doe <john.doe@example.com>",
			expectedDomain: "example.com",
			expectedErr:    nil,
		},
		{
			name:           "Valid input with multibyte username",
			input:          "John Doe <テスト@example.com>",
			expectedDomain: "example.com",
			expectedErr:    nil,
		},
		{
			name:           "Vaild input with ISO-2022-JP",
			input:          "=?ISO-2022-JP?B?GyRCRnxLXDhsJDUkTxsoQg==?= <test@example.jp>",
			expectedDomain: "example.jp",
		},
		{
			name:           "Valid input with simple address",
			input:          "test@example.net",
			expectedDomain: "example.net",
		},
		{
			name:           "Valid input with simple address",
			input:          "<test@example.net>",
			expectedDomain: "example.net",
		},
		{
			name:           "Valid input with simple address space",
			input:          "test@example.net",
			expectedDomain: "example.net",
		},
		{
			name:           "Invalid input with duble quote address",
			input:          "\"John Doe\" <john.doe@example.com>",
			expectedDomain: "example.com",
		},
		{
			name:           "Invalid input with duble quote address",
			input:          "\"John<aaa@aa.com>Doe\" <john.doe@example.com>",
			expectedDomain: "example.com",
		},
		{
			name:           "Invalid input with duble quote address",
			input:          "hoge <\"ho ge\"@example.com>",
			expectedDomain: "example.com",
		},
		{
			name:           "Invalid input with duble quote address and atmark",
			input:          "John Doe <\"john.doe@aa\"@example.com>",
			expectedDomain: "example.com",
		},
		{
			name:           "Valid input if the string is empty",
			input:          "",
			expectedDomain: "",
			expectedErr:    ErrInvalidEmailFormat,
		},
		{
			name:           "Valid input if the string is empty2",
			input:          "Maria <>",
			expectedDomain: "",
			expectedErr:    ErrInvalidEmailFormat,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			domain, err := ParseAddressDomain(tc.input)

			if domain != tc.expectedDomain {
				t.Errorf("Expected domain: %s, but got: %s", tc.expectedDomain, domain)
			}

			if (tc.expectedErr == nil && err != nil) || (tc.expectedErr != nil && err == nil) || (tc.expectedErr != nil && err != nil && tc.expectedErr.Error() != err.Error()) {
				t.Errorf("Expected error: %v, but got: %v", tc.expectedErr, err)
			}
		})
	}
}
