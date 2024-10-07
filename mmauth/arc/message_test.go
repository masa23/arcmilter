package arc

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/masa23/arcmilter/mmauth/domainkey"
)

func TestARCMessageSignatureParse(t *testing.T) {
	testCase := []struct {
		name     string
		input    string
		expected *ARCMessageSignature
	}{
		{
			name: "simple/simple",
			input: "ARC-Message-Signature: i=1; a=rsa-sha256; c=simple/simple; d=example.com; s=selector;\r\n" +
				"        h=Date:From:To:Subject:Message-Id;\r\n" +
				"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
				"        b=ZeWS0mo8KKL0Y0V2Cbzj4E2R9ZRE92GPnSYUb8xZAB8hhx6sTNgYQjnJIU3pmNEz\r\n" +
				"         kkU9yAQf+lRfy1wxVJxvX4lDwU6Kfbq4vQg7LZOqnoZYRmwpiQvY4SFOL6lzgBOW\r\n" +
				"         WDBRLmhjZFM35FRzCZDledSUC/JMVQjeqA4Go1UzwB9cxh+t1S3TvuatrTsb0z0u\r\n" +
				"         ZvnytXB/u2UXA8+3VmhU4+1PDNYruK07pSzUkV4cnGJ4q5h8M2Y5x+xoVed9Zp06\r\n" +
				"         JbwAkyhvBwa3P6eHZPpr6c5O+nyV5V6buwNuQ4ORl2sJxGE4HmpTaLDCPPVIJbfA\r\n" +
				"         gvyW8Csb55+hxcTILU4ZyQ==\r\n",
			expected: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmRSA_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "simple/simple",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject:Message-Id",
				Selector:         "selector",
				Timestamp:        1706971004,
				Signature: "ZeWS0mo8KKL0Y0V2Cbzj4E2R9ZRE92GPnSYUb8xZAB8hhx6sTNgYQjnJIU3pmNEzkkU9yAQf+lRfy1wx" +
					"VJxvX4lDwU6Kfbq4vQg7LZOqnoZYRmwpiQvY4SFOL6lzgBOWWDBRLmhjZFM35FRzCZDledSUC/JMVQje" +
					"qA4Go1UzwB9cxh+t1S3TvuatrTsb0z0uZvnytXB/u2UXA8+3VmhU4+1PDNYruK07pSzUkV4cnGJ4q5h8" +
					"M2Y5x+xoVed9Zp06JbwAkyhvBwa3P6eHZPpr6c5O+nyV5V6buwNuQ4ORl2sJxGE4HmpTaLDCPPVIJbfA" +
					"gvyW8Csb55+hxcTILU4ZyQ==",
				raw: "ARC-Message-Signature: i=1; a=rsa-sha256; c=simple/simple; d=example.com; s=selector;\r\n" +
					"        h=Date:From:To:Subject:Message-Id;\r\n" +
					"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
					"        b=ZeWS0mo8KKL0Y0V2Cbzj4E2R9ZRE92GPnSYUb8xZAB8hhx6sTNgYQjnJIU3pmNEz\r\n" +
					"         kkU9yAQf+lRfy1wxVJxvX4lDwU6Kfbq4vQg7LZOqnoZYRmwpiQvY4SFOL6lzgBOW\r\n" +
					"         WDBRLmhjZFM35FRzCZDledSUC/JMVQjeqA4Go1UzwB9cxh+t1S3TvuatrTsb0z0u\r\n" +
					"         ZvnytXB/u2UXA8+3VmhU4+1PDNYruK07pSzUkV4cnGJ4q5h8M2Y5x+xoVed9Zp06\r\n" +
					"         JbwAkyhvBwa3P6eHZPpr6c5O+nyV5V6buwNuQ4ORl2sJxGE4HmpTaLDCPPVIJbfA\r\n" +
					"         gvyW8Csb55+hxcTILU4ZyQ==\r\n",
			},
		},
		{
			name: "relaxed/relaxed",
			input: "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
				"        h=Date:From:To:Subject:Message-Id;\r\n" +
				"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
				"        b=MKEt/c7ZOAcIaIHtnT7jvthDLVR9JESqRyLLvFmUFxZPuLJeHstiVcRhWPC1PF1C\r\n" +
				"         TcWLKONKZYFWz3ERlTVcCQ7+hBc+J1z2gtsefglffeqDocEcGDo1cMz3FDwWDV5m\r\n" +
				"         NlNkuZPygJf0kM9JYc6wW/m7mpriEzTkYmxxSUn/2opOGAz8UiU/Tp663vo9jT7L\r\n" +
				"         sKfzuXk+zz83kn/sNs49PTYk1k5unEhvuhjoFgRKBNFzAH465mrr0xnkiIZK2Bzn\r\n" +
				"         jqhKpTah1uXEb0cWCCotj6RJDeEVpr5dlfS4Xsmns2nJ2cxrKbCCU2OXDhu95J60\r\n" +
				"         h9Jh14Pe6+KosrjrF6xqpQ==\r\n",
			expected: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmRSA_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject:Message-Id",
				Selector:         "selector",
				Timestamp:        1706971004,
				Signature: "MKEt/c7ZOAcIaIHtnT7jvthDLVR9JESqRyLLvFmUFxZPuLJeHstiVcRhWPC1PF1CTcWLKONKZYFWz3ER" +
					"lTVcCQ7+hBc+J1z2gtsefglffeqDocEcGDo1cMz3FDwWDV5mNlNkuZPygJf0kM9JYc6wW/m7mpriEzTk" +
					"YmxxSUn/2opOGAz8UiU/Tp663vo9jT7LsKfzuXk+zz83kn/sNs49PTYk1k5unEhvuhjoFgRKBNFzAH46" +
					"5mrr0xnkiIZK2BznjqhKpTah1uXEb0cWCCotj6RJDeEVpr5dlfS4Xsmns2nJ2cxrKbCCU2OXDhu95J60" +
					"h9Jh14Pe6+KosrjrF6xqpQ==",
				raw: "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
					"        h=Date:From:To:Subject:Message-Id;\r\n" +
					"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
					"        b=MKEt/c7ZOAcIaIHtnT7jvthDLVR9JESqRyLLvFmUFxZPuLJeHstiVcRhWPC1PF1C\r\n" +
					"         TcWLKONKZYFWz3ERlTVcCQ7+hBc+J1z2gtsefglffeqDocEcGDo1cMz3FDwWDV5m\r\n" +
					"         NlNkuZPygJf0kM9JYc6wW/m7mpriEzTkYmxxSUn/2opOGAz8UiU/Tp663vo9jT7L\r\n" +
					"         sKfzuXk+zz83kn/sNs49PTYk1k5unEhvuhjoFgRKBNFzAH465mrr0xnkiIZK2Bzn\r\n" +
					"         jqhKpTah1uXEb0cWCCotj6RJDeEVpr5dlfS4Xsmns2nJ2cxrKbCCU2OXDhu95J60\r\n" +
					"         h9Jh14Pe6+KosrjrF6xqpQ==\r\n",
			},
		},
	}

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			ams, err := ParseARCMessageSignature(tc.input)
			if err != nil {
				t.Fatalf("failed to parse: %s", err)
			}
			if ams.InstanceNumber != tc.expected.InstanceNumber {
				t.Errorf("instance number mismatch: got %d, want %d", ams.InstanceNumber, tc.expected.InstanceNumber)
			}
			if ams.Algorithm != tc.expected.Algorithm {
				t.Errorf("algorithm mismatch: got %s, want %s", ams.Algorithm, tc.expected.Algorithm)
			}
			if ams.BodyHash != tc.expected.BodyHash {
				t.Errorf("body hash mismatch: got %s, want %s", ams.BodyHash, tc.expected.BodyHash)
			}
			if ams.Canonicalization != tc.expected.Canonicalization {
				t.Errorf("canonicalization mismatch: got %s, want %s", ams.Canonicalization, tc.expected.Canonicalization)
			}
			if ams.Domain != tc.expected.Domain {
				t.Errorf("domain mismatch: got %s, want %s", ams.Domain, tc.expected.Domain)
			}
			if ams.Headers != tc.expected.Headers {
				t.Errorf("headers mismatch: got %s, want %s", ams.Headers, tc.expected.Headers)
			}
			if ams.Selector != tc.expected.Selector {
				t.Errorf("selector mismatch: got %s, want %s", ams.Selector, tc.expected.Selector)
			}
			if ams.Timestamp != tc.expected.Timestamp {
				t.Errorf("timestamp mismatch: got %d, want %d", ams.Timestamp, tc.expected.Timestamp)
			}
			if ams.Signature != tc.expected.Signature {
				t.Errorf("signature mismatch: got %s, want %s", ams.Signature, tc.expected.Signature)
			}
		})
	}
}

func TestARCMessageSignatureSign(t *testing.T) {
	testCases := []struct {
		name     string
		input    *ARCMessageSignature
		headers  []string
		expected string
	}{
		{
			name: "simple/simple rsa-sha256",
			input: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmRSA_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "simple/simple",
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
			expected: "HaSpZz5xD4PIl6aROJUfsMzToitrqEAWU/LSCZ3S2DpiHpnSIPRcNbN1FeeFtatyDKbJHZL3gxILppCe" +
				"7h34fJGqW5so7D3AnHGI86mtRO+h+X5iHDT0474B2B1hDY1+SFker3+8P4WI5Mz1Njl5nom3TgQSxp03" +
				"GWz0KWN9gFMH1tt7q7w/jfM8RkZ05AXy0xaf04AU/UNqUm88tFKfCHPxpSrsdtA4lPwz5X3Ql/bSfJpE" +
				"8W+WR3WMebyr9i6baJ72mCwqv5SqVZug8Sh3WliPqUJYTV1kYhB6NlZpGmLDsSLLEtnQpz5AIxBBHxTn" +
				"CIROrH3gMTIolx1V+2oKVQ==",
		},
		{
			name: "relaxed/relaxed rsa-sha256",
			input: &ARCMessageSignature{
				InstanceNumber:   1,
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
			expected: "ef198CMzjQC9DkeKZj8IrzvZuEPqV/MBDLYGPpdSiofRdBv6BkrFS8Gb7jH7/oXWBEzZnRVMjpD7dHLp" +
				"NjNjgqSQJI0GbSP/CK80BsVHRUioLWNPuG9aCNg/sOKl70yD3PwmimfOhr1tA18cdDNQv1Q5iAxPLCfY" +
				"2IKzY6FQqw0YBIFqACYC2Nf2ONXha89YUnZURPJSzXXrlZZserEqAt7MFaMzUVmBRHEDG9blwLkm/NhK" +
				"KL9IT/pKc6T9ibbgDlmh7sNjSEOIw7CS5dkp0k3r2zvR6l/fdChJh13fOv1LPwkmGeosXDWBmrdYr9Gx" +
				"vrgEwmI6O74ZZR9jWIuyGg==",
		},
		{
			name: "relaxed/relaxed ed25519-sha256",
			input: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmED25519_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "relaxed/relaxed",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject",
				Selector:         "selector",
				Timestamp:        1728300596,
			},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
			},
			expected: "B8O8oPo2sTAfWlgKfcwdBAq6zLgv9+9zUfwGy9XsjvCA3UxBUpy6VuVzXcCyTrTjvvlarL7sMnQeZvXN92nPDw==",
		},
		{
			name: "simple/simple ed25519-sha256",
			input: &ARCMessageSignature{
				InstanceNumber:   1,
				Algorithm:        SignatureAlgorithmED25519_SHA256,
				BodyHash:         "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
				Canonicalization: "simple/simple",
				Domain:           "example.com",
				Headers:          "Date:From:To:Subject",
				Selector:         "selector",
				Timestamp:        1728300596,
			},
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
			},
			expected: "xcCQDNQSYZW0jnjeAFmshNjmMMe3x3pxVw2fIKjCRkjzJPEexL9SWI6C/RpeeDBf+/vMpqpDxgvnFbHHcHIrBA==",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var privateKey crypto.Signer
			if tc.input.Algorithm == SignatureAlgorithmRSA_SHA256 || tc.input.Algorithm == SignatureAlgorithmRSA_SHA1 {
				privateKey = testKeys.RSAPrivateKey
			} else if tc.input.Algorithm == SignatureAlgorithmED25519_SHA256 {
				privateKey = testKeys.ED25519PrivateKey
			}

			if err := tc.input.Sign(tc.headers, privateKey); err != nil {
				t.Fatalf("failed to sign: %s", err)
			}
			if tc.input.Signature != tc.expected {
				t.Errorf("signature mismatch: got %s, want %s", tc.input.Signature, tc.expected)
			}
		})
	}
}

func TestARCMessageSignatureVerify(t *testing.T) {
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

	testCases := []struct {
		name      string
		bodyhash  string
		header    string
		headers   []string
		domainkey domainkey.DomainKey
	}{
		{
			name:     "simple/simple valid",
			bodyhash: "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
			header: "ARC-Message-Signature: i=1; a=rsa-sha256; c=simple/simple; d=example.com; s=selector;\r\n" +
				"        h=Date:From:To:Subject:Message-Id;\r\n" +
				"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
				"        b=HaSpZz5xD4PIl6aROJUfsMzToitrqEAWU/LSCZ3S2DpiHpnSIPRcNbN1FeeFtaty\r\n" +
				"         DKbJHZL3gxILppCe7h34fJGqW5so7D3AnHGI86mtRO+h+X5iHDT0474B2B1hDY1+\r\n" +
				"         SFker3+8P4WI5Mz1Njl5nom3TgQSxp03GWz0KWN9gFMH1tt7q7w/jfM8RkZ05AXy\r\n" +
				"         0xaf04AU/UNqUm88tFKfCHPxpSrsdtA4lPwz5X3Ql/bSfJpE8W+WR3WMebyr9i6b\r\n" +
				"         aJ72mCwqv5SqVZug8Sh3WliPqUJYTV1kYhB6NlZpGmLDsSLLEtnQpz5AIxBBHxTn\r\n" +
				"         CIROrH3gMTIolx1V+2oKVQ==\r\n",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
			},
			domainkey: domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{"rsa-sha256"},
				KeyType:   "rsa",
				PublicKey: publicKeyB64,
			},
		},
		{
			name:     "relaxed/relaxed valid",
			bodyhash: "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
			header: "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
				"        h=Date:From:To:Subject:Message-Id;\r\n" +
				"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
				"        b=ef198CMzjQC9DkeKZj8IrzvZuEPqV/MBDLYGPpdSiofRdBv6BkrFS8Gb7jH7/oXW\r\n" +
				"         BEzZnRVMjpD7dHLpNjNjgqSQJI0GbSP/CK80BsVHRUioLWNPuG9aCNg/sOKl70yD\r\n" +
				"         3PwmimfOhr1tA18cdDNQv1Q5iAxPLCfY2IKzY6FQqw0YBIFqACYC2Nf2ONXha89Y\r\n" +
				"         UnZURPJSzXXrlZZserEqAt7MFaMzUVmBRHEDG9blwLkm/NhKKL9IT/pKc6T9ibbg\r\n" +
				"         Dlmh7sNjSEOIw7CS5dkp0k3r2zvR6l/fdChJh13fOv1LPwkmGeosXDWBmrdYr9Gx\r\n" +
				"         vrgEwmI6O74ZZR9jWIuyGg==\r\n",
			headers: []string{
				"Date: Sat, 03 Feb 2024 23:36:43 +0900\r\n",
				"From: hogefuga@example.com\r\n",
				"To: aaa@example.org\r\n",
				"Subject: test\r\n",
				"Message-Id: <20240203233642.F020.87DC113@example.com>\r\n",
			},
			domainkey: domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{"rsa-sha256"},
				KeyType:   "rsa",
				PublicKey: publicKeyB64,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ams, err := ParseARCMessageSignature(tc.header)
			if err != nil {
				t.Fatalf("failed to parse arc message signature: %s", err)
			}
			result := ams.Verify(tc.headers, tc.bodyhash, &tc.domainkey)

			if result.Error() != nil {
				t.Errorf("verify failed: %s", result.Error())
			}
		})
	}
}
