package arc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/masa23/arcmilter/mmauth/domainkey"
)

func TestARCSealParse(t *testing.T) {
	testCase := []struct {
		name     string
		input    string
		expected *ARCSeal
	}{
		{
			name: "seal",
			input: "ARC-Seal: i=1; a=rsa-sha256; t=1706971004; cv=none;\r\n" +
				"        d=example.com; s=selector;\r\n" +
				"        b=g+R0nyap1H1wsIqc3AvSesOyicLqq/p5bMP4yJUG/Kqmb8iN42MuYVdjD8xFNiPg\r\n" +
				"         gfmq2Uz/FvYsyq9vx8R9Isxu0eNKyx4tZWMK0kNJkxW/cA+RRPZ1sSXxI2w+ZomV\r\n" +
				"         5OHl0AzFFAUlU41Ngq6mJLKNXVYDrd4SILiYHCC+1B/sylS+7c4tbCTtQbikeVDZ\r\n" +
				"         mTpq+W9lEDGxgtcmZK8UlAjDZ5CfMIef2ukeWWm8atqPRm0NfExmsWYhytVvccgN\r\n" +
				"         IfYCgsji2Cee45epWJXJSD+RJLbhwbLgfMlFSUa4cdW0yNN24OB7rHV1T/tg+boG\r\n" +
				"         y2vkgXJHRmKvadyjGwTW8A==\r\n",
			expected: &ARCSeal{
				InstanceNumber:  1,
				Algorithm:       SignatureAlgorithmRSA_SHA256,
				ChainValidation: ChainValidationResultNone,
				Domain:          "example.com",
				Selector:        "selector",
				Timestamp:       1706971004,
				Signature: "g+R0nyap1H1wsIqc3AvSesOyicLqq/p5bMP4yJUG/Kqmb8iN42MuYVdjD8xFNiPggfmq2Uz/FvYsyq9v" +
					"x8R9Isxu0eNKyx4tZWMK0kNJkxW/cA+RRPZ1sSXxI2w+ZomV5OHl0AzFFAUlU41Ngq6mJLKNXVYDrd4S" +
					"ILiYHCC+1B/sylS+7c4tbCTtQbikeVDZmTpq+W9lEDGxgtcmZK8UlAjDZ5CfMIef2ukeWWm8atqPRm0N" +
					"fExmsWYhytVvccgNIfYCgsji2Cee45epWJXJSD+RJLbhwbLgfMlFSUa4cdW0yNN24OB7rHV1T/tg+boG" +
					"y2vkgXJHRmKvadyjGwTW8A==",
				raw: "ARC-Seal: i=1; a=rsa-sha256; t=1706971004; cv=none;\r\n" +
					"        d=example.com; s=selector;\r\n" +
					"        b=g+R0nyap1H1wsIqc3AvSesOyicLqq/p5bMP4yJUG/Kqmb8iN42MuYVdjD8xFNiPg\r\n" +
					"         gfmq2Uz/FvYsyq9vx8R9Isxu0eNKyx4tZWMK0kNJkxW/cA+RRPZ1sSXxI2w+ZomV\r\n" +
					"         5OHl0AzFFAUlU41Ngq6mJLKNXVYDrd4SILiYHCC+1B/sylS+7c4tbCTtQbikeVDZ\r\n" +
					"         mTpq+W9lEDGxgtcmZK8UlAjDZ5CfMIef2ukeWWm8atqPRm0NfExmsWYhytVvccgN\r\n" +
					"         IfYCgsji2Cee45epWJXJSD+RJLbhwbLgfMlFSUa4cdW0yNN24OB7rHV1T/tg+boG\r\n" +
					"         y2vkgXJHRmKvadyjGwTW8A==\r\n",
			},
		},
	}

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			as, err := ParseARCSeal(tc.input)
			if err != nil {
				t.Fatalf("failed to parse: %s", err)
			}
			if as.InstanceNumber != tc.expected.InstanceNumber {
				t.Errorf("instance number mismatch: got %d, want %d", as.InstanceNumber, tc.expected.InstanceNumber)
			}
			if as.Algorithm != tc.expected.Algorithm {
				t.Errorf("algorithm mismatch: got %s, want %s", as.Algorithm, tc.expected.Algorithm)
			}
			if as.ChainValidation != tc.expected.ChainValidation {
				t.Errorf("chain validation mismatch: got %s, want %s", as.ChainValidation, tc.expected.ChainValidation)
			}
			if as.Domain != tc.expected.Domain {
				t.Errorf("domain mismatch: got %s, want %s", as.Domain, tc.expected.Domain)
			}
			if as.Selector != tc.expected.Selector {
				t.Errorf("selector mismatch: got %s, want %s", as.Selector, tc.expected.Selector)
			}
			if as.Timestamp != tc.expected.Timestamp {
				t.Errorf("timestamp mismatch: got %d, want %d", as.Timestamp, tc.expected.Timestamp)
			}
			if as.Signature != tc.expected.Signature {
				t.Errorf("signature mismatch: got %s, want %s", as.Signature, tc.expected.Signature)
			}
		})
	}
}

func TestARCSealSign(t *testing.T) {
	block, _ := pem.Decode([]byte(testRSAPrivateKey))
	if block == nil {
		t.Fatal("failed to decode pem")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse pkcs8 private key: %s", err)
	}
	privateKey := priv.(*rsa.PrivateKey)

	testCases := []struct {
		name     string
		input    *ARCSeal
		headers  []string
		expected string
	}{
		{
			input: &ARCSeal{
				InstanceNumber:  1,
				Algorithm:       SignatureAlgorithmRSA_SHA256,
				ChainValidation: ChainValidationResultNone,
				Domain:          "example.com",
				Selector:        "selector",
				Timestamp:       1706971004,
			},
			headers: []string{
				"ARC-Authentication-Results: i=1; example.com; dkim=pass; spf=pass\r\n",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
					"        h=Date:From:To:Subject:Message-Id;\r\n" +
					"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
					"        b=ef198CMzjQC9DkeKZj8IrzvZuEPqV/MBDLYGPpdSiofRdBv6BkrFS8Gb7jH7/oXW\r\n" +
					"         BEzZnRVMjpD7dHLpNjNjgqSQJI0GbSP/CK80BsVHRUioLWNPuG9aCNg/sOKl70yD\r\n" +
					"         3PwmimfOhr1tA18cdDNQv1Q5iAxPLCfY2IKzY6FQqw0YBIFqACYC2Nf2ONXha89Y\r\n" +
					"         UnZURPJSzXXrlZZserEqAt7MFaMzUVmBRHEDG9blwLkm/NhKKL9IT/pKc6T9ibbg\r\n" +
					"         Dlmh7sNjSEOIw7CS5dkp0k3r2zvR6l/fdChJh13fOv1LPwkmGeosXDWBmrdYr9Gx\r\n" +
					"         vrgEwmI6O74ZZR9jWIuyGg==\r\n",
			},
			expected: "g+R0nyap1H1wsIqc3AvSesOyicLqq/p5bMP4yJUG/Kqmb8iN42MuYVdjD8xFNiPggfmq2Uz/FvYsyq9v" +
				"x8R9Isxu0eNKyx4tZWMK0kNJkxW/cA+RRPZ1sSXxI2w+ZomV5OHl0AzFFAUlU41Ngq6mJLKNXVYDrd4S" +
				"ILiYHCC+1B/sylS+7c4tbCTtQbikeVDZmTpq+W9lEDGxgtcmZK8UlAjDZ5CfMIef2ukeWWm8atqPRm0N" +
				"fExmsWYhytVvccgNIfYCgsji2Cee45epWJXJSD+RJLbhwbLgfMlFSUa4cdW0yNN24OB7rHV1T/tg+boG" +
				"y2vkgXJHRmKvadyjGwTW8A==",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.input.Sign(tc.headers, privateKey); err != nil {
				t.Fatalf("failed to sign: %s", err)
			}
			if tc.input.Signature != tc.expected {
				t.Errorf("signature mismatch: got %s, want %s", tc.input.Signature, tc.expected)
			}
		})
	}
}

func Test_arcHeaderSort(t *testing.T) {
	testCases := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name: "test1",
			input: []string{
				"ARC-Authentication-Results: i=1;\r\n",
				"ARC-Message-Signature: i=1;\r\n",
				"ARC-Seal: i=1;\r\n",
			},
			want: []string{
				"ARC-Authentication-Results: i=1;\r\n",
				"ARC-Message-Signature: i=1;\r\n",
				"ARC-Seal: i=1;\r\n",
			},
		},
		{
			name: "test2",
			input: []string{
				"ARC-Authentication-Results: i=1;\r\n",
				"ARC-Message-Signature: i=1;\r\n",
				"ARC-Seal: i=1;\r\n",
				"ARC-Authentication-Results: i=2;\r\n",
				"ARC-Message-Signature: i=2;\r\n",
				"ARC-Seal: i=2;\r\n",
			},
			want: []string{
				"ARC-Authentication-Results: i=1;\r\n",
				"ARC-Message-Signature: i=1;\r\n",
				"ARC-Seal: i=1;\r\n",
				"ARC-Authentication-Results: i=2;\r\n",
				"ARC-Message-Signature: i=2;\r\n",
				"ARC-Seal: i=2;\r\n",
			},
		},
		{
			name: "test3",
			input: []string{
				"ARC-Seal: i=1;\r\n",
				"ARC-Message-Signature: i=2;\r\n",
				"ARC-Message-Signature: i=1;\r\n",
				"ARC-Authentication-Results: i=1;\r\n",
				"ARC-Seal: i=1;\r\n",
				"ARC-Authentication-Results: i=2;\r\n",
				"ARC-Seal: i=2;\r\n",
			},
			want: []string{
				"ARC-Authentication-Results: i=1;\r\n",
				"ARC-Message-Signature: i=1;\r\n",
				"ARC-Seal: i=1;\r\n",
				"ARC-Authentication-Results: i=2;\r\n",
				"ARC-Message-Signature: i=2;\r\n",
				"ARC-Seal: i=2;\r\n",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := arcHeaderSort(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("length mismatch: got %d, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("mismatch: got %s, want %s", got[i], tc.want[i])
				}
			}
		})
	}
}

func TestARCSealVerify(t *testing.T) {
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
		header    string
		headers   []string
		domainkey domainkey.DomainKey
	}{
		{
			name: "valid",
			header: "ARC-Seal: i=1; a=rsa-sha256; t=1706971004; cv=none;\r\n" +
				"        d=example.com; s=selector;\r\n" +
				"        b=g+R0nyap1H1wsIqc3AvSesOyicLqq/p5bMP4yJUG/Kqmb8iN42MuYVdjD8xFNiPg\r\n" +
				"         gfmq2Uz/FvYsyq9vx8R9Isxu0eNKyx4tZWMK0kNJkxW/cA+RRPZ1sSXxI2w+ZomV\r\n" +
				"         5OHl0AzFFAUlU41Ngq6mJLKNXVYDrd4SILiYHCC+1B/sylS+7c4tbCTtQbikeVDZ\r\n" +
				"         mTpq+W9lEDGxgtcmZK8UlAjDZ5CfMIef2ukeWWm8atqPRm0NfExmsWYhytVvccgN\r\n" +
				"         IfYCgsji2Cee45epWJXJSD+RJLbhwbLgfMlFSUa4cdW0yNN24OB7rHV1T/tg+boG\r\n" +
				"         y2vkgXJHRmKvadyjGwTW8A==\r\n",
			headers: []string{
				"ARC-Authentication-Results: i=1; example.com; dkim=pass; spf=pass\r\n",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
					"        h=Date:From:To:Subject:Message-Id;\r\n" +
					"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1706971004;\r\n" +
					"        b=ef198CMzjQC9DkeKZj8IrzvZuEPqV/MBDLYGPpdSiofRdBv6BkrFS8Gb7jH7/oXW\r\n" +
					"         BEzZnRVMjpD7dHLpNjNjgqSQJI0GbSP/CK80BsVHRUioLWNPuG9aCNg/sOKl70yD\r\n" +
					"         3PwmimfOhr1tA18cdDNQv1Q5iAxPLCfY2IKzY6FQqw0YBIFqACYC2Nf2ONXha89Y\r\n" +
					"         UnZURPJSzXXrlZZserEqAt7MFaMzUVmBRHEDG9blwLkm/NhKKL9IT/pKc6T9ibbg\r\n" +
					"         Dlmh7sNjSEOIw7CS5dkp0k3r2zvR6l/fdChJh13fOv1LPwkmGeosXDWBmrdYr9Gx\r\n" +
					"         vrgEwmI6O74ZZR9jWIuyGg==\r\n",
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
			ams, err := ParseARCSeal(tc.header)
			if err != nil {
				t.Fatalf("failed to parse arc seal: %s", err)
			}
			result := ams.Verify(tc.headers, &tc.domainkey)

			if result.Error() != nil {
				t.Errorf("verify failed: %s", result.Error())
			}
		})
	}
}

func Test_parseARCHeader(t *testing.T) {
	testCases := []struct {
		name   string
		input  []string
		expect signatures
	}{
		{
			name: "arc-seal",
			input: []string{
				"ARC-Seal: i=1; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature1",
				"ARC-Seal: i=2; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature2",
				"ARC-Seal: i=3; a=rsa-sha1; t=1617220000; cv=pass; d=example.com; s=selector; b=signature3",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash1; b=signature1",
				"ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash2; b=signature2",
				"ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash3; b=signature3",
				"ARC-Authentication-Results: i=1; example.com; arc=pass; dkim=pass",
				"ARC-Authentication-Results: i=2; example.com ; arc=pass; spf=pass",
				"ARC-Authentication-Results: i=3; example.com ; arc=pass; dmarc=pass",
			},
			expect: signatures{
				{
					InstanceNumber: 1,
					ARCSeal: &ARCSeal{
						InstanceNumber:  1,
						Algorithm:       SignatureAlgorithmRSA_SHA256,
						Timestamp:       1617220000,
						ChainValidation: ChainValidationResultPass,
						Domain:          "example.com",
						Selector:        "selector",
						Signature:       "signature1",
						raw:             "ARC-Seal: i=1; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature1",
					},
					ARCAuthenticationResults: &ARCAuthenticationResults{
						InstanceNumber: 1,
						AuthServId:     "example.com",
						Results:        []string{"arc=pass", "dkim=pass"},
						raw:            "ARC-Authentication-Results: i=1; example.com; arc=pass; dkim=pass",
					},
					ARCMessageSignature: &ARCMessageSignature{
						InstanceNumber:   1,
						Algorithm:        SignatureAlgorithmRSA_SHA256,
						Canonicalization: "relaxed/relaxed",
						Domain:           "example.com",
						Selector:         "selector",
						Timestamp:        1617220000,
						Headers:          "from:to:subject",
						BodyHash:         "bodyhash1",
						Signature:        "signature1",
						raw:              "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash1; b=signature1",
					},
				},
				{
					InstanceNumber: 2,
					ARCSeal: &ARCSeal{
						InstanceNumber:  2,
						Algorithm:       SignatureAlgorithmRSA_SHA256,
						Timestamp:       1617220000,
						ChainValidation: ChainValidationResultPass,
						Domain:          "example.com",
						Selector:        "selector",
						Signature:       "signature2",
						raw:             "ARC-Seal: i=2; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature2",
					},
					ARCAuthenticationResults: &ARCAuthenticationResults{
						InstanceNumber: 2,
						AuthServId:     "example.com",
						Results:        []string{"arc=pass", "spf=pass"},
						raw:            "ARC-Authentication-Results: i=2; example.com ; arc=pass; spf=pass",
					},
					ARCMessageSignature: &ARCMessageSignature{
						InstanceNumber:   2,
						Algorithm:        SignatureAlgorithmRSA_SHA256,
						Canonicalization: "relaxed/relaxed",
						Domain:           "example.com",
						Selector:         "selector",
						Timestamp:        1617220000,
						Headers:          "from:to:subject",
						BodyHash:         "bodyhash2",
						Signature:        "signature2",
						raw:              "ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash2; b=signature2",
					},
				},
				{
					InstanceNumber: 3,
					ARCSeal: &ARCSeal{
						InstanceNumber:  3,
						Algorithm:       SignatureAlgorithmRSA_SHA1,
						Timestamp:       1617220000,
						ChainValidation: ChainValidationResultPass,
						Domain:          "example.com",
						Selector:        "selector",
						Signature:       "signature3",
						raw:             "ARC-Seal: i=3; a=rsa-sha1; t=1617220000; cv=pass; d=example.com; s=selector; b=signature3",
					},
					ARCAuthenticationResults: &ARCAuthenticationResults{
						InstanceNumber: 3,
						AuthServId:     "example.com",
						Results:        []string{"arc=pass", "dmarc=pass"},
						raw:            "ARC-Authentication-Results: i=3; example.com ; arc=pass; dmarc=pass",
					},
					ARCMessageSignature: &ARCMessageSignature{
						InstanceNumber:   3,
						Algorithm:        SignatureAlgorithmRSA_SHA256,
						Canonicalization: "relaxed/relaxed",
						Domain:           "example.com",
						Selector:         "selector",
						Timestamp:        1617220000,
						Headers:          "from:to:subject",
						BodyHash:         "bodyhash3",
						Signature:        "signature3",
						raw:              "ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash3; b=signature3",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseARCHeaders(tc.input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if len(*got) != len(tc.expect) {
				t.Errorf("unexpected result: got=%d, expect=%d", len(*got), len(tc.expect))
			}
			for i, v := range *got {
				if v.InstanceNumber != tc.expect[i].InstanceNumber {
					t.Errorf("unexpected result: *got=%d, expect=%d", v.InstanceNumber, tc.expect[i].InstanceNumber)
				}
				if v.ARCSeal.InstanceNumber != tc.expect[i].ARCSeal.InstanceNumber {
					t.Errorf("unexpected result: *got=%d, expect=%d", v.ARCSeal.InstanceNumber, tc.expect[i].ARCSeal.InstanceNumber)
				}
				if v.ARCSeal.Algorithm != tc.expect[i].ARCSeal.Algorithm {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCSeal.Algorithm, tc.expect[i].ARCSeal.Algorithm)
				}
				if v.ARCSeal.Timestamp != tc.expect[i].ARCSeal.Timestamp {
					t.Errorf("unexpected result: *got=%d, expect=%d", v.ARCSeal.Timestamp, tc.expect[i].ARCSeal.Timestamp)
				}
				if v.ARCSeal.ChainValidation != tc.expect[i].ARCSeal.ChainValidation {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCSeal.ChainValidation, tc.expect[i].ARCSeal.ChainValidation)
				}
				if v.ARCSeal.Domain != tc.expect[i].ARCSeal.Domain {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCSeal.Domain, tc.expect[i].ARCSeal.Domain)
				}
				if v.ARCSeal.Selector != tc.expect[i].ARCSeal.Selector {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCSeal.Selector, tc.expect[i].ARCSeal.Selector)
				}
				if v.ARCSeal.Signature != tc.expect[i].ARCSeal.Signature {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCSeal.Signature, tc.expect[i].ARCSeal.Signature)
				}
				if v.ARCSeal.raw != tc.expect[i].ARCSeal.raw {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCSeal.raw, tc.expect[i].ARCSeal.raw)
				}
				if v.ARCAuthenticationResults.InstanceNumber != tc.expect[i].ARCAuthenticationResults.InstanceNumber {
					t.Errorf("unexpected result: *got=%d, expect=%d", v.ARCAuthenticationResults.InstanceNumber, tc.expect[i].ARCAuthenticationResults.InstanceNumber)
				}
				if v.ARCAuthenticationResults.AuthServId != tc.expect[i].ARCAuthenticationResults.AuthServId {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCAuthenticationResults.AuthServId, tc.expect[i].ARCAuthenticationResults.AuthServId)
				}
				for j, r := range v.ARCAuthenticationResults.Results {
					if r != tc.expect[i].ARCAuthenticationResults.Results[j] {
						t.Errorf("unexpected result: *got=%s, expect=%s", r, tc.expect[i].ARCAuthenticationResults.Results[j])
					}
				}
				if v.ARCAuthenticationResults.raw != tc.expect[i].ARCAuthenticationResults.raw {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCAuthenticationResults.raw, tc.expect[i].ARCAuthenticationResults.raw)
				}
				if v.ARCMessageSignature.InstanceNumber != tc.expect[i].ARCMessageSignature.InstanceNumber {
					t.Errorf("unexpected result: *got=%d, expect=%d", v.ARCMessageSignature.InstanceNumber, tc.expect[i].ARCMessageSignature.InstanceNumber)
				}
				if v.ARCMessageSignature.Algorithm != tc.expect[i].ARCMessageSignature.Algorithm {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCMessageSignature.Algorithm, tc.expect[i].ARCMessageSignature.Algorithm)
				}
				if v.ARCMessageSignature.Canonicalization != tc.expect[i].ARCMessageSignature.Canonicalization {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCMessageSignature.Canonicalization, tc.expect[i].ARCMessageSignature.Canonicalization)
				}
				if v.ARCMessageSignature.Domain != tc.expect[i].ARCMessageSignature.Domain {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCMessageSignature.Domain, tc.expect[i].ARCMessageSignature.Domain)
				}
				if v.ARCMessageSignature.Selector != tc.expect[i].ARCMessageSignature.Selector {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCMessageSignature.Selector, tc.expect[i].ARCMessageSignature.Selector)
				}
				if v.ARCMessageSignature.Timestamp != tc.expect[i].ARCMessageSignature.Timestamp {
					t.Errorf("unexpected result: *got=%d, expect=%d", v.ARCMessageSignature.Timestamp, tc.expect[i].ARCMessageSignature.Timestamp)
				}
				if v.ARCMessageSignature.Headers != tc.expect[i].ARCMessageSignature.Headers {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCMessageSignature.Headers, tc.expect[i].ARCMessageSignature.Headers)
				}
				if v.ARCMessageSignature.BodyHash != tc.expect[i].ARCMessageSignature.BodyHash {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCMessageSignature.BodyHash, tc.expect[i].ARCMessageSignature.BodyHash)
				}
				if v.ARCMessageSignature.Signature != tc.expect[i].ARCMessageSignature.Signature {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCMessageSignature.Signature, tc.expect[i].ARCMessageSignature.Signature)
				}
				if v.ARCMessageSignature.raw != tc.expect[i].ARCMessageSignature.raw {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.ARCMessageSignature.raw, tc.expect[i].ARCMessageSignature.raw)
				}
			}
		})
	}
}
