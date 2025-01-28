package arc

import (
	"crypto"
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
	testCases := []struct {
		name     string
		keyType  string
		input    *ARCSeal
		headers  []string
		expected string
	}{
		{
			name:    "rsa key test",
			keyType: "rsa",
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
		{
			name:    "ed25519 key test",
			keyType: "ed25519",
			input: &ARCSeal{
				InstanceNumber:  1,
				Algorithm:       SignatureAlgorithmED25519_SHA256,
				ChainValidation: ChainValidationResultNone,
				Domain:          "example.com",
				Selector:        "selector",
				Timestamp:       1728300596,
			},
			headers: []string{
				"ARC-Authentication-Results: i=1; example.com; dkim=pass; spf=pass\r\n",
				"ARC-Message-Signature: i=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
					"        h=Date:From:To:Subject;\r\n" +
					"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1728300596;\r\n" +
					"        b=B8O8oPo2sTAfWlgKfcwdBAq6zLgv9+9zUfwGy9XsjvCA3UxBUpy6VuVzXcCyTrTj\r\n" +
					"         vvlarL7sMnQeZvXN92nPDw==\r\n",
			},
			expected: "Xt6qSS3XrProksIWSKvJhxr2RW+FG2IfkIArZlpeRyBeSMezkp9fENlxV/7owRU7mDFM3ExsIOzOXrQjuaJOCw==",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var privateKey crypto.Signer
			if tc.keyType == "rsa" {
				privateKey = testKeys.RSAPrivateKey
			} else if tc.keyType == "ed25519" {
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
	testCases := []struct {
		name      string
		header    string
		headers   []string
		domainkey domainkey.DomainKey
	}{
		{
			name: "valid rsa",
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
				PublicKey: testKeys.getPublicKeyBase64("rsa"),
			},
		},
		{
			name: "valid ed25519",
			header: "ARC-Seal: i=1; a=ed25519-sha256; t=1728300596; cv=none;\r\n" +
				"        d=example.com; s=selector;\r\n" +
				"        b=Xt6qSS3XrProksIWSKvJhxr2RW+FG2IfkIArZlpeRyBeSMezkp9fENlxV/7owRU7\r\n" +
				"         mDFM3ExsIOzOXrQjuaJOCw==\r\n",
			headers: []string{
				"ARC-Authentication-Results: i=1; example.com; dkim=pass; spf=pass\r\n",
				"ARC-Message-Signature: i=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=selector;\r\n" +
					"        h=Date:From:To:Subject;\r\n" +
					"        bh=XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=; t=1728300596;\r\n" +
					"        b=B8O8oPo2sTAfWlgKfcwdBAq6zLgv9+9zUfwGy9XsjvCA3UxBUpy6VuVzXcCyTrTj\r\n" +
					"         vvlarL7sMnQeZvXN92nPDw==\r\n",
			},
			domainkey: domainkey.DomainKey{
				HashAlgo:  []domainkey.HashAlgo{"ed25519-sha256"},
				KeyType:   "ed25519",
				PublicKey: testKeys.getPublicKeyBase64("ed25519"),
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
					instanceNumber: 1,
					arcSeal: &ARCSeal{
						InstanceNumber:  1,
						Algorithm:       SignatureAlgorithmRSA_SHA256,
						Timestamp:       1617220000,
						ChainValidation: ChainValidationResultPass,
						Domain:          "example.com",
						Selector:        "selector",
						Signature:       "signature1",
						raw:             "ARC-Seal: i=1; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature1",
					},
					arcAuthenticationResults: &ARCAuthenticationResults{
						InstanceNumber: 1,
						AuthServId:     "example.com",
						Results:        []string{"arc=pass", "dkim=pass"},
						raw:            "ARC-Authentication-Results: i=1; example.com; arc=pass; dkim=pass",
					},
					arcMessageSignature: &ARCMessageSignature{
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
					instanceNumber: 2,
					arcSeal: &ARCSeal{
						InstanceNumber:  2,
						Algorithm:       SignatureAlgorithmRSA_SHA256,
						Timestamp:       1617220000,
						ChainValidation: ChainValidationResultPass,
						Domain:          "example.com",
						Selector:        "selector",
						Signature:       "signature2",
						raw:             "ARC-Seal: i=2; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature2",
					},
					arcAuthenticationResults: &ARCAuthenticationResults{
						InstanceNumber: 2,
						AuthServId:     "example.com",
						Results:        []string{"arc=pass", "spf=pass"},
						raw:            "ARC-Authentication-Results: i=2; example.com ; arc=pass; spf=pass",
					},
					arcMessageSignature: &ARCMessageSignature{
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
					instanceNumber: 3,
					arcSeal: &ARCSeal{
						InstanceNumber:  3,
						Algorithm:       SignatureAlgorithmRSA_SHA1,
						Timestamp:       1617220000,
						ChainValidation: ChainValidationResultPass,
						Domain:          "example.com",
						Selector:        "selector",
						Signature:       "signature3",
						raw:             "ARC-Seal: i=3; a=rsa-sha1; t=1617220000; cv=pass; d=example.com; s=selector; b=signature3",
					},
					arcAuthenticationResults: &ARCAuthenticationResults{
						InstanceNumber: 3,
						AuthServId:     "example.com",
						Results:        []string{"arc=pass", "dmarc=pass"},
						raw:            "ARC-Authentication-Results: i=3; example.com ; arc=pass; dmarc=pass",
					},
					arcMessageSignature: &ARCMessageSignature{
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
				if v.instanceNumber != tc.expect[i].instanceNumber {
					t.Errorf("unexpected result: *got=%d, expect=%d", v.instanceNumber, tc.expect[i].instanceNumber)
				}
				if v.arcSeal.InstanceNumber != tc.expect[i].arcSeal.InstanceNumber {
					t.Errorf("unexpected result: *got=%d, expect=%d", v.arcSeal.InstanceNumber, tc.expect[i].arcSeal.InstanceNumber)
				}
				if v.arcSeal.Algorithm != tc.expect[i].arcSeal.Algorithm {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcSeal.Algorithm, tc.expect[i].arcSeal.Algorithm)
				}
				if v.arcSeal.Timestamp != tc.expect[i].arcSeal.Timestamp {
					t.Errorf("unexpected result: *got=%d, expect=%d", v.arcSeal.Timestamp, tc.expect[i].arcSeal.Timestamp)
				}
				if v.arcSeal.ChainValidation != tc.expect[i].arcSeal.ChainValidation {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcSeal.ChainValidation, tc.expect[i].arcSeal.ChainValidation)
				}
				if v.arcSeal.Domain != tc.expect[i].arcSeal.Domain {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcSeal.Domain, tc.expect[i].arcSeal.Domain)
				}
				if v.arcSeal.Selector != tc.expect[i].arcSeal.Selector {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcSeal.Selector, tc.expect[i].arcSeal.Selector)
				}
				if v.arcSeal.Signature != tc.expect[i].arcSeal.Signature {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcSeal.Signature, tc.expect[i].arcSeal.Signature)
				}
				if v.arcSeal.raw != tc.expect[i].arcSeal.raw {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcSeal.raw, tc.expect[i].arcSeal.raw)
				}
				if v.arcAuthenticationResults.InstanceNumber != tc.expect[i].arcAuthenticationResults.InstanceNumber {
					t.Errorf("unexpected result: *got=%d, expect=%d", v.arcAuthenticationResults.InstanceNumber, tc.expect[i].arcAuthenticationResults.InstanceNumber)
				}
				if v.arcAuthenticationResults.AuthServId != tc.expect[i].arcAuthenticationResults.AuthServId {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcAuthenticationResults.AuthServId, tc.expect[i].arcAuthenticationResults.AuthServId)
				}
				for j, r := range v.arcAuthenticationResults.Results {
					if r != tc.expect[i].arcAuthenticationResults.Results[j] {
						t.Errorf("unexpected result: *got=%s, expect=%s", r, tc.expect[i].arcAuthenticationResults.Results[j])
					}
				}
				if v.arcAuthenticationResults.raw != tc.expect[i].arcAuthenticationResults.raw {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcAuthenticationResults.raw, tc.expect[i].arcAuthenticationResults.raw)
				}
				if v.arcMessageSignature.InstanceNumber != tc.expect[i].arcMessageSignature.InstanceNumber {
					t.Errorf("unexpected result: *got=%d, expect=%d", v.arcMessageSignature.InstanceNumber, tc.expect[i].arcMessageSignature.InstanceNumber)
				}
				if v.arcMessageSignature.Algorithm != tc.expect[i].arcMessageSignature.Algorithm {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcMessageSignature.Algorithm, tc.expect[i].arcMessageSignature.Algorithm)
				}
				if v.arcMessageSignature.Canonicalization != tc.expect[i].arcMessageSignature.Canonicalization {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcMessageSignature.Canonicalization, tc.expect[i].arcMessageSignature.Canonicalization)
				}
				if v.arcMessageSignature.Domain != tc.expect[i].arcMessageSignature.Domain {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcMessageSignature.Domain, tc.expect[i].arcMessageSignature.Domain)
				}
				if v.arcMessageSignature.Selector != tc.expect[i].arcMessageSignature.Selector {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcMessageSignature.Selector, tc.expect[i].arcMessageSignature.Selector)
				}
				if v.arcMessageSignature.Timestamp != tc.expect[i].arcMessageSignature.Timestamp {
					t.Errorf("unexpected result: *got=%d, expect=%d", v.arcMessageSignature.Timestamp, tc.expect[i].arcMessageSignature.Timestamp)
				}
				if v.arcMessageSignature.Headers != tc.expect[i].arcMessageSignature.Headers {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcMessageSignature.Headers, tc.expect[i].arcMessageSignature.Headers)
				}
				if v.arcMessageSignature.BodyHash != tc.expect[i].arcMessageSignature.BodyHash {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcMessageSignature.BodyHash, tc.expect[i].arcMessageSignature.BodyHash)
				}
				if v.arcMessageSignature.Signature != tc.expect[i].arcMessageSignature.Signature {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcMessageSignature.Signature, tc.expect[i].arcMessageSignature.Signature)
				}
				if v.arcMessageSignature.raw != tc.expect[i].arcMessageSignature.raw {
					t.Errorf("unexpected result: *got=%s, expect=%s", v.arcMessageSignature.raw, tc.expect[i].arcMessageSignature.raw)
				}
			}
		})
	}
}
