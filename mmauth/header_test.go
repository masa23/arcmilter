package mmauth

import (
	"bufio"
	"crypto"
	"strings"
	"testing"

	"github.com/masa23/arcmilter/mmauth/arc"
)

func Test_readHeader(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expect        headers
		expectedError bool
	}{
		{
			name:   "empty",
			input:  "\r\n\r\n",
			expect: headers{},
		},
		{
			name: "normal",
			input: "header:hoge\r\n" +
				"Header2:fuga\r\n" +
				"Header3:pi\r\n\tyo\r\n\r\n",
			expect: headers{
				"header:hoge\r\n",
				"Header2:fuga\r\n",
				"Header3:pi\r\n\tyo\r\n",
			},
		},
		{
			name:  "one header",
			input: "header:hoge\r\n\r\nbody\r\n",
			expect: headers{
				"header:hoge\r\n",
			},
		},
		{
			name:  "non body",
			input: "header:hoge\r\n\r\n",
			expect: headers{
				"header:hoge\r\n",
			},
		},
		{
			name:          "non header crlf",
			input:         "header:hoge",
			expectedError: true,
		},
		{
			name:          "non body crlf",
			input:         "header:hoge\r\nbody",
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := strings.NewReader(tc.input)
			br := bufio.NewReader(r)
			got, err := readHeader(br)
			if err == nil && tc.expectedError {
				t.Errorf("expected error, but no error")
				return
			} else if tc.expectedError {
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if len(got) != len(tc.expect) {
				t.Errorf("unexpected result: got=%d, expect=%d", len(got), len(tc.expect))
			}
			for i, v := range got {
				if v != tc.expect[i] {
					t.Errorf("unexpected result: got=%s, expect=%s", v, tc.expect[i])
				}
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

func Test_isCcanonicalizationBodyAndAlgorithm(t *testing.T) {
	testCases := []struct {
		name   string
		input  BodyCanonicalizationAndAlgorithm
		can    []BodyCanonicalizationAndAlgorithm
		expect bool
	}{
		{
			name: "true",
			input: BodyCanonicalizationAndAlgorithm{
				Body:      CanonicalizationSimple,
				Algorithm: crypto.SHA1,
			},
			can: []BodyCanonicalizationAndAlgorithm{
				{
					Body:      CanonicalizationSimple,
					Algorithm: crypto.SHA1,
				},
				{
					Body:      CanonicalizationSimple,
					Algorithm: crypto.SHA256,
				},
				{
					Body:      CanonicalizationRelaxed,
					Algorithm: crypto.SHA1,
				},
				{
					Body:      CanonicalizationRelaxed,
					Algorithm: crypto.SHA256,
				},
			},
			expect: true,
		},
		{
			name: "false",
			input: BodyCanonicalizationAndAlgorithm{
				Body:      CanonicalizationSimple,
				Algorithm: crypto.SHA1,
			},
			can: []BodyCanonicalizationAndAlgorithm{
				{
					Body:      CanonicalizationSimple,
					Algorithm: crypto.SHA256,
				},
				{
					Body:      CanonicalizationRelaxed,
					Algorithm: crypto.SHA1,
				},
				{
					Body:      CanonicalizationRelaxed,
					Algorithm: crypto.SHA256,
				},
			},
			expect: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := isCcanonicalizationBodyAndAlgorithm(tc.input, tc.can)
			if got != tc.expect {
				t.Errorf("unexpected result: got=%t, expect=%t", got, tc.expect)
			}
		})
	}
}

func Test_parseHeaderCanonicalization(t *testing.T) {
	testCase := []struct {
		name         string
		input        string
		expectHeader Canonicalization
		expectBody   Canonicalization
	}{
		{
			name:         "simple/simple",
			input:        "simple/simple",
			expectHeader: CanonicalizationSimple,
			expectBody:   CanonicalizationSimple,
		},
		{
			name:         "relaxed/relaxed",
			input:        "relaxed/relaxed",
			expectHeader: CanonicalizationRelaxed,
			expectBody:   CanonicalizationRelaxed,
		},
		{
			name:         "simple/relaxed",
			input:        "simple/relaxed",
			expectHeader: CanonicalizationSimple,
			expectBody:   CanonicalizationRelaxed,
		},
		{
			name:         "relaxed/simple",
			input:        "relaxed/simple",
			expectHeader: CanonicalizationRelaxed,
			expectBody:   CanonicalizationSimple,
		},
		{
			name:         "simple",
			input:        "simple",
			expectHeader: CanonicalizationSimple,
			expectBody:   CanonicalizationSimple,
		},
		{
			name:         "relaxed",
			input:        "relaxed",
			expectHeader: CanonicalizationRelaxed,
			expectBody:   CanonicalizationSimple,
		},
		{
			name:         "none",
			input:        "",
			expectHeader: CanonicalizationSimple,
			expectBody:   CanonicalizationSimple,
		},
	}
	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			header, body, err := parseHeaderCanonicalization(tc.input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if header != tc.expectHeader {
				t.Errorf("unexpected result: got=%s, expect=%s", header, tc.expectHeader)
			}
			if body != tc.expectBody {
				t.Errorf("unexpected result: got=%s, expect=%s", body, tc.expectBody)
			}
		})
	}
}

func TestGetARCChainValidationResult(t *testing.T) {
	testCases := []struct {
		name   string
		input  []string
		expect arc.ChainValidationResult
	}{
		{
			name: "pass",
			input: []string{
				"ARC-Seal: i=1; a=rsa-sha256; t=1617220000; cv=none; d=example.com; s=selector; b=signature1",
				"ARC-Seal: i=2; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature2",
				"ARC-Seal: i=3; a=rsa-sha1; t=1617220000; cv=pass; d=example.com; s=selector; b=signature3",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash1; b=signature1",
				"ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash2; b=signature2",
				"ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash3; b=signature3",
				"ARC-Authentication-Results: i=1; example.com; arc=pass; dkim=pass",
				"ARC-Authentication-Results: i=2; example.com ; arc=pass; spf=pass",
				"ARC-Authentication-Results: i=3; example.com ; arc=pass; dmarc=pass",
			},
			expect: arc.ChainValidationResultPass,
		},
		{
			name:   "none",
			input:  []string{},
			expect: arc.ChainValidationResultNone,
		},
		{
			name: "fail1",
			input: []string{
				"ARC-Seal: i=1; a=rsa-sha256; t=1617220000; cv=fail; d=example.com; s=selector; b=signature1",
				"ARC-Seal: i=2; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature2",
				"ARC-Seal: i=3; a=rsa-sha1; t=1617220000; cv=none; d=example.com; s=selector; b=signature3",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash1; b=signature1",
				"ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash2; b=signature2",
				"ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash3; b=signature3",
				"ARC-Authentication-Results: i=1; example.com; arc=pass; dkim=pass",
				"ARC-Authentication-Results: i=2; example.com ; arc=pass; spf=pass",
				"ARC-Authentication-Results: i=3; example.com ; arc=pass; dmarc=pass",
			},
			expect: arc.ChainValidationResultFail,
		},
		{
			name: "fail2",
			input: []string{
				"ARC-Seal: i=1; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature1",
				"ARC-Seal: i=2; a=rsa-sha256; t=1617220000; cv=fail; d=example.com; s=selector; b=signature2",
				"ARC-Seal: i=3; a=rsa-sha1; t=1617220000; cv=none; d=example.com; s=selector; b=signature3",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash1; b=signature1",
				"ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash2; b=signature2",
				"ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash3; b=signature3",
				"ARC-Authentication-Results: i=1; example.com; arc=pass; dkim=pass",
				"ARC-Authentication-Results: i=2; example.com ; arc=pass; spf=pass",
				"ARC-Authentication-Results: i=3; example.com ; arc=pass; dmarc=pass",
			},
			expect: arc.ChainValidationResultFail,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ahs, err := ParseARCHeaders(tc.input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ahs.GetARCChainValidation() != tc.expect {
				t.Errorf("unexpected result: got=%s, expect=%s, signature=pass", ahs.GetARCChainValidation(), tc.expect)
			}
		})
	}
}

func TestParseARCHeaders(t *testing.T) {
	testCases := []struct {
		name   string
		input  []string
		expect ARCSignatures
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
			expect: ARCSignatures{
				{
					InstanceNumber: 1,
					ARCSeal: &arc.ARCSeal{
						InstanceNumber:  1,
						Algorithm:       arc.SignatureAlgorithmRSA_SHA256,
						Timestamp:       1617220000,
						ChainValidation: arc.ChainValidationResultPass,
						Domain:          "example.com",
						Selector:        "selector",
						Signature:       "signature1",
					},
					ARCAuthenticationResults: &arc.ARCAuthenticationResults{
						InstanceNumber: 1,
						AuthServId:     "example.com",
						Results:        []string{"arc=pass", "dkim=pass"},
					},
					ARCMessageSignature: &arc.ARCMessageSignature{
						InstanceNumber:   1,
						Algorithm:        arc.SignatureAlgorithmRSA_SHA256,
						Canonicalization: "relaxed/relaxed",
						Domain:           "example.com",
						Selector:         "selector",
						Timestamp:        1617220000,
						Headers:          "from:to:subject",
						BodyHash:         "bodyhash1",
						Signature:        "signature1",
					},
				},
				{
					InstanceNumber: 2,
					ARCSeal: &arc.ARCSeal{
						InstanceNumber:  2,
						Algorithm:       arc.SignatureAlgorithmRSA_SHA256,
						Timestamp:       1617220000,
						ChainValidation: arc.ChainValidationResultPass,
						Domain:          "example.com",
						Selector:        "selector",
						Signature:       "signature2",
					},
					ARCAuthenticationResults: &arc.ARCAuthenticationResults{
						InstanceNumber: 2,
						AuthServId:     "example.com",
						Results:        []string{"arc=pass", "spf=pass"},
					},
					ARCMessageSignature: &arc.ARCMessageSignature{
						InstanceNumber:   2,
						Algorithm:        arc.SignatureAlgorithmRSA_SHA256,
						Canonicalization: "relaxed/relaxed",
						Domain:           "example.com",
						Selector:         "selector",
						Timestamp:        1617220000,
						Headers:          "from:to:subject",
						BodyHash:         "bodyhash2",
						Signature:        "signature2",
					},
				},
				{
					InstanceNumber: 3,
					ARCSeal: &arc.ARCSeal{
						InstanceNumber:  3,
						Algorithm:       arc.SignatureAlgorithmRSA_SHA1,
						Timestamp:       1617220000,
						ChainValidation: arc.ChainValidationResultPass,
						Domain:          "example.com",
						Selector:        "selector",
						Signature:       "signature3",
					},
					ARCAuthenticationResults: &arc.ARCAuthenticationResults{
						InstanceNumber: 3,
						AuthServId:     "example.com",
						Results:        []string{"arc=pass", "dmarc=pass"},
					},
					ARCMessageSignature: &arc.ARCMessageSignature{
						InstanceNumber:   3,
						Algorithm:        arc.SignatureAlgorithmRSA_SHA256,
						Canonicalization: "relaxed/relaxed",
						Domain:           "example.com",
						Selector:         "selector",
						Timestamp:        1617220000,
						Headers:          "from:to:subject",
						BodyHash:         "bodyhash3",
						Signature:        "signature3",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseARCHeaders(tc.input)
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
			}
		})
	}
}

func TestGetARCHeaders(t *testing.T) {
	testCases := []struct {
		name   string
		input  []string
		expect []string
	}{
		{
			name: "test1",
			input: []string{
				"ARC-Seal: i=1; a=rsa-sha256; t=1617220000; cv=none; d=example.com; s=selector; b=signature1",
				"ARC-Seal: i=2; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature2",
				"ARC-Seal: i=3; a=rsa-sha1; t=1617220000; cv=pass; d=example.com; s=selector; b=signature3",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash1; b=signature1",
				"ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash2; b=signature2",
				"ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash3; b=signature3",
				"ARC-Authentication-Results: i=1; example.com; arc=pass; dkim=pass",
				"ARC-Authentication-Results: i=2; example.com ; arc=pass; spf=pass",
				"ARC-Authentication-Results: i=3; example.com ; arc=pass; dmarc=pass",
			},
			expect: []string{
				"ARC-Authentication-Results: i=1; example.com; arc=pass; dkim=pass",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash1; b=signature1",
				"ARC-Seal: i=1; a=rsa-sha256; t=1617220000; cv=none; d=example.com; s=selector; b=signature1",
				"ARC-Authentication-Results: i=2; example.com ; arc=pass; spf=pass",
				"ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash2; b=signature2",
				"ARC-Seal: i=2; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature2",
				"ARC-Authentication-Results: i=3; example.com ; arc=pass; dmarc=pass",
				"ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash3; b=signature3",
				"ARC-Seal: i=3; a=rsa-sha1; t=1617220000; cv=pass; d=example.com; s=selector; b=signature3",
			},
		},
		{
			name: "test2",
			input: []string{
				"ARC-Seal: i=1; a=rsa-sha256; t=1617220000; cv=none; d=example.com; s=selector; b=signature1",
				"ARC-Seal: i=3; a=rsa-sha1; t=1617220000; cv=pass; d=example.com; s=selector; b=signature3",
				"ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash2; b=signature2",
				"ARC-Seal: i=2; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature2",
				"ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash3; b=signature3",
				"ARC-Authentication-Results: i=2; example.com ; arc=pass; spf=pass",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash1; b=signature1",
				"ARC-Authentication-Results: i=3; example.com ; arc=pass; dmarc=pass",
				"ARC-Authentication-Results: i=1; example.com; arc=pass; dkim=pass",
			},
			expect: []string{
				"ARC-Authentication-Results: i=1; example.com; arc=pass; dkim=pass",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash1; b=signature1",
				"ARC-Seal: i=1; a=rsa-sha256; t=1617220000; cv=none; d=example.com; s=selector; b=signature1",
				"ARC-Authentication-Results: i=2; example.com ; arc=pass; spf=pass",
				"ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash2; b=signature2",
				"ARC-Seal: i=2; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature2",
				"ARC-Authentication-Results: i=3; example.com ; arc=pass; dmarc=pass",
				"ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash3; b=signature3",
				"ARC-Seal: i=3; a=rsa-sha1; t=1617220000; cv=pass; d=example.com; s=selector; b=signature3",
			},
		},
		{
			name:   "no headers",
			input:  []string{},
			expect: []string{},
		},
		{
			name: "no arc headers",
			input: []string{
				"Authentication-Results: example.com; dkim=pass",
				"From: jon@example.com",
			},
			expect: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ahs, err := ParseARCHeaders(tc.input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			got := ahs.GetARCHeaders()
			if len(got) != len(tc.expect) {
				t.Errorf("unexpected result: got=%d, expect=%d", len(got), len(tc.expect))
			}
			for i, v := range got {
				if v != tc.expect[i] {
					t.Errorf("unexpected result: got=%s, expect=%s", v, tc.expect[i])
				}
			}
		})
	}
}
