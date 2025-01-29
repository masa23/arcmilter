package arc

import (
	"testing"
)

func TestGetARCChainValidationResult(t *testing.T) {
	testCases := []struct {
		name   string
		input  []string
		expect ChainValidationResult
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
			expect: ChainValidationResultPass,
		},
		{
			name:   "none",
			input:  []string{},
			expect: ChainValidationResultNone,
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
			expect: ChainValidationResultFail,
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
			expect: ChainValidationResultFail,
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
		name      string
		input     []string
		expect    Signatures
		expectErr bool
	}{
		{
			name: "arc parse test pass",
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
			expectErr: false,
			expect: Signatures{
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
					},
					arcAuthenticationResults: &ARCAuthenticationResults{
						InstanceNumber: 1,
						AuthServId:     "example.com",
						Results:        []string{"arc=pass", "dkim=pass"},
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
					},
					arcAuthenticationResults: &ARCAuthenticationResults{
						InstanceNumber: 2,
						AuthServId:     "example.com",
						Results:        []string{"arc=pass", "spf=pass"},
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
					},
					arcAuthenticationResults: &ARCAuthenticationResults{
						InstanceNumber: 3,
						AuthServId:     "example.com",
						Results:        []string{"arc=pass", "dmarc=pass"},
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
					},
				},
			},
		},
		{
			name: "arc parse test fail",
			input: []string{
				"ARC-Seal: i=1; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature1",
				"ARC-Seal: i=2; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature2",
				"ARC-Seal: i=3; a=rsa-sha1; t=1617220000; cv=pass; d=example.com; s=selector; b=signature3",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash1; b=signature1",
				"ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash3; b=signature3",
				"ARC-Authentication-Results: i=1; example.com; arc=pass; dkim=pass",
				"ARC-Authentication-Results: i=2; example.com ; arc=pass; spf=pass",
				"ARC-Authentication-Results: i=3; example.com ; arc=pass; dmarc=pass",
			},
			expectErr: true,
			expect:    Signatures{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseARCHeaders(tc.input)
			if err == nil && tc.expectErr {
				t.Errorf("expected error, but no error")
				return
			} else if tc.expectErr {
				return
			}
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
			}
		})
	}
}

func TestGetARCHeaders(t *testing.T) {
	testCases := []struct {
		name        string
		input       []string
		expect      []string
		expectError bool
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
			name: "missing arc-seal",
			input: []string{
				"ARC-Seal: i=1; a=rsa-sha256; t=1617220000; cv=none; d=example.com; s=selector; b=signature1",
				"ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash2; b=signature2",
				"ARC-Seal: i=2; a=rsa-sha256; t=1617220000; cv=pass; d=example.com; s=selector; b=signature2",
				"ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash3; b=signature3",
				"ARC-Authentication-Results: i=2; example.com ; arc=pass; spf=pass",
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; t=1617220000; h=from:to:subject; bh=bodyhash1; b=signature1",
				"ARC-Authentication-Results: i=3; example.com ; arc=pass; dmarc=pass",
				"ARC-Authentication-Results: i=1; example.com; arc=pass; dkim=pass",
			},
			expect:      []string{},
			expectError: true,
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
			if err == nil && tc.expectError {
				t.Errorf("expected error, but no error")
				return
			} else if tc.expectError {
				return
			}
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
