package dkim

import (
	"testing"
)

func TestGetResult(t *testing.T) {
	cases := []struct {
		name       string
		signatures Signatures
		expected   VerifyStatus
	}{
		{
			name: "Single Pass",
			signatures: Signatures{
				&Signature{
					VerifyResult: &VerifyResult{status: VerifyStatusPass},
				},
			},
			expected: VerifyStatusPass,
		},
		{
			name: "Single Fail",
			signatures: Signatures{
				&Signature{
					VerifyResult: &VerifyResult{status: VerifyStatusFail},
				},
			},
			expected: VerifyStatusFail,
		},
		{
			name: "Multiple Signatures with Fail",
			signatures: Signatures{
				&Signature{
					VerifyResult: &VerifyResult{status: VerifyStatusPass},
				},
				&Signature{
					VerifyResult: &VerifyResult{status: VerifyStatusFail},
				},
			},
			expected: VerifyStatusFail,
		},
		{
			name:       "No Signatures",
			signatures: Signatures{},
			expected:   VerifyStatusNone,
		},
		{
			name:       "Nil Signatures",
			signatures: nil,
			expected:   VerifyStatusNone,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := c.signatures.GetResult()
			if result != c.expected {
				t.Errorf("expected %s, got %s", c.expected, result)
			}
		})
	}
}

func TestParseDKIMHeaders(t *testing.T) {
	cases := []struct {
		name           string
		headers        []string
		expectedDomain string
		expectedCount  int
		expectError    bool
	}{
		{
			name: "Valid DKIM Signature",
			headers: []string{
				"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=example.com; s=selector; h=from:to:subject:date; bh=base64hash; b=base64signature",
				"Other-Header: value",
			},
			expectedDomain: "example.com",
			expectedCount:  1,
			expectError:    false,
		},
		{
			name: "No DKIM Signature",
			headers: []string{
				"Other-Header: value",
			},
			expectedDomain: "",
			expectedCount:  0,
			expectError:    false,
		},
		{
			name: "Invalid DKIM Signature",
			headers: []string{
				"DKIM-Signature: invalid-signature",
			},
			expectedDomain: "",
			expectedCount:  0,
			expectError:    true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sigs, err := ParseDKIMHeaders(c.headers)
			if c.expectError {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if len(*sigs) != c.expectedCount {
				t.Fatalf("expected %d signature(s), got %d", c.expectedCount, len(*sigs))
			}

			if c.expectedCount > 0 && (*sigs)[0].Domain != c.expectedDomain {
				t.Errorf("expected domain %s, got %s", c.expectedDomain, (*sigs)[0].Domain)
			}
		})
	}
}
