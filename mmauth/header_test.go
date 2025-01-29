package mmauth

import (
	"bufio"
	"crypto"
	"strings"
	"testing"
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
