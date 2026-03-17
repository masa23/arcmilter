package config

import (
	"os/user"
	"strconv"
	"testing"
)

func Test_getUid(t *testing.T) {
	testCase := []struct {
		name      string
		userStr   string
		expected  int
		expectErr bool
	}{
		{
			name:      "root",
			userStr:   "root",
			expected:  0,
			expectErr: false,
		},
		{
			name:      "empty",
			userStr:   "",
			expected:  0,
			expectErr: false,
		},
		{
			name:      "invalid",
			userStr:   "hogehogefugafuga",
			expected:  0,
			expectErr: true,
		},
	}

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := getUid(tc.userStr)
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error, but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tc.name == "empty" {
				u, err := user.Current()
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				uid, err := strconv.Atoi(u.Uid)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if actual != uid {
					t.Errorf("expected: %d, but got: %d", uid, actual)
				}
				return
			}
			if actual != tc.expected {
				t.Errorf("expected: %d, but got: %d", tc.expected, actual)
			}
		})
	}
}

func Test_getGid(t *testing.T) {
	testCase := []struct {
		name      string
		groupStr  string
		expected  int
		expectErr bool
	}{
		{
			name:      "root",
			groupStr:  "root",
			expected:  0,
			expectErr: false,
		},
		{
			name:      "empty",
			groupStr:  "",
			expected:  0,
			expectErr: false,
		},
		{
			name:      "invalid",
			groupStr:  "hogehogefugafuga",
			expected:  0,
			expectErr: true,
		},
	}

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := getGid(tc.groupStr)
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error, but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tc.name == "empty" {
				g, err := user.Current()
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				gid, err := strconv.Atoi(g.Gid)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if actual != gid {
					t.Errorf("expected: %d, but got: %d", gid, actual)
				}
				return
			}
			if actual != tc.expected {
				t.Errorf("expected: %d, but got: %d", tc.expected, actual)
			}
		})
	}
}

func Test_checkMilterListenNetwork(t *testing.T) {
	testCase := []struct {
		name      string
		network   string
		expectErr bool
	}{
		{
			name:      "tcp",
			network:   "tcp",
			expectErr: false,
		},
		{
			name:      "unix",
			network:   "unix",
			expectErr: false,
		},
		{
			name:      "invalid",
			network:   "udp",
			expectErr: true,
		},
	}

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMilterListenNetwork(tc.network)
			if err != nil && !tc.expectErr {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func Test_parseDomainPattern(t *testing.T) {
	testCases := []struct {
		name       string
		pattern    string
		expectWild bool
		expectHost string
	}{
		{
			name:       "exact match",
			pattern:    "example.com",
			expectWild: false,
			expectHost: "example.com",
		},
		{
			name:       "wildcard subdomain",
			pattern:    "*.example.com",
			expectWild: true,
			expectHost: "example.com",
		},
		{
			name:       "default wildcard",
			pattern:    "*",
			expectWild: true,
			expectHost: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isWild, hostPart := parseDomainPattern(tc.pattern)
			if isWild != tc.expectWild {
				t.Errorf("expected isWildcard=%v, got %v", tc.expectWild, isWild)
			}
			if hostPart != tc.expectHost {
				t.Errorf("expected hostPart=%s, got %s", tc.expectHost, hostPart)
			}
		})
	}
}

func Test_matchDomain(t *testing.T) {
	testCases := []struct {
		name     string
		pattern  string
		domain   string
		expected bool
	}{
		{
			name:     "exact match",
			pattern:  "example.com",
			domain:   "example.com",
			expected: true,
		},
		{
			name:     "exact mismatch",
			pattern:  "example.com",
			domain:   "sub.example.com",
			expected: false,
		},
		{
			name:     "wildcard matches subdomain",
			pattern:  "*.example.com",
			domain:   "sub.example.com",
			expected: true,
		},
		{
			name:     "wildcard matches deep subdomain",
			pattern:  "*.example.com",
			domain:   "mail.sub.example.com",
			expected: true,
		},
		{
			name:     "wildcard edge case matches exact domain",
			pattern:  "*.example.com",
			domain:   "example.com",
			expected: true,
		},
		{
			name:     "wildcard does not match different domain",
			pattern:  "*.example.com",
			domain:   "other.com",
			expected: false,
		},
		{
			name:     "default wildcard matches anything",
			pattern:  "*",
			domain:   "anything",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := matchDomain(tc.pattern, tc.domain)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func Test_expandDomains(t *testing.T) {
	input := map[string]Domain{
		"list:example.com,mail.example.com,*.sub.example.com": {
			Selector:       "default",
			PrivateKeyFile: "/etc/arcmilter/keys/default.key",
			DKIM:           true,
			ARC:            true,
		},
		"exact.com": {
			Selector:       "exact",
			PrivateKeyFile: "/etc/arcmilter/keys/exact.key",
			DKIM:           true,
			ARC:            true,
		},
	}

	result := expandDomains(input)

	// 展開されたエントリを確認
	if len(result) != 4 {
		t.Errorf("expected 4 domains, got %d", len(result))
	}

	// 個別のドメイン確認
	for _, domain := range []string{"example.com", "mail.example.com", "*.sub.example.com"} {
		if d, ok := result[domain]; !ok {
			t.Errorf("domain %s not found in result", domain)
		} else {
			if d.Selector != "default" {
				t.Errorf("domain %s: expected Selector=default, got %s", domain, d.Selector)
			}
			if d.Domain != domain {
				t.Errorf("domain %s: expected Domain=%s, got %s", domain, domain, d.Domain)
			}
			if d.Pattern != domain {
				t.Errorf("domain %s: expected Pattern=%s, got %s", domain, domain, d.Pattern)
			}
		}
	}

	// 完全一致ドメインの確認
	if d, ok := result["exact.com"]; !ok {
		t.Errorf("domain exact.com not found in result")
	} else {
		if d.Selector != "exact" {
			t.Errorf("domain exact.com: expected Selector=exact, got %s", d.Selector)
		}
	}
}

func Test_GetMatchingDomain(t *testing.T) {
	testConfig := &Config{
		Domains: map[string]Domain{
			"example.com": {
				Domain:         "example.com",
				Pattern:        "example.com",
				Selector:       "exact",
				PrivateKeyFile: "/tmp/keys/exact.key",
				DKIM:           true,
			},
			"*.customer.com": {
				Domain:         "*.customer.com",
				Pattern:        "*.customer.com",
				Selector:       "customer",
				PrivateKeyFile: "/tmp/keys/customer.key",
				DKIM:           true,
			},
			"*.sub.customer.com": {
				Domain:         "*.sub.customer.com",
				Pattern:        "*.sub.customer.com",
				Selector:       "subcustomer",
				PrivateKeyFile: "/tmp/keys/subcustomer.key",
				DKIM:           true,
			},
			"*": {
				Domain:         "*",
				Pattern:        "*",
				Selector:       "default",
				PrivateKeyFile: "/tmp/keys/default.key",
				DKIM:           true,
			},
		},
	}

	testCases := []struct {
		name          string
		domain        string
		expectPattern string
	}{
		{
			name:          "exact match takes priority",
			domain:        "example.com",
			expectPattern: "example.com",
		},
		{
			name:          "wildcard match",
			domain:        "mail.customer.com",
			expectPattern: "*.customer.com",
		},
		{
			name:          "more specific wildcard match",
			domain:        "mail.sub.customer.com",
			expectPattern: "*.sub.customer.com",
		},
		{
			name:          "default wildcard match",
			domain:        "other.com",
			expectPattern: "*",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			domain, ok := testConfig.GetMatchingDomain(tc.domain)
			if !ok {
				t.Errorf("domain %s: expected match, got none", tc.domain)
				return
			}
			if domain.Pattern != tc.expectPattern {
				t.Errorf("domain %s: expected pattern %s, got %s", tc.domain, tc.expectPattern, domain.Pattern)
			}
		})
	}
}
