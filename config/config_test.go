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
			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error, but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
