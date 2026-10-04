package config

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func validConfigYAML(keyPath string) string {
	return fmt.Sprintf(`MilterListen:
  Network: unix
  Address: /tmp/arcmilter.sock
PIDFile:
  Path: /tmp/arcmilter.pid
ControlSocketFile:
  Path: /tmp/arcmilterctl.sock
MyNetworks:
  - 127.0.0.0/8
  - "::1/128"
Domains:
  example.jp:
    PrivateKeyFile: %q
    DKIM: true
    ARC: true
DKIMSignHeaders: [From, Subject]
ARCSignHeaders: [From, Subject]
`, keyPath)
}

func writeConfigFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSupportedKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		key   crypto.Signer
		pkcs1 bool
	}{
		{"RSA PKCS1", rsaKey, true},
		{"RSA PKCS8", rsaKey, false},
		{"Ed25519 PKCS8", edKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block := &pem.Block{Type: "PRIVATE KEY"}
			if tc.pkcs1 {
				block.Type, block.Bytes = "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)
			} else {
				var err error
				block.Bytes, err = x509.MarshalPKCS8PrivateKey(tc.key)
				if err != nil {
					t.Fatal(err)
				}
			}
			keyPath := writeConfigFixture(t, "private.key", pem.EncodeToMemory(block))
			path := writeConfigFixture(t, "config.yaml", []byte(validConfigYAML(keyPath)))
			c, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			d := c.Domains["example.jp"]
			if d.PrivateKeySigner == nil || !reflect.DeepEqual(d.PrivateKeySigner.Public(), tc.key.Public()) {
				t.Fatal("loaded signer does not match configured key")
			}
			if c.Path != path || d.Domain != "example.jp" || d.Pattern != "example.jp" || !d.DKIM || !d.ARC {
				t.Fatal("loaded configuration lost its path or domain settings")
			}
			if d.HeaderCanonicalization != "relaxed" || d.BodyCanonicalization != "relaxed" || d.HashAlgo != crypto.SHA256 || d.Selector != "default" || d.ARCSelector != "default" {
				t.Fatalf("unexpected signing defaults: %+v", d)
			}
			if c.MilterListen.Mode != 0600 || c.ControlSocketFile.Mode != 0600 || c.LogFile.Mode != 0600 {
				t.Fatal("unexpected default file modes")
			}
			for _, tc := range []struct {
				ip   string
				want bool
			}{
				{"127.0.0.1", true}, {"127.255.255.255", true}, {"128.0.0.1", false},
				{"::1", true}, {"::2", false}, {"invalid", false},
			} {
				if got := c.IsMyNetwork(net.ParseIP(tc.ip)); got != tc.want {
					t.Errorf("IsMyNetwork(%q)=%v, want %v", tc.ip, got, tc.want)
				}
			}
		})
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeConfigFixture(t, "private.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	for _, tc := range []struct {
		name, old, replacement, field string
	}{
		{"malformed YAML", "MilterListen:", "MilterListen: [", ""},
		{"invalid network", "Network: unix", "Network: udp", ""},
		{"missing address", "Address: /tmp/arcmilter.sock", "Address: ''", "MilterListen.Address"},
		{"missing PID file", "Path: /tmp/arcmilter.pid", "Path: ''", "PIDFile.Path"},
		{"missing control socket", "Path: /tmp/arcmilterctl.sock", "Path: ''", "ControlSocketFile.Path"},
		{"missing networks", "MyNetworks:\n  - 127.0.0.0/8\n  - \"::1/128\"", "MyNetworks: []", "MyNetworks"},
		{"invalid CIDR", "127.0.0.0/8", "127.0.0.1/99", ""},
		{"missing domains", "Domains:\n  example.jp:\n    PrivateKeyFile: \"missing.key\"\n    DKIM: true\n    ARC: true", "Domains: {}", "Domains"},
		{"invalid header canonicalization", "DKIM: true", "DKIM: true\n    HeaderCanonicalization: invalid", "Domains[example.jp].HeaderCanonicalization"},
		{"invalid body canonicalization", "DKIM: true", "DKIM: true\n    BodyCanonicalization: invalid", "Domains[example.jp].BodyCanonicalization"},
		{"invalid hash", "DKIM: true", "DKIM: true\n    HashAlgorithm: md5", "Domains[example.jp].HashAlgorithm"},
		{"missing DKIM headers", "DKIMSignHeaders: [From, Subject]", "DKIMSignHeaders: []", "DKIMSignHeaders"},
		{"missing ARC headers", "ARCSignHeaders: [From, Subject]", "ARCSignHeaders: []", "ARCSignHeaders"},
		{"missing ARC From", "ARCSignHeaders: [From, Subject]", "ARCSignHeaders: [Subject]", "ARCSignHeaders"},
		{"unknown owner", "Network: unix", "Network: unix\n  Owner: arcmilter-test-nonexistent-user", ""},
		{"unknown group", "Network: unix", "Network: unix\n  Group: arcmilter-test-nonexistent-group", ""},
		{"unknown process user", "MyNetworks:", "User: arcmilter-test-nonexistent-user\nMyNetworks:", ""},
		{"unknown process group", "MyNetworks:", "Group: arcmilter-test-nonexistent-group\nMyNetworks:", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := validConfigYAML("missing.key")
			if !strings.Contains(raw, tc.old) {
				t.Fatal("test fixture replacement did not match")
			}
			raw = strings.Replace(raw, tc.old, tc.replacement, 1)
			// 検証漏れが鍵ファイルの別エラーで隠れないよう、有効な鍵を使う。
			raw = strings.Replace(raw, `"missing.key"`, fmt.Sprintf("%q", keyPath), 1)
			path := writeConfigFixture(t, "config.yaml", []byte(raw))
			c, err := Load(path)
			if err == nil || c != nil {
				t.Fatalf("expected rejected configuration, got %v, %v", c, err)
			}
			if tc.field != "" {
				var configError *ConfigError
				if !errors.As(err, &configError) || configError.Field != tc.field {
					t.Fatalf("expected field %s, got %v", tc.field, err)
				}
				if !strings.Contains(err.Error(), tc.field) {
					t.Fatalf("error does not identify the field: %v", err)
				}
			}
		})
	}
	if c, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); c != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing config: got %v, %v", c, err)
	}
}

func TestLoadRejectsInvalidKeys(t *testing.T) {
	unsupported, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unsupportedDER, err := x509.MarshalPKCS8PrivateKey(unsupported)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		data    []byte
		message string
	}{
		{"missing file", nil, "no such file"},
		{"not PEM", []byte("not a private key"), "failed to decode pem"},
		{"broken PKCS1", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("broken")}), ""},
		{"broken PKCS8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("broken")}), ""},
		{"unsupported PEM type", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("public")}), "unknown key type"},
		{"unsupported private key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: unsupportedDER}), "unknown key type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "private.key")
			if tc.data != nil {
				if err := os.WriteFile(keyPath, tc.data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			path := writeConfigFixture(t, "config.yaml", []byte(validConfigYAML(keyPath)))
			c, err := Load(path)
			if err == nil || c != nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("expected key error containing %q, got %v, %v", tc.message, c, err)
			}
		})
	}
}
