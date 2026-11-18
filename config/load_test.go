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
	"math/big"
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

func TestLoadRejectsUnsafePrivateKeyFiles(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeConfigFixture(t, "private.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	confPath := writeConfigFixture(t, "config.yaml", []byte(validConfigYAML(keyPath)))
	if _, err := Load(confPath); err != nil {
		t.Fatalf("private key with mode 0600 was rejected: %v", err)
	}
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(confPath); err == nil || !strings.Contains(err.Error(), "owner-only read access") {
		t.Fatalf("world-readable private key was accepted: %v", err)
	}
	if err := os.Chmod(keyPath, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked.key")
	if err := os.Symlink(keyPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustedPrivateKeyFile(link); err == nil {
		t.Fatal("symlink private key was accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keyPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustedPrivateKeyFile(keyPath); err == nil {
		t.Fatal("multiply linked private key was accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	large := writeConfigFixture(t, "large.key", make([]byte, (1<<20)+1))
	if _, err := readTrustedPrivateKeyFile(large); err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Fatalf("oversized private key was accepted: %v", err)
	}
	unsafeParent := filepath.Join(t.TempDir(), "writable")
	if err := os.Mkdir(unsafeParent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeParent, 0777); err != nil {
		t.Fatal(err)
	}
	unsafeKey := filepath.Join(unsafeParent, "private.key")
	if err := os.WriteFile(unsafeKey, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustedPrivateKeyFile(unsafeKey); err == nil {
		t.Fatal("private key under replaceable parent was accepted")
	}
}

func TestLoadRejectsUntrustedConfigurationPaths(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.yaml")
	if err := os.WriteFile(valid, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustedConfigFile(link); err == nil {
		t.Fatal("symlink configuration was accepted")
	}
	hardlink := filepath.Join(dir, "hardlink.yaml")
	if err := os.Link(valid, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustedConfigFile(hardlink); err == nil {
		t.Fatal("multiply-linked configuration was accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(valid, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustedConfigFile(valid); err == nil {
		t.Fatal("group/world-writable configuration was accepted")
	}
	if err := os.Chmod(valid, 0644); err != nil {
		t.Fatal(err)
	}
	if got, err := readTrustedConfigFile(valid); err != nil || string(got) != "preserve" {
		t.Fatalf("safe mode 0644 failed: %q, %v", got, err)
	}

	unsafe := filepath.Join(dir, "writable")
	if err := os.Mkdir(unsafe, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	unsafeConfig := filepath.Join(unsafe, "config.yaml")
	if err := os.WriteFile(unsafeConfig, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustedConfigFile(unsafeConfig); err == nil {
		t.Fatal("configuration in writable directory was accepted")
	}

	large := filepath.Join(dir, "large.yaml")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", (4<<20)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrustedConfigFile(large); err == nil {
		t.Fatal("oversized configuration was accepted")
	}
}

func generateRSAKeyWithExponent(t *testing.T, bits, exponent int) *rsa.PrivateKey {
	t.Helper()
	e := big.NewInt(int64(exponent))
	for {
		p, err := rand.Prime(rand.Reader, bits/2)
		if err != nil {
			t.Fatal(err)
		}
		q, err := rand.Prime(rand.Reader, bits-bits/2)
		if err != nil {
			t.Fatal(err)
		}
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != bits {
			continue
		}
		phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}
		key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: exponent}, D: d, Primes: []*big.Int{p, q}}
		if key.Validate() == nil {
			return key
		}
	}
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

func TestLoadRejectsDKIM2RSAParameters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		bits     int
		exponent int
	}{
		{"weak modulus", 512, 65537},
		{"nonstandard exponent", 1024, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := generateRSAKeyWithExponent(t, tc.bits, tc.exponent)
			keyPath := writeConfigFixture(t, "private.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
			raw := strings.Replace(validConfigYAML(keyPath), "    DKIM: true\n", "    DKIM: true\n    DKIM2: true\n", 1)
			c, err := Load(writeConfigFixture(t, "config.yaml", []byte(raw)))
			var configError *ConfigError
			if c != nil || !errors.As(err, &configError) || configError.Field != "Domains[example.jp].PrivateKeyFile" {
				t.Fatalf("invalid DKIM2 RSA parameters accepted: config=%v err=%v", c, err)
			}
		})
	}
}

func TestLoadMilterPeerPolicy(t *testing.T) {
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
		name, peers string
		allowed     []string
		denied      []string
	}{
		{"loopback default", "", []string{"127.0.0.1", "::1"}, []string{"192.0.2.1", "::2"}},
		{"explicit host and CIDR", "  AllowedPeers:\n    - 192.0.2.10\n    - 2001:db8::/64\n", []string{"192.0.2.10", "2001:db8::1"}, []string{"127.0.0.1", "192.0.2.11"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(validConfigYAML(keyPath), "  Network: unix\n  Address: /tmp/arcmilter.sock\n", "  Network: tcp\n  Address: 127.0.0.1:10029\n  AllowTCPWithSigning: true\n"+tc.peers, 1)
			c, err := Load(writeConfigFixture(t, "config.yaml", []byte(raw)))
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range tc.allowed {
				if !c.IsAllowedMilterPeer(net.ParseIP(value)) {
					t.Errorf("expected peer %s to be allowed", value)
				}
			}
			for _, value := range tc.denied {
				if c.IsAllowedMilterPeer(net.ParseIP(value)) {
					t.Errorf("expected peer %s to be denied", value)
				}
			}
			if c.IsAllowedMilterPeer(nil) {
				t.Error("nil peer was allowed")
			}
		})
	}
}

func TestLoadRequiresExplicitTCPSigningPolicy(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeConfigFixture(t, "private.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	base := validConfigYAML(keyPath)
	tcp := strings.Replace(base, "  Network: unix\n  Address: /tmp/arcmilter.sock\n",
		"  Network: tcp\n  Address: 127.0.0.1:10029\n", 1)
	if _, err := Load(writeConfigFixture(t, "tcp.yaml", []byte(tcp))); err == nil ||
		!strings.Contains(err.Error(), "MilterListen.AllowTCPWithSigning") {
		t.Fatalf("TCP signing was accepted without explicit policy: %v", err)
	}
	tcp = strings.Replace(tcp, "  Network: tcp\n", "  Network: tcp\n  AllowTCPWithSigning: true\n", 1)
	if _, err := Load(writeConfigFixture(t, "tcp-allowed.yaml", []byte(tcp))); err != nil {
		t.Fatalf("explicit TCP signing policy was rejected: %v", err)
	}
	unix := strings.Replace(base, "  Network: unix\n", "  Network: unix\n  AllowTCPWithSigning: true\n", 1)
	if _, err := Load(writeConfigFixture(t, "unix.yaml", []byte(unix))); err == nil ||
		!strings.Contains(err.Error(), "MilterListen.AllowTCPWithSigning") {
		t.Fatalf("TCP-only policy was accepted on a Unix socket: %v", err)
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
		{"unknown field", "MilterListen:", "UnknownSecuritySetting: true\nMilterListen:", ""},
		{"invalid network", "Network: unix", "Network: udp", ""},
		{"invalid allowed peer", "Network: unix", "Network: tcp\n  AllowedPeers: [not-an-ip]", ""},
		{"allowed peers on unix", "Network: unix", "Network: unix\n  AllowedPeers: [127.0.0.1]", "MilterListen.AllowedPeers"},
		{"world-accessible milter socket", "Network: unix", "Network: unix\n  Mode: 0666", "MilterListen.Mode"},
		{"world-accessible control socket", "Path: /tmp/arcmilterctl.sock", "Path: /tmp/arcmilterctl.sock\n  Mode: 0666", "ControlSocketFile.Mode"},
		{"world-writable log file", "ControlSocketFile:", "LogFile:\n  Mode: 0666\nControlSocketFile:", "LogFile.Mode"},
		{"unwritable log file", "ControlSocketFile:", "LogFile:\n  Mode: 0400\nControlSocketFile:", "LogFile.Mode"},
		{"negative max connections", "Network: unix", "Network: unix\n  MaxConnections: -1", "MilterListen.MaxConnections"},
		{"excessive max connections", "Network: unix", "Network: unix\n  MaxConnections: 4097", "MilterListen.MaxConnections"},
		{"missing address", "Address: /tmp/arcmilter.sock", "Address: ''", "MilterListen.Address"},
		{"missing PID file", "Path: /tmp/arcmilter.pid", "Path: ''", "PIDFile.Path"},
		{"missing control socket", "Path: /tmp/arcmilterctl.sock", "Path: ''", "ControlSocketFile.Path"},
		{"missing networks", "MyNetworks:\n  - 127.0.0.0/8\n  - \"::1/128\"", "MyNetworks: []", "MyNetworks"},
		{"invalid CIDR", "127.0.0.0/8", "127.0.0.1/99", ""},
		{"missing domains", "Domains:\n  example.jp:\n    PrivateKeyFile: \"missing.key\"\n    DKIM: true\n    ARC: true", "Domains: {}", "Domains"},
		{"invalid header canonicalization", "DKIM: true", "DKIM: true\n    HeaderCanonicalization: invalid", "Domains[example.jp].HeaderCanonicalization"},
		{"invalid body canonicalization", "DKIM: true", "DKIM: true\n    BodyCanonicalization: invalid", "Domains[example.jp].BodyCanonicalization"},
		{"invalid hash", "DKIM: true", "DKIM: true\n    HashAlgorithm: md5", "Domains[example.jp].HashAlgorithm"},
		{"negative DKIM2 limit", "MilterListen:", "DKIM2MaxMessageBytes: -1\nMilterListen:", "DKIM2MaxMessageBytes"},
		{"excessive DKIM2 limit", "MilterListen:", "DKIM2MaxMessageBytes: 33554433\nMilterListen:", "DKIM2MaxMessageBytes"},
		{"invalid DKIM2 selector", "    DKIM: true", "    DKIM: true\n    DKIM2: true\n    DKIM2Selector: invalid_selector", "Domains[example.jp].DKIM2Selector"},
		{"Unicode DKIM2 selector", "    DKIM: true", "    DKIM: true\n    DKIM2: true\n    DKIM2Selector: bücher", "Domains[example.jp].DKIM2Selector"},
		{"empty DKIM2 selector label", "    DKIM: true", "    DKIM: true\n    DKIM2: true\n    DKIM2Selector: one..two", "Domains[example.jp].DKIM2Selector"},
		{"leading hyphen in DKIM2 selector", "    DKIM: true", "    DKIM: true\n    DKIM2: true\n    DKIM2Selector: -selector", "Domains[example.jp].DKIM2Selector"},
		{"invalid DKIM2 A-label domain", "  example.jp:\n    PrivateKeyFile", "  \"xn--0.example\":\n    DKIM2: true\n    PrivateKeyFile", "Domains[xn--0.example]"},
		{"invalid forwarding mode", "MilterListen:", "DKIM2Forwarding:\n  Mode: forward\nMilterListen:", "DKIM2Forwarding.Mode"},
		{"missing receive store", "MilterListen:", "DKIM2Forwarding:\n  Mode: receive\nMilterListen:", "DKIM2Forwarding.StoreDirectory"},
		{"missing send store", "MilterListen:", "DKIM2Forwarding:\n  Mode: send\nMilterListen:", "DKIM2Forwarding.StoreDirectory"},
		{"relative forwarding store", "MilterListen:", "DKIM2Forwarding:\n  Mode: receive\n  StoreDirectory: spool/dkim2\nMilterListen:", "DKIM2Forwarding.StoreDirectory"},
		{"missing forwarding recipients", "MilterListen:", "DKIM2Forwarding:\n  Mode: receive\n  StoreDirectory: /tmp/dkim2\nMilterListen:", "DKIM2Forwarding.ForwardRecipients"},
		{"invalid forwarding recipient A-label", "MilterListen:", "DKIM2Forwarding:\n  Mode: receive\n  StoreDirectory: /tmp/dkim2\n  ForwardRecipients: [forward@xn--0.example]\nMilterListen:", "DKIM2Forwarding.ForwardRecipients"},
		{"oversized forwarding recipient policy", "MilterListen:", "DKIM2Forwarding:\n  Mode: receive\n  StoreDirectory: /tmp/dkim2\n  ForwardRecipients: [\"" + strings.Repeat("a", MaxDKIM2ForwardRecipientQuotaBytes) + "@example.jp\"]\nMilterListen:", "DKIM2Forwarding.ForwardRecipients"},
		{"negative forwarding age", "MilterListen:", "DKIM2Forwarding:\n  MaxAgeSeconds: -1\nMilterListen:", "DKIM2Forwarding.MaxAgeSeconds"},
		{"invalid forwarding cache failure action", "MilterListen:", "DKIM2Forwarding:\n  CacheFailureAction: accept\nMilterListen:", "DKIM2Forwarding.CacheFailureAction"},
		{"excessive forwarding age", "MilterListen:", "DKIM2Forwarding:\n  MaxAgeSeconds: 1209601\nMilterListen:", "DKIM2Forwarding.MaxAgeSeconds"},
		{"negative forwarding capacity", "MilterListen:", "DKIM2Forwarding:\n  MaxStoredBytes: -1\nMilterListen:", "DKIM2Forwarding.MaxStoredBytes"},
		{"negative per-recipient capacity", "MilterListen:", "DKIM2Forwarding:\n  MaxStoredBytesPerRecipient: -1\nMilterListen:", "DKIM2Forwarding.MaxStoredBytesPerRecipient"},
		{"per-recipient capacity exceeds total", "MilterListen:", "DKIM2Forwarding:\n  MaxStoredBytes: 1024\n  MaxStoredBytesPerRecipient: 2048\nMilterListen:", "DKIM2Forwarding.MaxStoredBytesPerRecipient"},
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

func TestLoadRequiresSingleYAMLDocument(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeConfigFixture(t, "private.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	base := validConfigYAML(keyPath)
	for _, tc := range []struct {
		name, raw string
		wantError bool
	}{
		{"single document", base, false},
		{"explicit document markers", "---\n" + base + "...\n", false},
		{"trailing comment", base + "# end of configuration\n", false},
		{"second settings document", base + "---\nEnableDKIM2: true\n", true},
		{"unknown field in second document", base + "---\nUnknownSecuritySetting: true\n", true},
		{"malformed second document", base + "---\nMilterListen: [\n", true},
		{"empty second document", base + "---\n# empty document\n", true},
		{"empty first document", "---\n---\n" + base, true},
		{"empty file", "", true},
		{"empty document", "---\n...\n", true},
		{"null document", "null\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load(writeConfigFixture(t, "config.yaml", []byte(tc.raw)))
			if tc.wantError {
				if err == nil || c != nil {
					t.Fatalf("expected rejected YAML document stream, got config=%v err=%v", c, err)
				}
				return
			}
			if err != nil || c == nil {
				t.Fatalf("single document rejected: config=%v err=%v", c, err)
			}
		})
	}
}

func TestLoadDKIM2Configuration(t *testing.T) {
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
		name, global, domain string
		verify, sign         bool
		limit                int64
		selector             string
	}{
		{"omitted", "", "", false, false, DefaultDKIM2MaxMessageBytes, "default"},
		{"enabled", "EnableDKIM2: true\n", "    DKIM2: true\n", true, true, DefaultDKIM2MaxMessageBytes, "default"},
		{"verification only", "EnableDKIM2: true\n", "    DKIM2: false\n", true, false, DefaultDKIM2MaxMessageBytes, "default"},
		{"signing only", "EnableDKIM2: false\n", "    DKIM2: true\n", false, true, DefaultDKIM2MaxMessageBytes, "default"},
		{"disabled", "EnableDKIM2: false\n", "    DKIM2: false\n", false, false, DefaultDKIM2MaxMessageBytes, "default"},
		{"zero limit", "DKIM2MaxMessageBytes: 0\n", "", false, false, DefaultDKIM2MaxMessageBytes, "default"},
		{"custom limit", "EnableDKIM2: true\nDKIM2MaxMessageBytes: 1048576\n", "", true, false, 1048576, "default"},
		{"maximum limit", "DKIM2MaxMessageBytes: 33554432\n", "", false, false, DefaultDKIM2MaxMessageBytes, "default"},
		{"inherited selector", "", "    Selector: shared\n    DKIM2: true\n", false, true, DefaultDKIM2MaxMessageBytes, "shared"},
		{"separate selector", "", "    Selector: shared\n    DKIM2: true\n    DKIM2Selector: dkim2\n", false, true, DefaultDKIM2MaxMessageBytes, "dkim2"},
		{"ASCII selector with double hyphen", "", "    DKIM2: true\n    DKIM2Selector: ab--selector\n", false, true, DefaultDKIM2MaxMessageBytes, "ab--selector"},
		{"ASCII selector resembling an A-label", "", "    DKIM2: true\n    DKIM2Selector: xn--0\n", false, true, DefaultDKIM2MaxMessageBytes, "xn--0"},
		{"inherited ASCII selector with double hyphen", "", "    Selector: ab--selector\n    DKIM2: true\n", false, true, DefaultDKIM2MaxMessageBytes, "ab--selector"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.global + strings.Replace(validConfigYAML(keyPath), "    DKIM: true\n", tc.domain+"    DKIM: true\n", 1)
			path := writeConfigFixture(t, "config.yaml", []byte(raw))
			c, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			d := c.Domains["example.jp"]
			if c.EnableDKIM2 != tc.verify || d.DKIM2 != tc.sign || c.DKIM2MaxMessageBytes != tc.limit || d.DKIM2Selector != tc.selector {
				t.Fatalf("DKIM2 configuration: verify=%v sign=%v limit=%d selector=%q", c.EnableDKIM2, d.DKIM2, c.DKIM2MaxMessageBytes, d.DKIM2Selector)
			}
			wantConnections := DefaultMilterMaxConnections
			if tc.verify || tc.sign {
				wantConnections = DefaultDKIM2MilterMaxConnections
			}
			if c.MilterListen.MaxConnections != wantConnections {
				t.Fatalf("MaxConnections=%d, want %d", c.MilterListen.MaxConnections, wantConnections)
			}
			if !reflect.DeepEqual(d.PrivateKeySigner.Public(), key.Public()) {
				t.Fatal("DKIM2 changed the configured signing key")
			}
		})
	}
}

func TestLoadDKIM2ForwardingConfiguration(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeConfigFixture(t, "private.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	store := filepath.Join(t.TempDir(), "dkim2")
	for _, tc := range []struct {
		name, settings string
		mode           string
		hasStore       bool
		age, capacity  int64
		multiple       bool
	}{
		{"omitted", "", "disabled", false, DefaultDKIM2ForwardingMaxAgeSeconds, DefaultDKIM2ForwardingMaxStoredBytes, false},
		{"empty", "DKIM2Forwarding: {}\n", "disabled", false, DefaultDKIM2ForwardingMaxAgeSeconds, DefaultDKIM2ForwardingMaxStoredBytes, false},
		{"disabled", "DKIM2Forwarding:\n  Mode: disabled\n", "disabled", false, DefaultDKIM2ForwardingMaxAgeSeconds, DefaultDKIM2ForwardingMaxStoredBytes, false},
		{"receive defaults", "DKIM2Forwarding:\n  Mode: receive\n  StoreDirectory: %q\n  ForwardRecipients:\n    - forward@example.jp\n", "receive", true, DefaultDKIM2ForwardingMaxAgeSeconds, DefaultDKIM2ForwardingMaxStoredBytes, false},
		{"send defaults", "DKIM2Forwarding:\n  Mode: send\n  StoreDirectory: %q\n", "send", true, DefaultDKIM2ForwardingMaxAgeSeconds, DefaultDKIM2ForwardingMaxStoredBytes, false},
		{"explicit zeros", "DKIM2Forwarding:\n  Mode: receive\n  StoreDirectory: %q\n  ForwardRecipients:\n    - forward@example.jp\n  MaxAgeSeconds: 0\n  MaxStoredBytes: 0\n", "receive", true, DefaultDKIM2ForwardingMaxAgeSeconds, DefaultDKIM2ForwardingMaxStoredBytes, false},
		{"minimum limits", "DKIM2Forwarding:\n  Mode: send\n  StoreDirectory: %q\n  MaxAgeSeconds: 1\n  MaxStoredBytes: 1\n", "send", true, 1, 1, false},
		{"maximum age", "DKIM2Forwarding:\n  Mode: receive\n  StoreDirectory: %q\n  ForwardRecipients:\n    - forward@example.jp\n  MaxAgeSeconds: 1209600\n  MaxStoredBytes: 2147483648\n", "receive", true, MaxDKIM2ForwardingMaxAgeSeconds, 2147483648, false},
		{"multiple deliveries", "DKIM2Forwarding:\n  Mode: send\n  StoreDirectory: %q\n  MultipleDeliveries: true\n", "send", true, DefaultDKIM2ForwardingMaxAgeSeconds, DefaultDKIM2ForwardingMaxStoredBytes, true},
		{"recipe disclosure opt-in", "DKIM2Forwarding:\n  Mode: send\n  StoreDirectory: %q\n  AllowRecipeDisclosure: true\n", "send", true, DefaultDKIM2ForwardingMaxAgeSeconds, DefaultDKIM2ForwardingMaxStoredBytes, false},
		{"per-recipient quota", "DKIM2Forwarding:\n  Mode: send\n  StoreDirectory: %q\n  MaxStoredBytesPerRecipient: 134217728\n", "send", true, DefaultDKIM2ForwardingMaxAgeSeconds, DefaultDKIM2ForwardingMaxStoredBytes, false},
		{"explicit skip signing", "DKIM2Forwarding:\n  Mode: send\n  StoreDirectory: %q\n  CacheFailureAction: skip-signing\n", "send", true, DefaultDKIM2ForwardingMaxAgeSeconds, DefaultDKIM2ForwardingMaxStoredBytes, false},
		{"strict cache failures", "DKIM2Forwarding:\n  Mode: send\n  StoreDirectory: %q\n  CacheFailureAction: tempfail\n", "send", true, DefaultDKIM2ForwardingMaxAgeSeconds, DefaultDKIM2ForwardingMaxStoredBytes, false},
		{"empty cache failure action", "DKIM2Forwarding:\n  Mode: send\n  StoreDirectory: %q\n  CacheFailureAction: ''\n", "send", true, DefaultDKIM2ForwardingMaxAgeSeconds, DefaultDKIM2ForwardingMaxStoredBytes, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := tc.settings
			if tc.hasStore {
				settings = fmt.Sprintf(settings, store)
			}
			path := writeConfigFixture(t, "config.yaml", []byte(settings+validConfigYAML(keyPath)))
			c, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			wantStore := ""
			if tc.hasStore {
				wantStore = store
			}
			got := c.DKIM2Forwarding
			if !strings.Contains(tc.settings, "MaxAgeSeconds:") && got.MaxAgeSeconds != 86400 {
				t.Fatalf("default MaxAgeSeconds=%d, want 86400", got.MaxAgeSeconds)
			}
			wantCacheFailureAction := "skip-signing"
			if strings.Contains(tc.settings, "CacheFailureAction: tempfail") {
				wantCacheFailureAction = "tempfail"
			}
			if got.CacheFailureAction != wantCacheFailureAction {
				t.Fatalf("CacheFailureAction=%q, want %q", got.CacheFailureAction, wantCacheFailureAction)
			}
			if got.Mode != tc.mode || got.StoreDirectory != wantStore || got.SigningDomain != "" || got.MaxAgeSeconds != tc.age || got.MaxStoredBytes != tc.capacity || got.MultipleDeliveries != tc.multiple {
				t.Fatalf("DKIM2 forwarding configuration: %+v", got)
			}
			wantPerRecipient := min(DefaultDKIM2ForwardingMaxStoredBytesPerRecipient, tc.capacity)
			if len(got.ForwardRecipients) > 1 {
				wantPerRecipient = min(wantPerRecipient, max(int64(1), tc.capacity/int64(len(got.ForwardRecipients))))
			}
			if strings.Contains(tc.settings, "MaxStoredBytesPerRecipient: 134217728") {
				wantPerRecipient = 134217728
			}
			if got.MaxStoredBytesPerRecipient != wantPerRecipient {
				t.Fatalf("MaxStoredBytesPerRecipient=%d, want %d", got.MaxStoredBytesPerRecipient, wantPerRecipient)
			}
			wantRecipients := []string(nil)
			if tc.mode == "receive" {
				wantRecipients = []string{"forward@example.jp"}
			}
			if !reflect.DeepEqual(got.ForwardRecipients, wantRecipients) || got.AllowRecipeDisclosure != strings.Contains(tc.settings, "AllowRecipeDisclosure: true") {
				t.Fatalf("DKIM2 forwarding security configuration: %+v", got)
			}
			wantConnections := DefaultMilterMaxConnections
			if tc.mode != "disabled" {
				wantConnections = DefaultDKIM2MilterMaxConnections
			}
			if c.MilterListen.MaxConnections != wantConnections {
				t.Fatalf("MaxConnections=%d, want %d", c.MilterListen.MaxConnections, wantConnections)
			}
		})
	}
}

func TestLoadDKIM2ForwardingSigningDomain(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeConfigFixture(t, "private.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	store := filepath.Join(t.TempDir(), "dkim2")
	for _, tc := range []struct {
		name, domain, pattern, mode, want string
		enabled, invalid                  bool
	}{
		{"omitted", "", "example.jp", "send", "", false, false},
		{"explicit", "example.jp", "example.jp", "send", "example.jp", true, false},
		{"case insensitive", "EXAMPLE.JP", "example.jp", "send", "example.jp", true, false},
		{"uppercase configuration key", "EXAMPLE.JP", "EXAMPLE.JP", "send", "example.jp", true, false},
		{"wildcard", "Mail.Example.JP", "*.example.jp", "send", "mail.example.jp", true, false},
		{"uppercase wildcard", "Mail.Example.JP", "*.EXAMPLE.JP", "send", "mail.example.jp", true, false},
		{"uppercase list", "Mail.Example.JP", "LIST:EXAMPLE.JP,Mail.Example.JP", "send", "mail.example.jp", true, false},
		{"disabled target", "example.jp", "example.jp", "send", "", false, true},
		{"missing target", "outside.example", "example.jp", "send", "", true, true},
		{"receive does not select signer", "outside.example", "example.jp", "receive", "outside.example", false, false},
		{"wildcard is not a signing name", "*.example.jp", "*.example.jp", "send", "", true, true},
		{"address is not a signing name", "bounce@example.jp", "example.jp", "send", "", true, true},
		{"empty label", "mail..example.jp", "*.example.jp", "send", "", true, true},
		{"leading hyphen", "-mail.example.jp", "*.example.jp", "send", "", true, true},
		{"trailing hyphen", "mail-.example.jp", "*.example.jp", "send", "", true, true},
		{"whitespace", " example.jp", "example.jp", "send", "", true, true},
		{"long label", strings.Repeat("a", 64) + ".example.jp", "*.example.jp", "send", "", true, true},
		{"Unicode requires A-label", "bücher.example.jp", "*.example.jp", "send", "", true, true},
		{"A-label", "xn--bcher-kva.example.jp", "*.example.jp", "send", "xn--bcher-kva.example.jp", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := validConfigYAML(keyPath)
			raw = strings.Replace(raw, "  example.jp:\n", "  "+fmt.Sprintf("%q", tc.pattern)+":\n", 1)
			raw = strings.Replace(raw, "    DKIM: true\n", fmt.Sprintf("    DKIM2: %t\n    DKIM: true\n", tc.enabled), 1)
			forwardRecipients := ""
			if tc.mode == "receive" {
				forwardRecipients = "  ForwardRecipients:\n    - forward@example.jp\n"
			}
			raw = fmt.Sprintf("DKIM2Forwarding:\n  Mode: %s\n  StoreDirectory: %q\n  SigningDomain: %q\n%s", tc.mode, store, tc.domain, forwardRecipients) + raw
			c, err := Load(writeConfigFixture(t, "config.yaml", []byte(raw)))
			if tc.invalid {
				var configError *ConfigError
				if c != nil || !errors.As(err, &configError) || configError.Field != "DKIM2Forwarding.SigningDomain" {
					t.Fatalf("expected SigningDomain configuration error, got %v, %v", c, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.DKIM2Forwarding.SigningDomain != tc.want {
				t.Fatalf("SigningDomain=%q, want %q", c.DKIM2Forwarding.SigningDomain, tc.want)
			}
		})
	}
}

func TestLoadDomainCaseDuplicates(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeConfigFixture(t, "private.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	for _, pattern := range []string{"EXAMPLE.JP", "list:EXAMPLE.JP,other.example", "list:example.jp,EXAMPLE.JP"} {
		t.Run(pattern, func(t *testing.T) {
			extra := fmt.Sprintf("Domains:\n  %q:\n    PrivateKeyFile: %q\n    DKIM: true\n", pattern, keyPath)
			raw := strings.Replace(validConfigYAML(keyPath), "Domains:\n", extra, 1)
			c, err := Load(writeConfigFixture(t, "config.yaml", []byte(raw)))
			var configError *ConfigError
			if c != nil || !errors.As(err, &configError) || configError.Field != "Domains" {
				t.Fatalf("expected case-duplicate domain error, got %v, %v", c, err)
			}
		})
	}
	// 同一表記のlist/個別指定では、従来の個別指定優先を維持する。
	extra := fmt.Sprintf("Domains:\n  %q:\n    PrivateKeyFile: %q\n    Selector: list\n", "list:example.jp,other.example", keyPath)
	raw := strings.Replace(validConfigYAML(keyPath), "Domains:\n", extra, 1)
	c, err := Load(writeConfigFixture(t, "config.yaml", []byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Domains["example.jp"].Selector != "default" || c.Domains["other.example"].Selector != "list" {
		t.Fatalf("list/exact precedence changed: %+v", c.Domains)
	}
}

func TestGetMatchingDomainIgnoresDNSCase(t *testing.T) {
	c := &Config{Domains: map[string]Domain{
		"EXAMPLE.JP":       {Domain: "EXAMPLE.JP", Selector: "exact"},
		"*.EXAMPLE.JP":     {Selector: "wildcard"},
		"*.Sub.EXAMPLE.JP": {Selector: "deep"},
		"*":                {Selector: "default"},
	}}
	for _, tc := range []struct{ domain, selector string }{
		{"example.jp", "exact"}, {"EXAMPLE.JP", "exact"},
		{"Mail.EXAMPLE.JP", "wildcard"}, {"Mail.Sub.Example.JP", "deep"},
		{"else.EXAMPLE", "default"},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			domain, ok := c.GetMatchingDomain(tc.domain)
			if !ok || domain.Selector != tc.selector || domain.Domain != strings.ToLower(tc.domain) {
				t.Fatalf("domain lookup: %+v, %v", domain, ok)
			}
		})
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
