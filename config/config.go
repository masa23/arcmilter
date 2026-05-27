package config

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultHeaderCanonicalization = "relaxed"
	DefaultBodyCanonicalization   = "relaxed"
	DefaultHashAlgorithm          = "sha256"
	DefaultSelector               = "default"
)

type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type Config struct {
	Path    string
	LogFd   *os.File
	PidFile struct {
		Path string `yaml:"Path"`
	} `yaml:"PIDFile"`
	MilterListen struct {
		Network string `yaml:"Network"`
		Address string `yaml:"Address"`
		Mode    uint32 `yaml:"Mode"`
		Owner   string `yaml:"Owner"`
		Group   string `yaml:"Group"`
		Uid     int
		Gid     int
	} `yaml:"MilterListen"`
	ControlSocketFile struct {
		Path string `yaml:"Path"`
		Mode uint32 `yaml:"Mode"`
	} `yaml:"ControlSocketFile"`
	LogFile struct {
		Path string `yaml:"Path"`
		Mode uint32 `yaml:"Mode"`
	} `yaml:"LogFile"`
	MyNetworks       []string `yaml:"MyNetworks"`
	ParsedMyNetworks []*net.IPNet
	Domains          map[string]Domain `yaml:"Domains"`
	User             string            `yaml:"User"`
	Group            string            `yaml:"Group"`
	Uid              int
	Gid              int
	Debug            bool     `yaml:"Debug"`
	ARCSignHeaders   []string `yaml:"ARCSignHeaders"`
	DKIMSignHeaders  []string `yaml:"DKIMSignHeaders"`
}

type Domain struct {
	HeaderCanonicalization string `yaml:"HeaderCanonicalization"`
	BodyCanonicalization   string `yaml:"BodyCanonicalization"`
	HashAlgorithm          string `yaml:"HashAlgorithm"`
	HashAlgo               crypto.Hash
	PrivateKeyFile         string `yaml:"PrivateKeyFile"`
	PrivateKeySigner       crypto.Signer
	Selector               string `yaml:"Selector"`
	ARCSelector            string `yaml:"ARCSelector"`
	Domain                 string
	Pattern                string // Original pattern from config (e.g., "*.example.com")
	DKIM                   bool   `yaml:"DKIM"`
	ARC                    bool   `yaml:"ARC"`
}

func getUid(userStr string) (int, error) {
	var uidStr string
	if userStr == "" {
		u, err := user.Current()
		if err != nil {
			return 0, err
		}
		uidStr = u.Uid
	} else {
		u, err := user.Lookup(userStr)
		if err != nil {
			return 0, err
		}
		uidStr = u.Uid
	}
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return 0, err
	}
	return uid, nil
}

func getGid(groupStr string) (int, error) {
	var gidStr string
	if groupStr == "" {
		g, err := user.Current()
		if err != nil {
			return 0, err
		}
		gidStr = g.Gid
	} else {
		g, err := user.LookupGroup(groupStr)
		if err != nil {
			return 0, err
		}
		gidStr = g.Gid
	}
	gid, err := strconv.Atoi(gidStr)
	if err != nil {
		return 0, err
	}
	return gid, nil
}

func checkMilterListenNetwork(network string) error {
	switch network {
	case "tcp", "unix":
		return nil
	default:
		return fmt.Errorf("invalid MilterListen.Network: %s", network)
	}
}

func Load(path string) (*Config, error) {
	config := createDefaultConfig()

	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = parseYAML(buf, config)
	if err != nil {
		return nil, err
	}

	err = validateConfig(config)
	if err != nil {
		return nil, err
	}

	err = loadKeys(config)
	if err != nil {
		return nil, err
	}

	config.Path = path
	return config, nil
}

func createDefaultConfig() *Config {
	return &Config{
		MilterListen: struct {
			Network string `yaml:"Network"`
			Address string `yaml:"Address"`
			Mode    uint32 `yaml:"Mode"`
			Owner   string `yaml:"Owner"`
			Group   string `yaml:"Group"`
			Uid     int
			Gid     int
		}{},
		ControlSocketFile: struct {
			Path string `yaml:"Path"`
			Mode uint32 `yaml:"Mode"`
		}{},
		LogFile: struct {
			Path string `yaml:"Path"`
			Mode uint32 `yaml:"Mode"`
		}{},
		Domains:          make(map[string]Domain),
		ParsedMyNetworks: make([]*net.IPNet, 0),
		ARCSignHeaders:   make([]string, 0),
		DKIMSignHeaders:  make([]string, 0),
	}
}

func parseYAML(buf []byte, config *Config) error {
	err := yaml.Unmarshal(buf, config)
	if err != nil {
		return err
	}
	return nil
}

func validateConfig(config *Config) error {
	if err := checkMilterListenNetwork(config.MilterListen.Network); err != nil {
		return err
	}

	if config.MilterListen.Network == "unix" {
		uid, err := getUid(config.MilterListen.Owner)
		if err != nil {
			return err
		}
		config.MilterListen.Uid = uid
		gid, err := getGid(config.MilterListen.Group)
		if err != nil {
			return err
		}
		config.MilterListen.Gid = gid
	}

	if config.MilterListen.Address == "" {
		return &ConfigError{Field: "MilterListen.Address", Message: "is not set"}
	}

	if config.MilterListen.Mode == 0 {
		config.MilterListen.Mode = 0600
	}

	if config.PidFile.Path == "" {
		return &ConfigError{Field: "PIDFile.Path", Message: "is not set"}
	}

	if config.ControlSocketFile.Path == "" {
		return &ConfigError{Field: "ControlSocketFile.Path", Message: "is not set"}
	}

	if config.ControlSocketFile.Mode == 0 {
		config.ControlSocketFile.Mode = 0600
	}

	if config.LogFile.Mode == 0 {
		config.LogFile.Mode = 0600
	}

	if len(config.MyNetworks) == 0 {
		return &ConfigError{Field: "MyNetworks", Message: "is not set"}
	}

	for _, network := range config.MyNetworks {
		_, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			return err
		}
		config.ParsedMyNetworks = append(config.ParsedMyNetworks, ipNet)
	}

	if len(config.Domains) == 0 {
		return &ConfigError{Field: "Domains", Message: "is not set"}
	}

	config.Domains = expandDomains(config.Domains)

	for domain, value := range config.Domains {
		if value.HeaderCanonicalization == "" {
			value.HeaderCanonicalization = DefaultHeaderCanonicalization
		}
		switch value.HeaderCanonicalization {
		case "simple", "relaxed":
		default:
			return &ConfigError{Field: fmt.Sprintf("Domains[%s].HeaderCanonicalization", value.Domain), Message: fmt.Sprintf(`invalid value "%s"`, value.HeaderCanonicalization)}
		}
		if value.BodyCanonicalization == "" {
			value.BodyCanonicalization = DefaultBodyCanonicalization
		}
		switch value.BodyCanonicalization {
		case "simple", "relaxed":
		default:
			return &ConfigError{Field: fmt.Sprintf("Domains[%s].BodyCanonicalization", value.Domain), Message: fmt.Sprintf(`invalid value "%s"`, value.BodyCanonicalization)}
		}

		if value.HashAlgorithm == "" {
			value.HashAlgorithm = DefaultHashAlgorithm
		}
		switch value.HashAlgorithm {
		case "sha1":
			value.HashAlgo = crypto.SHA1
		case "sha256":
			value.HashAlgo = crypto.SHA256
		default:
			return &ConfigError{Field: fmt.Sprintf("Domains[%s].HashAlgorithm", value.Domain), Message: fmt.Sprintf(`invalid value "%s"`, value.HashAlgorithm)}
		}

		if value.Selector == "" {
			value.Selector = DefaultSelector
		}
		if value.ARCSelector == "" {
			value.ARCSelector = value.Selector
		}

		if value.Pattern == "" {
			value.Pattern = domain
		}
		value.Domain = domain

		config.Domains[domain] = value
	}

	uid, err := getUid(config.User)
	if err != nil {
		return err
	}
	config.Uid = uid

	gid, err := getGid(config.Group)
	if err != nil {
		return err
	}
	config.Gid = gid

	if len(config.DKIMSignHeaders) == 0 {
		return &ConfigError{Field: "DKIMSignHeaders", Message: "is not set"}
	}

	if len(config.ARCSignHeaders) == 0 {
		return &ConfigError{Field: "ARCSignHeaders", Message: "is not set"}
	}

	return nil
}

func loadKeys(config *Config) error {
	for domain, value := range config.Domains {
		buf, err := os.ReadFile(value.PrivateKeyFile)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(buf)
		if block == nil {
			return fmt.Errorf("failed to decode pem: %s", value.PrivateKeyFile)
		}

		var priv interface{}
		switch block.Type {
		case "RSA PRIVATE KEY":
			priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return err
			}
		case "PRIVATE KEY":
			priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown key type: %s", block.Type)
		}

		switch key := priv.(type) {
		case *rsa.PrivateKey:
			value.PrivateKeySigner = key
		case ed25519.PrivateKey:
			value.PrivateKeySigner = key
		default:
			return fmt.Errorf("unknown key type: %T", key)
		}

		config.Domains[domain] = value
	}

	return nil
}

// IsMyNetwork は指定された IP アドレスが自分のネットワークに含まれるかを返す
func (c *Config) IsMyNetwork(ip net.IP) bool {
	for _, ipNet := range c.ParsedMyNetworks {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// parseDomainPattern はドメインパターンを解析する
// "example.com" → {isWildcard: false, hostPart: "example.com"}
// "*.example.com" → {isWildcard: true, hostPart: "example.com"}
// "*" → {isWildcard: true, hostPart: ""}
func parseDomainPattern(pattern string) (isWildcard bool, hostPart string) {
	if strings.HasPrefix(pattern, "*.") {
		isWildcard = true
		hostPart = pattern[2:]
	} else if pattern == "*" {
		isWildcard = true
		hostPart = ""
	} else {
		isWildcard = false
		hostPart = pattern
	}
	return
}

// matchDomain はドメインパターンが対象ドメインにマッチするか判定する
func matchDomain(pattern string, domain string) bool {
	isWildcard, hostPart := parseDomainPattern(pattern)

	if !isWildcard {
		return pattern == domain
	}

	if pattern == "*" {
		return true
	}

	return strings.HasSuffix(domain, "."+hostPart) || domain == hostPart
}

// expandDomains は簡略構文 "list:domain1,domain2,*.domain3" を展開する
func expandDomains(domains map[string]Domain) map[string]Domain {
	result := make(map[string]Domain)

	for domainKey, domainConf := range domains {
		if strings.HasPrefix(domainKey, "list:") {
			domainList := strings.Split(domainKey[5:], ",")
			for _, d := range domainList {
				d = strings.TrimSpace(d)
				if d == "" {
					continue
				}
				domainCopy := domainConf
				domainCopy.Domain = d
				domainCopy.Pattern = d
				result[d] = domainCopy
			}
		}
	}

	for domainKey, domainConf := range domains {
		if !strings.HasPrefix(domainKey, "list:") {
			domainConf.Domain = domainKey
			domainConf.Pattern = domainKey
			result[domainKey] = domainConf
		}
	}

	return result
}

// GetMatchingDomain は対象ドメインに最もマッチするドメイン設定を返す
// 優先順位：完全一致 → ワイルドカード一致（より限定的なもの優先） → デフォルト(*)
// 返される Domain の Domain フィールドは、マッチした実際のドメイン名に設定される
func (c *Config) GetMatchingDomain(domain string) (*Domain, bool) {
	if d, ok := c.Domains[domain]; ok {
		return &d, true
	}

	bestMatchKey := ""
	bestMatchLen := 0

	for pattern := range c.Domains {
		if pattern == "*" {
			continue
		}
		if matchDomain(pattern, domain) {
			_, hostPart := parseDomainPattern(pattern)
			matchLen := len(hostPart)
			if matchLen > bestMatchLen {
				bestMatchKey = pattern
				bestMatchLen = matchLen
			}
		}
	}

	if bestMatchKey != "" {
		if d, ok := c.Domains[bestMatchKey]; ok {
			d.Domain = domain
			return &d, true
		}
	}

	if d, ok := c.Domains["*"]; ok {
		d.Domain = domain
		return &d, true
	}

	return nil, false
}
