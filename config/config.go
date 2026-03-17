package config

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

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
	// 空の場合は自分自身のUIDを取得
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
	// 空の場合は自分自身のGIDを取得
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
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// YAMLをパースする
	var config Config
	err = yaml.Unmarshal(buf, &config)
	if err != nil {
		return nil, err
	}

	// MilterListen Networkのバリデーション
	if err := checkMilterListenNetwork(config.MilterListen.Network); err != nil {
		return nil, err
	}

	// UnixSocketの場合はOwnerとGroupを設定
	if config.MilterListen.Network == "unix" {
		uid, err := getUid(config.MilterListen.Owner)
		if err != nil {
			return nil, err
		}
		config.MilterListen.Uid = uid
		gid, err := getGid(config.MilterListen.Group)
		if err != nil {
			return nil, err
		}
		config.MilterListen.Gid = gid
	}

	// MilterListen Addressのバリデーション
	if config.MilterListen.Address == "" {
		return nil, errors.New("MilterListen.Address is not set")
	}

	// MilterListen Modeが設定されていなければ0600にする
	if config.MilterListen.Mode == 0 {
		config.MilterListen.Mode = 0600
	}

	// PidFile Pathが設定されているか確認
	if config.PidFile.Path == "" {
		return nil, errors.New("PIDFile is not set")
	}

	// ControlSocketファイルのパスが設定されているか確認
	if config.ControlSocketFile.Path == "" {
		return nil, errors.New("ControlSocketFile.Path is not set")
	}

	// ControlSocket Modeが設定されていなければ0600にする
	if config.ControlSocketFile.Mode == 0 {
		config.ControlSocketFile.Mode = 0600
	}

	// LogFIle Modeが設定されていなければ0600にする
	if config.LogFile.Mode == 0 {
		config.LogFile.Mode = 0600
	}

	// MyNetworksが設定されていなければエラー
	if len(config.MyNetworks) == 0 {
		return nil, errors.New("MyNetwork is not set")
	}
	// MyNetworksをパースする
	for _, network := range config.MyNetworks {
		_, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			return nil, err
		}
		config.ParsedMyNetworks = append(config.ParsedMyNetworks, ipNet)
	}

	// Domainsが設定されていなければエラー
	if len(config.Domains) == 0 {
		return nil, errors.New("domains is not set")
	}
	// 簡略構文を展開
	config.Domains = expandDomains(config.Domains)

	// Domainsを読み込む
	for domain, value := range config.Domains {
		// PrivateKeyを読み込む
		buf, err := os.ReadFile(value.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(buf)
		if block == nil {
			return nil, fmt.Errorf("failed to decode pem: %s", value.PrivateKeyFile)
		}

		var priv interface{}
		switch block.Type {
		case "RSA PRIVATE KEY":
			priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		case "PRIVATE KEY":
			priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown key type: %s", block.Type)
		}

		switch key := priv.(type) {
		case *rsa.PrivateKey:
			value.PrivateKeySigner = key
		case ed25519.PrivateKey:
			value.PrivateKeySigner = key
		default:
			return nil, fmt.Errorf("unknown key type: %T", key)
		}

		// HeaderCanonicalizationとBodyCanonicalizationのバリデーション
		if value.HeaderCanonicalization == "" {
			value.HeaderCanonicalization = "relaxed"
		}
		switch value.HeaderCanonicalization {
		case "simple", "relaxed":
		default:
			return nil, fmt.Errorf("invalid HeaderCanonicalization: %s", value.HeaderCanonicalization)
		}
		if value.BodyCanonicalization == "" {
			value.BodyCanonicalization = "relaxed"
		}
		switch value.BodyCanonicalization {
		case "simple", "relaxed":
		default:
			return nil, fmt.Errorf("invalid BodyCanonicalization: %s", value.BodyCanonicalization)
		}

		// HashAlgoのバリデーション
		if value.HashAlgorithm == "" {
			value.HashAlgorithm = "sha256"
		}
		switch value.HashAlgorithm {
		case "sha1":
			value.HashAlgo = crypto.SHA1
		case "sha256":
			value.HashAlgo = crypto.SHA256
		default:
			return nil, fmt.Errorf("invalid HashAlgo: %s", value.HashAlgo)
		}

		// if Selector is empty, use "default"
		if value.Selector == "" {
			value.Selector = "default"
		}
		if value.ARCSelector == "" {
			value.ARCSelector = value.Selector
		}

		// PatternはexpandDomainsで既に設定されている
		if value.Pattern == "" {
			value.Pattern = domain
		}
		// DomainはexpandDomainsで既に設定されているが、念のため再設定
		value.Domain = domain

		config.Domains[domain] = value

	}
	uid, err := getUid(config.User)
	if err != nil {
		return nil, err
	}
	config.Uid = uid

	// GroupをGIDに変換
	gid, err := getGid(config.Group)
	if err != nil {
		return nil, err
	}
	config.Gid = gid

	// DKIMSignHeadersが設定されていなければエラー
	if len(config.DKIMSignHeaders) == 0 {
		return nil, errors.New("DKIMSignHeaders is not set")
	}

	// ARCSignHeadersが設定されていなければエラー
	if len(config.ARCSignHeaders) == 0 {
		return nil, errors.New("ARCSignHeaders is not set")
	}

	// HUP用にパスを保存
	config.Path = path

	return &config, nil
}

// IsMyNetwork は指定されたIPアドレスが自分のネットワークに含まれるかを返す
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
		hostPart = pattern[2:] // Remove "*."
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

	// ワイルドカード: *.example.com → sub.example.com をマッチ
	// また、example.com 自体もマッチさせる（edge case）
	return strings.HasSuffix(domain, "."+hostPart) || domain == hostPart
}

// expandDomains は簡略構文 "list:domain1,domain2,*.domain3" を展開する
func expandDomains(domains map[string]Domain) map[string]Domain {
	result := make(map[string]Domain)

	// 第一フェーズ: list構文のみを展開
	for domainKey, domainConf := range domains {
		if strings.HasPrefix(domainKey, "list:") {
			domainList := strings.Split(domainKey[5:], ",") // "list:"の5文字をスキップ
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

	// 第二フェーズ: 明示的なキーを適用（list構文の設定を上書き）
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
// 優先順位: 完全一致 → ワイルドカード一致（より限定的なもの優先） → デフォルト(*)
// 返されるDomainのDomainフィールドは、マッチした実際のドメイン名に設定される
func (c *Config) GetMatchingDomain(domain string) (*Domain, bool) {
	// 完全一致を優先
	if d, ok := c.Domains[domain]; ok {
		return &d, true
	}

	// ワイルドカード一致を検索（最も限定的なものを優先）
	bestMatchKey := ""
	bestMatchLen := 0

	for pattern := range c.Domains {
		if pattern == "*" {
			continue // デフォルトは最後にチェック
		}
		if matchDomain(pattern, domain) {
			_, hostPart := parseDomainPattern(pattern)
			matchLen := len(hostPart)
			// より長いホストパーツ（より限定的）を優先
			if matchLen > bestMatchLen {
				bestMatchKey = pattern
				bestMatchLen = matchLen
			}
		}
	}

	if bestMatchKey != "" {
		if d, ok := c.Domains[bestMatchKey]; ok {
			d.Domain = domain // マッチした実際のドメイン名を設定
			return &d, true
		}
	}

	// デフォルト
	if d, ok := c.Domains["*"]; ok {
		d.Domain = domain // マッチした実際のドメイン名を設定
		return &d, true
	}

	return nil, false
}
