package config

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"gopkg.in/yaml.v3"
)

const (
	MaxConfigBytes                                         = 4 << 20
	DefaultMilterMaxConnections                            = 64
	DefaultDKIM2MilterMaxConnections                       = 4
	MaxMilterMaxConnections                                = 4096
	DefaultHeaderCanonicalization                          = "relaxed"
	DefaultBodyCanonicalization                            = "relaxed"
	DefaultHashAlgorithm                                   = "sha256"
	DefaultSelector                                        = "default"
	DefaultDKIM2MaxMessageBytes                      int64 = 32 << 20
	DefaultDKIM2ForwardingMaxAgeSeconds              int64 = 24 * 60 * 60
	DefaultDKIM2ForwardingCacheFailureAction               = "skip-signing"
	MaxDKIM2ForwardingMaxAgeSeconds                  int64 = 14 * 24 * 60 * 60
	DefaultDKIM2ForwardingMaxStoredBytes             int64 = 1 << 30
	DefaultDKIM2ForwardingMaxStoredBytesPerRecipient int64 = 256 << 20
	MaxDKIM2ForwardRecipients                              = 128
	MaxDKIM2ForwardRecipientQuotaBytes                     = 32 << 10
)

var configDKIM2IDNA = idna.New(idna.ValidateForRegistration())

type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type Config struct {
	Path       string   `yaml:"-"`
	SourceYAML []byte   `yaml:"-"`
	LogFd      *os.File `yaml:"-"`
	PidFile    struct {
		Path string `yaml:"Path"`
	} `yaml:"PIDFile"`
	MilterListen struct {
		Network             string       `yaml:"Network"`
		Address             string       `yaml:"Address"`
		Mode                uint32       `yaml:"Mode"`
		Owner               string       `yaml:"Owner"`
		Group               string       `yaml:"Group"`
		AllowedPeers        []string     `yaml:"AllowedPeers"`
		AllowTCPWithSigning bool         `yaml:"AllowTCPWithSigning"`
		ParsedAllowedPeers  []*net.IPNet `yaml:"-"`
		MaxConnections      int          `yaml:"MaxConnections"`
		Uid                 int          `yaml:"-"`
		Gid                 int          `yaml:"-"`
	} `yaml:"MilterListen"`
	ControlSocketFile struct {
		Path string `yaml:"Path"`
		Mode uint32 `yaml:"Mode"`
	} `yaml:"ControlSocketFile"`
	LogFile struct {
		Path string `yaml:"Path"`
		Mode uint32 `yaml:"Mode"`
	} `yaml:"LogFile"`
	MyNetworks           []string              `yaml:"MyNetworks"`
	ParsedMyNetworks     []*net.IPNet          `yaml:"-"`
	Domains              map[string]Domain     `yaml:"Domains"`
	User                 string                `yaml:"User"`
	Group                string                `yaml:"Group"`
	Uid                  int                   `yaml:"-"`
	Gid                  int                   `yaml:"-"`
	Debug                bool                  `yaml:"Debug"`
	ARCSignHeaders       []string              `yaml:"ARCSignHeaders"`
	DKIMSignHeaders      []string              `yaml:"DKIMSignHeaders"`
	EnableDKIM2          bool                  `yaml:"EnableDKIM2"`
	DKIM2MaxMessageBytes int64                 `yaml:"DKIM2MaxMessageBytes"`
	DKIM2Forwarding      DKIM2ForwardingConfig `yaml:"DKIM2Forwarding"`
}

type DKIM2ForwardingConfig struct {
	Mode                       string   `yaml:"Mode"`
	StoreDirectory             string   `yaml:"StoreDirectory"`
	SigningDomain              string   `yaml:"SigningDomain"`
	MaxAgeSeconds              int64    `yaml:"MaxAgeSeconds"`
	MaxStoredBytes             int64    `yaml:"MaxStoredBytes"`
	MaxStoredBytesPerRecipient int64    `yaml:"MaxStoredBytesPerRecipient"`
	MultipleDeliveries         bool     `yaml:"MultipleDeliveries"`
	ForwardRecipients          []string `yaml:"ForwardRecipients"`
	AllowRecipeDisclosure      bool     `yaml:"AllowRecipeDisclosure"`
	CacheFailureAction         string   `yaml:"CacheFailureAction"`
}

type Domain struct {
	HeaderCanonicalization string        `yaml:"HeaderCanonicalization"`
	BodyCanonicalization   string        `yaml:"BodyCanonicalization"`
	HashAlgorithm          string        `yaml:"HashAlgorithm"`
	HashAlgo               crypto.Hash   `yaml:"-"`
	PrivateKeyFile         string        `yaml:"PrivateKeyFile"`
	PrivateKeySigner       crypto.Signer `yaml:"-"`
	Selector               string        `yaml:"Selector"`
	ARCSelector            string        `yaml:"ARCSelector"`
	DKIM2Selector          string        `yaml:"DKIM2Selector"`
	Domain                 string        `yaml:"-"`
	Pattern                string        `yaml:"-"` // Original pattern from config (e.g., "*.example.com")
	DKIM                   bool          `yaml:"DKIM"`
	DKIM2                  bool          `yaml:"DKIM2"`
	ARC                    bool          `yaml:"ARC"`
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

func parseMilterAllowedPeer(value string) (*net.IPNet, error) {
	if ip := net.ParseIP(value); ip != nil {
		bits := 128
		if ip4 := ip.To4(); ip4 != nil {
			ip, bits = ip4, 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return nil, fmt.Errorf("invalid MilterListen.AllowedPeers entry %q: %w", value, err)
	}
	return network, nil
}

func hasDKIM2Domain(domains map[string]Domain) bool {
	for _, domain := range domains {
		if domain.DKIM2 {
			return true
		}
	}
	return false
}

func hasSigningDomain(domains map[string]Domain) bool {
	for _, domain := range domains {
		if domain.DKIM || domain.DKIM2 || domain.ARC {
			return true
		}
	}
	return false
}

func Load(path string) (*Config, error) {
	buf, err := readTrustedConfigFile(path)
	if err != nil {
		return nil, err
	}
	return LoadTrustedSnapshot(path, buf)
}

// LoadTrustedSnapshot loads configuration bytes previously authenticated by
// Load. The parent passes its accepted snapshot to children through a pipe so
// a rejected on-disk edit cannot be adopted by an automatic child restart.
func LoadTrustedSnapshot(path string, buf []byte) (*Config, error) {
	if len(buf) > MaxConfigBytes {
		return nil, errors.New("configuration exceeds 4 MiB limit")
	}
	config := createDefaultConfig()

	err := parseYAML(buf, config)
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
	if err := validateDKIM2SigningKeys(config); err != nil {
		return nil, err
	}

	config.Path = path
	config.SourceYAML = append([]byte(nil), buf...)
	return config, nil
}

// ValidateTrustedParentDirectory rejects path components that an unrelated
// local account can replace. Root-owned sticky directories are safe for files
// owned by this process; both original and symlink-resolved chains are checked.
func ValidateTrustedParentDirectory(path string) error {
	directory, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	for _, chain := range []string{directory, resolved} {
		current := string(os.PathSeparator)
		for _, component := range strings.Split(strings.TrimPrefix(chain, current), current) {
			if component == "" {
				continue
			}
			current = filepath.Join(current, component)
			link, err := os.Lstat(current)
			if err != nil {
				return err
			}
			if link.Mode()&os.ModeSymlink != 0 {
				stat, ok := link.Sys().(*syscall.Stat_t)
				if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
					return fmt.Errorf("directory symlink %s is not trusted", current)
				}
			}
			info, err := os.Stat(current)
			if err != nil {
				return err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !info.IsDir() || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) ||
				info.Mode().Perm()&0022 != 0 && !(info.Mode()&os.ModeSticky != 0 && stat.Uid == 0) {
				return fmt.Errorf("directory %s must be owned by root or the daemon and protected from untrusted writes", current)
			}
		}
	}
	return nil
}

func readTrustedConfigFile(path string) ([]byte, error) {
	if err := ValidateTrustedParentDirectory(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) ||
		stat.Nlink != 1 || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("configuration must be an owned, non-writable regular file with one link")
	}
	buf, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > MaxConfigBytes {
		return nil, errors.New("configuration exceeds 4 MiB limit")
	}
	return buf, nil
}

func createDefaultConfig() *Config {
	return &Config{
		MilterListen: struct {
			Network             string       `yaml:"Network"`
			Address             string       `yaml:"Address"`
			Mode                uint32       `yaml:"Mode"`
			Owner               string       `yaml:"Owner"`
			Group               string       `yaml:"Group"`
			AllowedPeers        []string     `yaml:"AllowedPeers"`
			AllowTCPWithSigning bool         `yaml:"AllowTCPWithSigning"`
			ParsedAllowedPeers  []*net.IPNet `yaml:"-"`
			MaxConnections      int          `yaml:"MaxConnections"`
			Uid                 int          `yaml:"-"`
			Gid                 int          `yaml:"-"`
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
	decoder := yaml.NewDecoder(bytes.NewReader(buf))
	decoder.KnownFields(true)
	err := decoder.Decode(config)
	if err != nil {
		return err
	}
	// The configuration is one document. Otherwise later security settings or
	// malformed YAML would be silently ignored by the first Decode call.
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("configuration must contain exactly one YAML document")
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
	if config.MilterListen.Network == "unix" && config.MilterListen.Mode&0007 != 0 {
		return &ConfigError{Field: "MilterListen.Mode", Message: "must not grant access to other users"}
	}
	if config.MilterListen.MaxConnections < 0 || config.MilterListen.MaxConnections > MaxMilterMaxConnections {
		return &ConfigError{Field: "MilterListen.MaxConnections", Message: fmt.Sprintf("must be between 0 and %d", MaxMilterMaxConnections)}
	}
	if config.MilterListen.MaxConnections == 0 {
		config.MilterListen.MaxConnections = DefaultMilterMaxConnections
		if config.EnableDKIM2 || hasDKIM2Domain(config.Domains) || config.DKIM2Forwarding.Mode != "" && config.DKIM2Forwarding.Mode != "disabled" {
			config.MilterListen.MaxConnections = DefaultDKIM2MilterMaxConnections
		}
	}
	if config.MilterListen.Network != "tcp" && len(config.MilterListen.AllowedPeers) != 0 {
		return &ConfigError{Field: "MilterListen.AllowedPeers", Message: "is only valid for tcp listeners"}
	}
	if config.MilterListen.Network != "tcp" && config.MilterListen.AllowTCPWithSigning {
		return &ConfigError{Field: "MilterListen.AllowTCPWithSigning", Message: "is only valid for tcp listeners"}
	}
	if config.MilterListen.Network == "tcp" {
		peers := config.MilterListen.AllowedPeers
		if len(peers) == 0 {
			peers = []string{"127.0.0.0/8", "::1/128"}
		}
		for _, peer := range peers {
			network, err := parseMilterAllowedPeer(peer)
			if err != nil {
				return err
			}
			config.MilterListen.ParsedAllowedPeers = append(config.MilterListen.ParsedAllowedPeers, network)
		}
		if hasSigningDomain(config.Domains) && !config.MilterListen.AllowTCPWithSigning {
			return &ConfigError{Field: "MilterListen.AllowTCPWithSigning", Message: "TCP peer IP addresses do not authenticate local processes; use a private Unix socket or explicitly allow signing over an isolated TCP endpoint"}
		}
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
	if config.ControlSocketFile.Mode&0007 != 0 {
		return &ConfigError{Field: "ControlSocketFile.Mode", Message: "must not grant access to other users"}
	}

	if config.LogFile.Mode == 0 {
		config.LogFile.Mode = 0600
	}
	if config.LogFile.Mode&^0640 != 0 || config.LogFile.Mode&0200 == 0 {
		return &ConfigError{Field: "LogFile.Mode", Message: "must grant owner write access and at most group read access"}
	}
	if config.DKIM2MaxMessageBytes < 0 || config.DKIM2MaxMessageBytes > DefaultDKIM2MaxMessageBytes {
		return &ConfigError{Field: "DKIM2MaxMessageBytes", Message: fmt.Sprintf("must be between 0 and %d", DefaultDKIM2MaxMessageBytes)}
	}
	if config.DKIM2MaxMessageBytes == 0 {
		config.DKIM2MaxMessageBytes = DefaultDKIM2MaxMessageBytes
	}
	forwarding := &config.DKIM2Forwarding
	forwarding.SigningDomain = strings.ToLower(forwarding.SigningDomain)
	if forwarding.SigningDomain != "" && !validDKIM2SigningDomain(forwarding.SigningDomain) {
		return &ConfigError{Field: "DKIM2Forwarding.SigningDomain", Message: "must be a valid DNS name in ASCII A-label form"}
	}
	switch forwarding.Mode {
	case "":
		forwarding.Mode = "disabled"
	case "disabled", "receive", "send":
	default:
		return &ConfigError{Field: "DKIM2Forwarding.Mode", Message: "must be disabled, receive or send"}
	}
	switch forwarding.CacheFailureAction {
	case "":
		forwarding.CacheFailureAction = DefaultDKIM2ForwardingCacheFailureAction
	case "skip-signing", "tempfail":
	default:
		return &ConfigError{Field: "DKIM2Forwarding.CacheFailureAction", Message: "must be skip-signing or tempfail"}
	}
	if forwarding.Mode != "disabled" {
		if forwarding.StoreDirectory == "" {
			return &ConfigError{Field: "DKIM2Forwarding.StoreDirectory", Message: "is not set"}
		}
		if !filepath.IsAbs(forwarding.StoreDirectory) {
			return &ConfigError{Field: "DKIM2Forwarding.StoreDirectory", Message: "must be an absolute path"}
		}
	}
	if forwarding.Mode == "receive" && len(forwarding.ForwardRecipients) == 0 {
		return &ConfigError{Field: "DKIM2Forwarding.ForwardRecipients", Message: "must list the Postfix alias or forwarding recipients saved by the receive stage"}
	}
	if len(forwarding.ForwardRecipients) > MaxDKIM2ForwardRecipients {
		return &ConfigError{Field: "DKIM2Forwarding.ForwardRecipients", Message: fmt.Sprintf("must contain at most %d entries", MaxDKIM2ForwardRecipients)}
	}
	if len(forwarding.ForwardRecipients) > 0 {
		seenForwardRecipients := make(map[string]bool, len(forwarding.ForwardRecipients))
		normalizedForwardRecipients := make([]string, 0, len(forwarding.ForwardRecipients))
		quotaKeyBytes := 0
		for _, recipient := range forwarding.ForwardRecipients {
			normalized, err := normalizeDKIM2ForwardRecipient(recipient)
			if err != nil {
				return &ConfigError{Field: "DKIM2Forwarding.ForwardRecipients", Message: err.Error()}
			}
			if !seenForwardRecipients[normalized] {
				quotaKeyBytes += len(normalized)
				if quotaKeyBytes > MaxDKIM2ForwardRecipientQuotaBytes {
					return &ConfigError{Field: "DKIM2Forwarding.ForwardRecipients", Message: fmt.Sprintf("total normalized size must not exceed %d bytes", MaxDKIM2ForwardRecipientQuotaBytes)}
				}
				seenForwardRecipients[normalized] = true
				normalizedForwardRecipients = append(normalizedForwardRecipients, normalized)
			}
		}
		forwarding.ForwardRecipients = normalizedForwardRecipients
	}
	if forwarding.MaxAgeSeconds < 0 || forwarding.MaxAgeSeconds > MaxDKIM2ForwardingMaxAgeSeconds {
		return &ConfigError{Field: "DKIM2Forwarding.MaxAgeSeconds", Message: fmt.Sprintf("must be between 0 and %d", MaxDKIM2ForwardingMaxAgeSeconds)}
	}
	if forwarding.MaxAgeSeconds == 0 {
		forwarding.MaxAgeSeconds = DefaultDKIM2ForwardingMaxAgeSeconds
	}
	if forwarding.MaxStoredBytes < 0 {
		return &ConfigError{Field: "DKIM2Forwarding.MaxStoredBytes", Message: "must not be negative"}
	}
	if forwarding.MaxStoredBytes == 0 {
		forwarding.MaxStoredBytes = DefaultDKIM2ForwardingMaxStoredBytes
	}
	if forwarding.MaxStoredBytesPerRecipient < 0 {
		return &ConfigError{Field: "DKIM2Forwarding.MaxStoredBytesPerRecipient", Message: "must not be negative"}
	}
	if forwarding.MaxStoredBytesPerRecipient == 0 {
		forwarding.MaxStoredBytesPerRecipient = min(DefaultDKIM2ForwardingMaxStoredBytesPerRecipient, forwarding.MaxStoredBytes)
		if len(forwarding.ForwardRecipients) > 1 {
			forwarding.MaxStoredBytesPerRecipient = min(forwarding.MaxStoredBytesPerRecipient,
				max(int64(1), forwarding.MaxStoredBytes/int64(len(forwarding.ForwardRecipients))))
		}
	}
	if forwarding.MaxStoredBytesPerRecipient > forwarding.MaxStoredBytes {
		return &ConfigError{Field: "DKIM2Forwarding.MaxStoredBytesPerRecipient", Message: "must not exceed MaxStoredBytes"}
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

	var err error
	config.Domains, err = normalizeDomainConfig(config.Domains)
	if err != nil {
		return err
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
		if value.DKIM2Selector == "" {
			value.DKIM2Selector = value.Selector
		}
		if value.DKIM2 {
			_, signingDomain := parseDomainPattern(domain)
			if domain != "*" && !validDKIM2SigningDomain(signingDomain) {
				return &ConfigError{Field: fmt.Sprintf("Domains[%s]", domain), Message: "DKIM2 domain must be a valid DNS name in ASCII A-label form"}
			}
			value.DKIM2Selector = strings.ToLower(value.DKIM2Selector)
			if !validDKIM2ASCIIDNSName(value.DKIM2Selector) {
				return &ConfigError{Field: fmt.Sprintf("Domains[%s].DKIM2Selector", domain), Message: "must be a valid ASCII DNS name"}
			}
		}

		if value.Pattern == "" {
			value.Pattern = domain
		}
		value.Domain = domain

		config.Domains[domain] = value
	}
	if forwarding.Mode == "send" && forwarding.SigningDomain != "" {
		if domain, ok := config.GetMatchingDomain(forwarding.SigningDomain); !ok || !domain.DKIM2 {
			return &ConfigError{Field: "DKIM2Forwarding.SigningDomain", Message: "must match a domain with DKIM2 enabled"}
		}
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
	fromSigned := false
	for _, name := range config.ARCSignHeaders {
		if strings.EqualFold(strings.TrimSpace(name), "From") {
			fromSigned = true
			break
		}
	}
	if !fromSigned {
		return &ConfigError{Field: "ARCSignHeaders", Message: "must include From"}
	}

	return nil
}

// Selectors are ASCII DNS names, not IDNA mailbox domains. In particular,
// an LDH selector need not be a valid A-label even if it begins with xn--.
func validDKIM2ASCIIDNSName(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 || domain != strings.ToLower(domain) {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range label {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validDKIM2SigningDomain(domain string) bool {
	if !validDKIM2ASCIIDNSName(domain) {
		return false
	}
	ascii, err := configDKIM2IDNA.ToASCII(domain)
	return err == nil && ascii == domain
}

// normalizeDKIM2ForwardRecipient keeps the SMTP local-part byte-for-byte and
// canonicalizes the configured DNS domain. A local-part of "*" selects a
// forwarding-only domain or catch-all alias.
func normalizeDKIM2ForwardRecipient(recipient string) (string, error) {
	if recipient == "" || recipient != strings.TrimSpace(recipient) || !utf8.ValidString(recipient) {
		return "", errors.New("must contain valid UTF-8 without surrounding whitespace or control characters")
	}
	for _, r := range recipient {
		if unicode.IsControl(r) {
			return "", errors.New("must contain valid UTF-8 without surrounding whitespace or control characters")
		}
	}
	if strings.HasPrefix(recipient, "<") && strings.HasSuffix(recipient, ">") {
		recipient = recipient[1 : len(recipient)-1]
	}
	at := strings.LastIndexByte(recipient, '@')
	if at <= 0 || at == len(recipient)-1 {
		return "", errors.New("must contain a nonempty local-part and domain")
	}
	local, domain := recipient[:at], strings.ToLower(recipient[at+1:])
	if strings.ContainsAny(local, "<>\r\n\x00") || strings.Contains(local, "*") && local != "*" {
		return "", errors.New("contains an invalid local-part")
	}
	if !validDKIM2SigningDomain(domain) {
		return "", errors.New("domain must be an ASCII DNS name in A-label form")
	}
	return local + "@" + domain, nil
}

func loadKeys(config *Config) error {
	for domain, value := range config.Domains {
		buf, err := readTrustedPrivateKeyFile(value.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("private key %s: %w", value.PrivateKeyFile, err)
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

func readTrustedPrivateKeyFile(path string) ([]byte, error) {
	if err := ValidateTrustedParentDirectory(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) ||
		stat.Nlink != 1 || info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0400 == 0 {
		return nil, errors.New("private key must be a root- or daemon-owned regular file with owner-only read access and one link")
	}
	const maxPrivateKeyBytes = 1 << 20
	buf, err := io.ReadAll(io.LimitReader(file, maxPrivateKeyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > maxPrivateKeyBytes {
		return nil, errors.New("private key exceeds 1 MiB limit")
	}
	return buf, nil
}

func validateDKIM2SigningKeys(config *Config) error {
	for name, domain := range config.Domains {
		if !domain.DKIM2 {
			continue
		}
		switch key := domain.PrivateKeySigner.Public().(type) {
		case *rsa.PublicKey:
			if key.N == nil || key.N.BitLen() < 1024 || key.N.BitLen() > 8192 || key.E != 65537 {
				return &ConfigError{Field: fmt.Sprintf("Domains[%s].PrivateKeyFile", name), Message: "DKIM2 RSA keys must be 1024-8192 bits with exponent 65537"}
			}
		case ed25519.PublicKey:
			if len(key) != ed25519.PublicKeySize {
				return &ConfigError{Field: fmt.Sprintf("Domains[%s].PrivateKeyFile", name), Message: "invalid DKIM2 Ed25519 key"}
			}
		default:
			return &ConfigError{Field: fmt.Sprintf("Domains[%s].PrivateKeyFile", name), Message: fmt.Sprintf("unsupported DKIM2 key type %T", key)}
		}
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

// IsAllowedMilterPeer authenticates the process speaking the Milter protocol
// by its real TCP peer. MyNetworks is intentionally not used here: it describes
// the SMTP client reported by the trusted MTA, not the MTA process itself.
func (c *Config) IsAllowedMilterPeer(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if len(c.MilterListen.ParsedAllowedPeers) == 0 {
		return ip.IsLoopback()
	}
	for _, network := range c.MilterListen.ParsedAllowedPeers {
		if network.Contains(ip) {
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
	pattern, domain = strings.ToLower(pattern), strings.ToLower(domain)
	isWildcard, hostPart := parseDomainPattern(pattern)

	if !isWildcard {
		return pattern == domain
	}

	if pattern == "*" {
		return true
	}

	return strings.HasSuffix(domain, "."+hostPart) || domain == hostPart
}

// DNS名の大小文字によって設定が分岐しないよう、展開前に表記を統一する。
// 同じ表記のlist/個別指定は従来どおり個別指定が優先される。
func normalizeDomainConfig(domains map[string]Domain) (map[string]Domain, error) {
	normalized := make(map[string]Domain, len(domains))
	spellings := make(map[string]string)
	for key, domain := range domains {
		normalizedKey := strings.ToLower(key)
		if _, exists := normalized[normalizedKey]; exists {
			return nil, &ConfigError{Field: "Domains", Message: "contains duplicate domain keys differing only in case"}
		}
		patterns := []string{key}
		if strings.HasPrefix(normalizedKey, "list:") {
			patterns = strings.Split(key[5:], ",")
		}
		for _, pattern := range patterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			name := strings.ToLower(pattern)
			if previous, exists := spellings[name]; exists && previous != pattern {
				return nil, &ConfigError{Field: "Domains", Message: fmt.Sprintf("contains case-duplicate domain pattern %q", pattern)}
			}
			spellings[name] = pattern
		}
		normalized[normalizedKey] = domain
	}
	return normalized, nil
}

// expandDomains は簡略構文 "list:domain1,domain2,*.domain3" を展開する
func expandDomains(domains map[string]Domain) map[string]Domain {
	result := make(map[string]Domain)

	for domainKey, domainConf := range domains {
		domainKey = strings.ToLower(domainKey)
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
		domainKey = strings.ToLower(domainKey)
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
	domain = strings.ToLower(domain)
	if d, ok := c.Domains[domain]; ok {
		d.Domain = domain
		return &d, true
	}
	// Configの直接生成でも、大文字の完全一致キーをワイルドカードより優先する。
	for pattern, d := range c.Domains {
		if strings.EqualFold(pattern, domain) {
			d.Domain = domain
			return &d, true
		}
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
