package domainkey

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

var (
	ErrNoRecordFound        = errors.New("no record found")
	ErrDNSLookupFailed      = errors.New("dns lookup failed")
	ErrInvalidHashAlgo      = errors.New("invalid hash algorithm")
	ErrInvalidKeyType       = errors.New("invalid key type")
	ErrInvalidServiceType   = errors.New("invalid service type")
	ErrInvalidSelectorFlags = errors.New("invalid selector flags")
	ErrInvalidVersion       = errors.New("invalid version")
)

type HashAlgo string

const (
	HashAlgoSHA1   HashAlgo = "sha1"
	HashAlgoSHA256 HashAlgo = "sha256"
)

type KeyType string

const (
	KeyTypeRSA     KeyType = "rsa"
	KeyTypeED25519 KeyType = "ed25519"
)

type ServiceType string

const (
	ServiceTypeEmail ServiceType = "email"
	ServiceTypeAll   ServiceType = "*"
)

type SelectorFlags string

const (
	SelectorFlagsTest         SelectorFlags = "y"
	SelectorFlagsStrictDomain SelectorFlags = "s" // identifier is strict domain
)

type DomainKey struct {
	HashAlgo      []HashAlgo      // h hash algorithm separated by colons
	KeyType       KeyType         // k default:rsa
	Notes         string          // n notes
	PublicKey     string          // p public key base64 encoded
	ServiceType   []ServiceType   // s service type separated by colons
	SelectorFlags []SelectorFlags // t flags separated by colons
	Version       string          // v version default:DKIM1
	raw           string          // raw record
}

// テストフラグが立っているか
func (d *DomainKey) IsTestFlag() bool {
	for _, f := range d.SelectorFlags {
		if f == SelectorFlagsTest {
			return true
		}
	}
	return false
}

// サービスタイプが指定されたものか
func (d *DomainKey) IsService(service ServiceType) bool {
	if service == ServiceTypeAll {
		return true
	}
	// service typeが指定されていない場合は全てのサービスに対応
	if len(d.ServiceType) == 0 {
		return true
	}
	for _, s := range d.ServiceType {
		if s == service {
			return true
		}
	}
	return false
}

// LookupDKIMDomainKey DKIMのドメインキーをLookupする
// versionがDKIM1でない場合はエラーを返す
func LookupDKIMDomainKey(selector, domain string) (DomainKey, error) {
	d, err := lookupDomainKey(selector, domain)
	if err != nil {
		return DomainKey{}, err
	}
	if d.Version != "DKIM1" {
		return DomainKey{}, ErrInvalidVersion
	}
	return d, nil
}

// LookupARCDomainKey ARCのドメインキーを検索する
// versionが含まれていなくてもエラーを返さない
func LookupARCDomainKey(selector, domain string) (DomainKey, error) {
	return lookupDomainKey(selector, domain)
}

// lookupDomainKey
func lookupDomainKey(selector, domain string) (DomainKey, error) {
	query := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	res, err := net.LookupTXT(query)
	if dnsErr, ok := err.(*net.DNSError); ok {
		if dnsErr.IsNotFound {
			return DomainKey{}, ErrNoRecordFound
		}
	} else if err != nil {
		return DomainKey{}, ErrDNSLookupFailed
	}
	// レコードの解析
	for _, r := range res {
		domainKey, err := ParseDomainKeyRecode(r)
		if err != nil {
			return DomainKey{}, err
		}
		if domainKey.PublicKey != "" {
			return domainKey, nil
		}
	}
	return DomainKey{}, ErrNoRecordFound
}

// ドメインキーレコードの解析
func ParseDomainKeyRecode(r string) (DomainKey, error) {
	var key DomainKey
	key.raw = r

	pairs := strings.Split(r, ";")
	for _, pair := range pairs {
		k, v, _ := strings.Cut(pair, "=")
		switch strings.TrimSpace(k) {
		case "v":
			key.Version = v
			continue
		case "h":
			algos := strings.Split(v, ":")
			for _, algo := range algos {
				switch HashAlgo(algo) {
				case HashAlgoSHA1:
					key.HashAlgo = append(key.HashAlgo, HashAlgoSHA1)
				case HashAlgoSHA256:
					key.HashAlgo = append(key.HashAlgo, HashAlgoSHA256)
				default:
					return DomainKey{}, ErrInvalidHashAlgo
				}
			}
		case "k":
			keyTypes := strings.Split(v, ":")
			for _, keyType := range keyTypes {
				switch KeyType(keyType) {
				case KeyTypeRSA:
					key.KeyType = KeyTypeRSA
				case KeyTypeED25519:
					key.KeyType = KeyTypeED25519
				default:
					return DomainKey{}, ErrInvalidKeyType
				}
			}
		case "n":
			key.Notes = v
		case "p":
			key.PublicKey = v
		case "s":
			serviceTypes := strings.Split(v, ":")
			for _, serviceType := range serviceTypes {
				switch ServiceType(serviceType) {
				case ServiceTypeEmail:
					key.ServiceType = append(key.ServiceType, ServiceTypeEmail)
				case ServiceTypeAll:
					key.ServiceType = append(key.ServiceType, ServiceTypeAll)
				default:
					return DomainKey{}, ErrInvalidServiceType
				}
			}
		case "t":
			switch SelectorFlags(v) {
			case SelectorFlagsTest:
				key.SelectorFlags = append(key.SelectorFlags, SelectorFlagsTest)
			case SelectorFlagsStrictDomain:
				key.SelectorFlags = append(key.SelectorFlags, SelectorFlagsStrictDomain)
			default:
				return DomainKey{}, ErrInvalidSelectorFlags
			}
		}
	}

	return key, nil
}
