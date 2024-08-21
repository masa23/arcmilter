package config

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"

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
	} `yaml:"MilterListen"`
	ControlSocketFile struct {
		Path string `yaml:"Path"`
		Mode uint32 `yaml:"Mode"`
	} `yaml:"ControlSocketFile"`
	LogFile struct {
		Path string `yaml:"Path"`
		Mode uint32 `yaml:"Mode"`
	} `yaml:"LogFile"`
	Domains         map[string]Domain `yaml:"Domains"`
	User            string            `yaml:"User"`
	Group           string            `yaml:"Group"`
	Uid             int
	Gid             int
	Debug           bool     `yaml:"Debug"`
	ARCSignHeaders  []string `yaml:"ARCSignHeaders"`
	DKIMSignHeaders []string `yaml:"DKIMSignHeaders"`
}

type Domain struct {
	HeaderCanonicalization string `yaml:"HeaderCanonicalization"`
	BodyCanonicalization   string `yaml:"BodyCanonicalization"`
	HashAlgorithm          string `yaml:"HashAlgorithm"`
	HashAlgo               crypto.Hash
	PrivateKeyFile         string `yaml:"PrivateKeyFile"`
	PrivateKeySigner       crypto.Signer
	Selector               string `yaml:"Selector"`
	Domain                 string
	DKIM                   bool `yaml:"DKIM"`
	ARC                    bool `yaml:"ARC"`
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
	switch config.MilterListen.Network {
	case "unix", "tcp":
	default:
		return nil, fmt.Errorf("invalid MilterListen.Network: %s", config.MilterListen.Network)
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

	// PIDファイルのパスが設定されているか確認
	if config.PidFile.Path == "" {
		return nil, errors.New("PIDFile is not set")
	}

	// LogFIle Modeが設定されていなければ0600にする
	if config.LogFile.Mode == 0 {
		config.LogFile.Mode = 0600
	}

	// Domainsが設定されていなければエラー
	if len(config.Domains) == 0 {
		return nil, errors.New("domains is not set")
	}
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
		case *ed25519.PrivateKey:
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

		value.Domain = domain
		config.Domains[domain] = value

	}

	// UserをUIDに変換
	if config.User != "" {
		u, err := user.Lookup(config.User)
		if err != nil {
			return nil, err
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return nil, err
		}
		config.Uid = uid
	} else {
		// ユーザーが設定されていなければ自分自身のUIDを取得
		u, err := user.Current()
		if err != nil {
			return nil, err
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return nil, err
		}
		config.Uid = uid
	}
	// GroupをGIDに変換
	if config.Group != "" {
		g, err := user.LookupGroup(config.Group)
		if err != nil {
			return nil, err
		}
		gid, err := strconv.Atoi(g.Gid)
		if err != nil {
			return nil, err
		}
		config.Gid = gid
	} else {
		// グループが設定されていなければ自分自身のGIDを取得
		g, err := user.Current()
		if err != nil {
			return nil, err
		}
		gid, err := strconv.Atoi(g.Gid)
		if err != nil {
			return nil, err
		}
		config.Gid = gid
	}

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
