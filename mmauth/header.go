package mmauth

import (
	"bufio"
	"crypto"
	"fmt"
	"net/textproto"
	"strings"

	"github.com/masa23/arcmilter/mmauth/internal/canonical"
	"github.com/masa23/arcmilter/mmauth/internal/header"
)

type headers []string

// ヘッダを読み込み分解する
func readHeader(r *bufio.Reader) (headers, error) {
	tr := textproto.NewReader(r)

	var h headers
	for {
		l, err := tr.ReadLine()
		if err != nil {
			return h, fmt.Errorf("failed to read header: %v", err)
		}

		if len(l) == 0 {
			break
		} else if len(h) > 0 && (l[0] == ' ' || l[0] == '\t') {
			// This is a continuation line
			h[len(h)-1] += l + crlf
		} else {
			h = append(h, l+crlf)
		}
	}

	return h, nil
}

func hashAlgo(algo SignatureAlgorithm) crypto.Hash {
	switch algo {
	case SignatureAlgorithmRSA_SHA1:
		return crypto.SHA1
	case SignatureAlgorithmRSA_SHA256:
		return crypto.SHA256
	case SignatureAlgorithmED25519_SHA256:
		return crypto.SHA256
	default:
		return crypto.SHA256
	}
}

type BodyCanonicalizationAndAlgorithm struct {
	Body      Canonicalization
	Algorithm crypto.Hash
	Limit     int64
}

func isCcanonicalizationBodyAndAlgorithm(c BodyCanonicalizationAndAlgorithm, can []BodyCanonicalizationAndAlgorithm) bool {
	for _, v := range can {
		if v.Body == c.Body && v.Algorithm == c.Algorithm && v.Limit == c.Limit {
			return true
		}
	}
	return false
}

func parseHeaderCanonicalization(s string) (header Canonicalization, body Canonicalization, err error) {
	if s == "" {
		// 指定がない場合はsimple/simple
		return CanonicalizationSimple, CanonicalizationSimple, nil
	}
	ret := strings.Split(s, "/")
	if len(ret) != 2 {
		// 一つしかしていない場合はヘッダーに適用
		// bodyはsimple
		return Canonicalization(ret[0]), CanonicalizationSimple, nil
	}
	switch canonical.Canonicalization(ret[0]) {
	case canonical.Simple, canonical.Relaxed:
		header = Canonicalization(ret[0])
	default:
		return "", "", fmt.Errorf("invalid canonicalization")
	}
	switch canonical.Canonicalization(ret[1]) {
	case canonical.Simple, canonical.Relaxed:
		body = Canonicalization(ret[1])
	default:
		return "", "", fmt.Errorf("invalid canonicalization")
	}

	return
}

// ヘッダからアドレスを取得する
func ParseAddress(s string) string {
	return header.ParseAddress(s)
}

// アドレスからドメイン部分を取得する
func ParseAddressDomain(s string) (string, error) {
	return header.ParseAddressDomain(s)
}

// ヘッダリストから指定された複数のヘッダをARC署名順で抽出する
func ExtractHeadersARC(headers []string, keys []string) []string {
	return header.ExtractHeadersARC(headers, keys)
}

// ヘッダリストから指定された複数のヘッダをDKIM署名順で抽出する
func ExtractHeadersDKIM(headers []string, keys []string) []string {
	return header.ExtractHeadersDKIM(headers, keys)
}

// ヘッダリストから指定されたヘッダを削除する
// 存在しない場合は空文字列を返す
func ExtractHeader(headers []string, key string) string {
	return header.ExtractHeader(headers, key)
}
