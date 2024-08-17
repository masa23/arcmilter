package header

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/masa23/arcmilter/mmauth/internal/canonical"
)

const (
	crlf = "\r\n"
)

var (
	ErrInvalidEmailFormat = errors.New("invalid email address format")
)

// ヘッダをパースする
func ParseHeaderField(s string) (string, string) {
	key, value, _ := strings.Cut(s, ":")
	return strings.TrimSpace(key), strings.TrimSpace(value)
}

// ヘッダのパラメータをパースする
func ParseHeaderParams(s string) (map[string]string, error) {
	pairs := strings.Split(s, ";")
	params := make(map[string]string)
	for _, s := range pairs {
		key, value, ok := strings.Cut(s, "=")
		if !ok {
			if strings.TrimSpace(s) == "" {
				continue
			}
			return params, errors.New("malformed header params")
		}

		params[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return params, nil
}

// StripWithSpace は文字列から空白を削除する
// '\t', '\n', '\v', '\f', '\r', ' ', U+0085 (NEL), U+00A0 (NBSP).\r \n \t
func StripWhiteSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// WrapSignatureWithBreaks は署名を64文字ごとに改行しスペースを挿入する
func WrapSignatureWithBreaks(s string) string {
	lines := splitStringIntoChunks(s, 64)
	return strings.Join(lines, "\r\n         ")
}

func splitStringIntoChunks(s string, chunkSize int) []string {
	var chunks []string
	for chunkSize < len(s) {
		chunks = append(chunks, s[:chunkSize])
		s = s[chunkSize:]
	}
	chunks = append(chunks, s)
	return chunks
}

// ヘッダ、秘密鍵、正規化の種類を指定して署名を生成する
func Signer(headers []string, key crypto.Signer, canon canonical.Canonicalization) (string, error) {
	var s string
	for _, header := range headers {
		s += canonical.Header(header, canonical.Canonicalization(canon))
	}
	// 末尾のCRLFを削除
	s = strings.TrimSuffix(s, crlf)

	// 署名するヘッダをハッシュ化
	hashed := sha256.Sum256([]byte(s))

	// 秘密鍵を用いてハッシュを署名（ハッシュアルゴリズムの指定を修正）
	signature, err := key.Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		return "", err
	}

	// 署名をbase64エンコード
	b64 := base64.StdEncoding.EncodeToString(signature)
	return b64, nil
}

// relaxed/simpleなどの文字列をパースしてcanonicalizationを返す
func ParseHeaderCanonicalization(s string) (header canonical.Canonicalization, body canonical.Canonicalization, err error) {
	if s == "" {
		// 指定がない場合はsimple/simple
		return canonical.Simple, canonical.Simple, nil
	}
	ret := strings.Split(s, "/")
	if len(ret) != 2 {
		// 一つしかしていない場合はヘッダーに適用
		// bodyはsimple
		return canonical.Canonicalization(ret[0]), canonical.Simple, nil
	}
	switch canonical.Canonicalization(ret[0]) {
	case canonical.Simple, canonical.Relaxed:
		header = canonical.Canonicalization(ret[0])
	default:
		return "", "", fmt.Errorf("invalid canonicalization")
	}
	switch canonical.Canonicalization(ret[1]) {
	case canonical.Simple, canonical.Relaxed:
		body = canonical.Canonicalization(ret[1])
	default:
		return "", "", fmt.Errorf("invalid canonicalization")
	}

	return
}

// DKIM、ARCのヘッダから署名を削除する
func DeleteSignature(header string) string {
	fields := strings.Split(header, ";")
	var ret []string
	for _, field := range fields {
		keyValue := strings.SplitN(field, "=", 2)
		if len(keyValue) != 2 {
			ret = append(ret, field)
			continue
		}
		key := strings.SplitN(field, "=", 2)[0]
		switch strings.TrimSpace(keyValue[0]) {
		case "b":
			ret = append(ret, key+"=")
		default:
			ret = append(ret, key+"="+keyValue[1])
		}
	}
	return strings.Join(ret, ";")
}

// keysをLowercaseに変換し重複を削除する
func lowercaseAndRemoveDuplicates(keys []string) []string {
	// keyはmapのkeyにしたいため全て小文字に変換
	for i, key := range keys {
		keys[i] = strings.ToLower(key)
	}
	return RemoveDuplicates(keys)
}

// headersから指定したヘッダリストのヘッダを抽出する
// ただし、重複してヘッダが存在する場合は、最後に出現したものを先に返す
func ExtractHeadersDKIM(headers []string, keys []string) []string {
	var ret []string

	// 重複を削除し、小文字に変換
	keys = lowercaseAndRemoveDuplicates(keys)

	// ヘッダを抽出
	maps := extractHeaders(headers, keys)

	for _, m := range maps {
		for _, v := range m {
			// vを逆順にして返す
			for i := len(v) - 1; i >= 0; i-- {
				ret = append(ret, v[i])
			}
		}
	}

	return ret
}

// headersから指定したヘッダリストのヘッダを抽出する
// ただし、重複してヘッダが存在する場合は、最後に出現したもののみを返す
func ExtractHeadersARC(headers []string, keys []string) []string {
	var ret []string

	// 重複を削除し、小文字に変換
	keys = lowercaseAndRemoveDuplicates(keys)

	// ヘッダを抽出
	maps := extractHeaders(headers, keys)

	// keys順に抽出する
	for _, k := range keys {
		for _, m := range maps {
			if v, ok := m[k]; ok {
				// 最後に出現したものを返す
				ret = append(ret, v[len(v)-1])
				break
			}
		}
	}

	return ret
}

// headersから指定したヘッダリストのヘッダを抽出する
func extractHeaders(headers []string, keys []string) []map[string][]string {
	var maps []map[string][]string

	for _, header := range headers {
		for _, key := range keys {
			k, _, ok := strings.Cut(header, ":")
			if !ok {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(k), key) {
				if !mapsContainsKey(maps, key) {
					maps = append(maps, map[string][]string{key: {header}})
				} else {
					for j, m := range maps {
						if _, ok := m[key]; ok {
							maps[j][key] = append(maps[j][key], header)
						}
					}
				}
			}
		}
	}

	return maps
}

func mapsContainsKey(maps []map[string][]string, key string) bool {
	for _, m := range maps {
		if _, ok := m[key]; ok {
			return true
		}
	}
	return false
}

// headersから指定したヘッダを抽出する
func ExtractHeader(headers []string, key string) string {
	for _, h := range headers {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), key) {
			return k + ":" + v
		}
	}
	return ""
}

func RemoveDuplicates(strings []string) []string {
	seen := make(map[string]struct{}) // 空のstructを使用してメモリ使用量を節約
	var result []string

	for _, str := range strings {
		if _, ok := seen[str]; !ok {
			seen[str] = struct{}{}
			result = append(result, str)
		}
	}

	return result
}

// Fromのヘッダからメールアドレスを取り出す
func ParseAddress(s string) string {
	var address string
	var quoted bool
	var afeeld bool
	var start, end int

	// 1文字ずつ処理する
	for i, r := range s {
		switch {
		case r == '"' && !afeeld:
			quoted = !quoted
		case r == '<' && !quoted:
			afeeld = true
			start = i
		case r == '>' && !quoted:
			afeeld = false
			end = i
		}
	}

	if start < end {
		address = s[start+1 : end]
	} else {
		address = s
	}

	// 前後の空白を削除
	address = strings.TrimSpace(address)

	return address
}

// Fromのヘッダからドメインを取り出す
func ParseAddressDomain(s string) (string, error) {
	// ヘッダをパースしてメールアドレスを取り出す
	addr := ParseAddress(s)

	if addr == "" {
		return "", ErrInvalidEmailFormat
	}

	// @マークで分割して、後ろのドメインを取り出す
	parts := strings.SplitN(addr, "@", -1)
	if len(parts) < 2 {
		return "", ErrInvalidEmailFormat
	}

	return parts[len(parts)-1], nil
}
