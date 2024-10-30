package mmauth

import (
	"bufio"
	"crypto"
	"fmt"
	"net/textproto"
	"strings"

	"github.com/masa23/arcmilter/mmauth/arc"
	"github.com/masa23/arcmilter/mmauth/dkim"
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

type DKIMSignatures []*dkim.Signature

func (d *DKIMSignatures) GetResult() dkim.VerifyStatus {
	// DKIM署名がない場合はNone
	if len(*d) == 0 {
		return dkim.VerifyStatusNone
	}
	for _, sig := range *d {
		if sig.VerifyResult.Status() != dkim.VerifyStatusPass {
			return sig.VerifyResult.Status()
		}
	}
	return dkim.VerifyStatusPass
}

func ParseDKIMHeaders(headers []string) (*DKIMSignatures, error) {
	var sigs DKIMSignatures
	for _, h := range headers {
		k, _ := header.ParseHeaderField(h)
		switch strings.ToLower(k) {
		case "dkim-signature":
			sig, err := dkim.ParseSignature(h)
			if err != nil {
				return nil, fmt.Errorf("failed to parse dkim-signature: %v", err)
			}
			sigs = append(sigs, sig)
		}
	}
	return &sigs, nil
}

type ARCSignatures []*arc.Signature

// インスタンス番号を指定してSignatureを取得する
func (s *ARCSignatures) GetInstance(i int) *arc.Signature {
	if s == nil {
		return nil
	}
	for _, sig := range *s {
		if sig.InstanceNumber == i {
			return sig
		}
	}
	sig := &arc.Signature{
		InstanceNumber: i,
	}
	*s = append(*s, sig)
	return sig
}

// 最大のインスタンス番号を取得する
func (s *ARCSignatures) GetMaxInstance() int {
	if s == nil {
		return 0
	}
	max := 0
	for _, sig := range *s {
		if sig.InstanceNumber > max {
			max = sig.InstanceNumber
		}
	}
	return max
}

// 最後のARCのVerify結果を文字列で取得する
func (s *ARCSignatures) GetVerifyResultString() string {
	if s == nil {
		return "arc=none"
	}
	max := s.GetMaxInstance()
	if max == 0 {
		return "arc=none"
	}

	// 最後のインスタンスの結果を取得
	ah := s.GetInstance(max)
	if ah == nil {
		return "arc=none"
	}
	return fmt.Sprintf("arc=%s (i=%d %s)", ah.VerifyResult.Status(), ah.InstanceNumber, ah.VerifyResult.Message())
}

// 最後のARCのVerify結果を取得する
func (s *ARCSignatures) GetVerifyResult() arc.VerifyStatus {
	if s == nil {
		return arc.VerifyStatusNone
	}
	max := s.GetMaxInstance()
	if max == 0 {
		return arc.VerifyStatusNone
	}

	// 最後のインスタンスの結果を取得
	ah := s.GetInstance(max)
	if ah == nil {
		return arc.VerifyStatusNone
	}
	return ah.VerifyResult.Status()
}

// 既存のARC-SealのCV結果をチェックしarc.ChainValidationResultを返す
// i=1がNone以外の場合はFail
// それ以外のインスタンスがPassでなければFail
func (s *ARCSignatures) GetARCChainValidation() arc.ChainValidationResult {
	if s == nil {
		return arc.ChainValidationResultNone
	}
	max := s.GetMaxInstance()
	// インスタンスがない場合はNone
	if max == 0 {
		return arc.ChainValidationResultNone
	}

	// ここからインスタンスの結果をチェック
	for i := 1; i <= max; i++ {
		a := s.GetInstance(i)
		if i == 1 {
			// 最初のインスタンスはnone以外許されない
			if a.ARCSeal.ChainValidation == arc.ChainValidationResultNone {
				continue
			}
			return arc.ChainValidationResultFail
		}
		// それ以外のインスタンスはPassでなければならない
		if a.ARCSeal.ChainValidation != arc.ChainValidationResultPass {
			return arc.ChainValidationResultFail
		}
	}
	return arc.ChainValidationResultPass
}

// ARCヘッダをパースする
func ParseARCHeaders(headers []string) (*ARCSignatures, error) {
	var sigs ARCSignatures

	for _, h := range headers {
		k, _ := header.ParseHeaderField(h)
		switch strings.ToLower(k) {
		case "arc-seal":
			ret, err := arc.ParseARCSeal(h)
			if err != nil {
				return nil, fmt.Errorf("failed to parse arc-seal: %v", err)
			}
			// インスタンス番号が50以上の場合はエラー
			if ret.InstanceNumber > 50 {
				return nil, fmt.Errorf("instance number is too large")
			}
			as := sigs.GetInstance(ret.InstanceNumber)
			as.ARCSeal = ret
		case "arc-authentication-results":
			ret, err := arc.ParseARCAuthenticationResults(h)
			if err != nil {
				return nil, fmt.Errorf("failed to parse arc-authentication-results: %v", err)
			}
			// インスタンス番号が50以上の場合はエラー
			if ret.InstanceNumber > 50 {
				return nil, fmt.Errorf("instance number is too large")
			}
			as := sigs.GetInstance(ret.InstanceNumber)
			as.ARCAuthenticationResults = ret
		case "arc-message-signature":
			ret, err := arc.ParseARCMessageSignature(h)
			if err != nil {
				return nil, fmt.Errorf("failed to parse arc-message-signature: %v", err)
			}
			// インスタンス番号が50以上の場合はエラー
			if ret.InstanceNumber > 50 {
				return nil, fmt.Errorf("instance number is too large")
			}
			as := sigs.GetInstance(ret.InstanceNumber)
			as.ARCMessageSignature = ret
		}
	}

	// インスタンスのチェック
	for i := 1; i <= sigs.GetMaxInstance(); i++ {
		// インスタンスが連続していない場合はエラー
		ah := sigs.GetInstance(i)
		if ah == nil {
			return nil, fmt.Errorf("instance number is not continuous")
		}
		// ARC-Seal、ARC-Authentication-Results、ARC-Message-Signatureがない場合はエラー
		if ah.ARCSeal == nil || ah.ARCAuthenticationResults == nil || ah.ARCMessageSignature == nil {
			return nil, fmt.Errorf("arc headers are missing")
		}
	}

	return &sigs, nil
}

// ARCヘッダをSealで署名する順番にソートする
func (s *ARCSignatures) GetARCHeaders() []string {
	if s == nil {
		return nil
	}
	var ret []string
	max := s.GetMaxInstance()
	if max <= 0 {
		return ret
	}

	for i := 1; i <= max; i++ {
		arc := s.GetInstance(i)
		if arc.ARCAuthenticationResults != nil && arc.ARCMessageSignature != nil && arc.ARCSeal != nil {
			ret = append(ret, arc.ARCAuthenticationResults.Raw())
			ret = append(ret, arc.ARCMessageSignature.Raw())
			ret = append(ret, arc.ARCSeal.Raw())
		}
	}
	return ret
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
