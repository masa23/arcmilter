package arc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/masa23/arcmilter/mmauth/domainkey"
	"github.com/masa23/arcmilter/mmauth/internal/canonical"
	"github.com/masa23/arcmilter/mmauth/internal/header"
)

// ARC-Seal の構造体
type ARCSeal struct {
	Algorithm       SignatureAlgorithm    // a algorithm
	Signature       string                // b signature
	ChainValidation ChainValidationResult // cv chain validation result
	Domain          string                // d domain
	InstanceNumber  int                   // i instance number
	Selector        string                // s selector
	Timestamp       int64                 // t timestamp
	raw             string
	hashAlgo        crypto.Hash
}

func (as *ARCSeal) Raw() string {
	if as.raw == "" {
		return as.String()
	}
	return as.raw
}

// ARC-Seal の文字列化
// ヘッダ名は含まない
func (as ARCSeal) String() string {
	return fmt.Sprintf("i=%d; a=%s; t=%d; cv=%s;\r\n"+
		"        d=%s; s=%s;\r\n"+
		"        b=%s",
		as.InstanceNumber, as.Algorithm, as.Timestamp, as.ChainValidation, as.Domain, as.Selector,
		header.WrapSignatureWithBreaks(as.Signature),
	)
}

// ARC-Seal のパース
func ParseARCSeal(s string) (*ARCSeal, error) {
	result := &ARCSeal{}
	result.raw = s

	// ヘッダと値に分割
	k, v := header.ParseHeaderField(s)
	if !strings.EqualFold(k, "arc-seal") {
		return nil, fmt.Errorf("invalid header field")
	}
	fields := strings.Split(v, ";")

	for _, field := range fields {
		keyValue := strings.SplitN(strings.TrimSpace(field), "=", 2)

		if len(keyValue) != 2 {
			continue
		}

		key := strings.TrimSpace(keyValue[0])
		value := header.StripWhiteSpace(keyValue[1])

		switch key {
		case "i":
			instanceNumber, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid instance number")
			}
			result.InstanceNumber = instanceNumber
		case "a":
			switch SignatureAlgorithm(value) {
			case SignatureAlgorithmRSA_SHA1:
				result.Algorithm = SignatureAlgorithmRSA_SHA1
			case SignatureAlgorithmRSA_SHA256:
				result.Algorithm = SignatureAlgorithmRSA_SHA256
			case SignatureAlgorithmED25519_SHA256:
				result.Algorithm = SignatureAlgorithmED25519_SHA256
			default:
				return nil, fmt.Errorf("invalid algorithm")
			}
		case "b":
			value = strings.ReplaceAll(value, "\r\n", "")
			value = strings.ReplaceAll(value, "\n", "")
			result.Signature = value
		case "d":
			result.Domain = value
		case "s":
			result.Selector = value
		case "t":
			timestamp, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid timestamp")
			}
			result.Timestamp = timestamp
		case "cv":
			if !isChainValidationResult(value) {
				return nil, fmt.Errorf("invalid chain validation result")
			}
			result.ChainValidation = ChainValidationResult(value)
		}
	}
	result.hashAlgo = hashAlgo(result.Algorithm)

	return result, nil
}

// ARC-Seal の署名
func (as *ARCSeal) Sign(headers []string, key crypto.Signer) error {
	// timestampを設定
	if as.Timestamp == 0 {
		as.Timestamp = time.Now().Unix()
	}
	headers = append(headers, "ARC-Seal: "+as.String())
	signature, err := header.Signer(headers, key, canonical.Relaxed)
	if err != nil {
		return err
	}
	as.Signature = signature
	return nil
}

// ARC-Seal の検証
func (as *ARCSeal) Verify(headers []string, domainKey *domainkey.DomainKey) *VerifyResult {
	// domainKeyがnilの場合はLookupDomainKeyを実行
	if domainKey == nil {
		domKey, err := domainkey.LookupARCDomainKey(as.Selector, as.Domain)
		if errors.Is(err, domainkey.ErrNoRecordFound) {
			return &VerifyResult{
				status: VerifyStatusPermErr,
				err:    fmt.Errorf("domain key is not found: %v", err),
				msg:    "domain key is not found",
			}
		} else if err != nil {
			return &VerifyResult{
				status: VerifyStatusTempErr,
				err:    fmt.Errorf("failed to lookup domain key: %v", err),
				msg:    "failed to lookup domain key",
			}
		}
		domainKey = &domKey
	}

	if as.raw == "" {
		return &VerifyResult{
			status:    VerifyStatusNeutral,
			err:       fmt.Errorf("arc seal is not found"),
			msg:       "seal is not found",
			domainKey: domainKey,
		}
	}

	// ヘッダの抽出と連結
	h := header.ExtractHeadersARC(headers, []string{"ARC-Authentication-Results", "ARC-Message-Signature", "ARC-Seal"})
	h = append(h, header.DeleteSignature(as.raw))
	h = arcHeaderSort(h)

	// ヘッダの正規化
	var s string
	for _, header := range h {
		s += canonical.Header(header, canonical.Relaxed)
	}
	s = strings.TrimSuffix(s, "\r\n")

	// 署名するヘッダをハッシュ化
	hash := as.hashAlgo.New()
	hash.Write([]byte(s))

	// 署名をbase64デコード
	signature, err := base64Decode(as.Signature)
	if err != nil {
		return &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to decode arc-seal signature: %v", err),
			msg:       "invalid signature",
			domainKey: domainKey,
		}
	}

	// 署名の検証
	decoded, err := base64Decode(domainKey.PublicKey)
	if err != nil {
		return &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to decode domainkey public key: %v", err),
			msg:       "invalid public key",
			domainKey: domainKey,
		}
	}

	// 公開鍵をパース
	pub, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		return &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to parse domainkey public key: %v", err),
			msg:       "invalid public key",
			domainKey: domainKey,
		}
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, as.hashAlgo, hash.Sum(nil), signature); err != nil {
			return &VerifyResult{
				status:    VerifyStatusFail,
				err:       fmt.Errorf("failed to verify arc-seal signature: %v", err),
				msg:       "invalid signature",
				domainKey: domainKey,
			}
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, hash.Sum(nil), signature) {
			return &VerifyResult{
				status:    VerifyStatusFail,
				err:       fmt.Errorf("failed to verify arc-seal signature: %v", err),
				msg:       "invalid signature",
				domainKey: domainKey,
			}
		}
	default:
		return &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to convert arc-seal public key to rsa or ed25519"),
			msg:       "invalid public key",
			domainKey: domainKey,
		}
	}

	return &VerifyResult{
		status:    VerifyStatusPass,
		err:       nil,
		msg:       "good signature",
		domainKey: domainKey,
	}

}

// ARCヘッダをSealで署名する順番にソートする
func arcHeaderSort(h []string) []string {
	var ret []string
	ah, err := parseARCHeaders(h)
	if err != nil {
		return ret
	}

	max := ah.getMaxInstance()

	for i := 1; i <= max; i++ {
		arc := ah.getInstance(i)
		if arc.ARCAuthenticationResults != nil && arc.ARCMessageSignature != nil && arc.ARCSeal != nil {
			ret = append(ret, arc.ARCAuthenticationResults.raw)
			ret = append(ret, arc.ARCMessageSignature.raw)
			ret = append(ret, arc.ARCSeal.raw)
		}
	}
	return ret
}

type signatures []*Signature

func (s *signatures) getInstance(i int) *Signature {
	for _, sig := range *s {
		if sig.InstanceNumber == i {
			return sig
		}
	}
	sig := &Signature{
		InstanceNumber: i,
	}
	*s = append(*s, sig)
	return sig
}

func (s *signatures) getMaxInstance() int {
	max := 0
	for _, sig := range *s {
		if sig.InstanceNumber > max {
			max = sig.InstanceNumber
		}
	}
	return max
}

func parseARCHeaders(headers []string) (*signatures, error) {
	var sigs signatures

	for _, h := range headers {
		k, _ := header.ParseHeaderField(h)
		switch strings.ToLower(k) {
		case "arc-seal":
			ret, err := ParseARCSeal(h)
			if err != nil {
				return nil, fmt.Errorf("failed to parse arc-seal: %v", err)
			}
			as := sigs.getInstance(ret.InstanceNumber)
			as.ARCSeal = ret
		case "arc-authentication-results":
			ret, err := ParseARCAuthenticationResults(h)
			if err != nil {
				return nil, fmt.Errorf("failed to parse arc-authentication-results: %v", err)
			}
			as := sigs.getInstance(ret.InstanceNumber)
			as.ARCAuthenticationResults = ret
		case "arc-message-signature":
			ret, err := ParseARCMessageSignature(h)
			if err != nil {
				return nil, fmt.Errorf("failed to parse arc-message-signature: %v", err)
			}
			as := sigs.getInstance(ret.InstanceNumber)
			as.ARCMessageSignature = ret
		}
	}

	return &sigs, nil
}
