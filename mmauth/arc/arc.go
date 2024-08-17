package arc

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/masa23/arcmilter/mmauth/domainkey"
	"github.com/masa23/arcmilter/mmauth/internal/canonical"
)

// 正規化
type Canonicalization canonical.Canonicalization

const (
	CanonicalizationSimple  Canonicalization = "simple"
	CanonicalizationRelaxed Canonicalization = "relaxed"
)

// ARC署名のアルゴリズム
type SignatureAlgorithm string

const (
	SignatureAlgorithmRSA_SHA1       SignatureAlgorithm = "rsa-sha1"
	SignatureAlgorithmRSA_SHA256     SignatureAlgorithm = "rsa-sha256"
	SignatureAlgorithmED25519_SHA256 SignatureAlgorithm = "ed25519-sha256"
)

type CanonicalizationAndAlgorithm struct {
	Header    Canonicalization
	Body      Canonicalization
	Algorithm SignatureAlgorithm
	HashAlgo  crypto.Hash
}

type VerifyStatus string

const (
	VerifyStatusNeutral VerifyStatus = "neutral"
	VerifyStatusFail    VerifyStatus = "fail"
	VerifyStatusTempErr VerifyStatus = "temperror"
	VerifyStatusPermErr VerifyStatus = "permerror"
	VerifyStatusPass    VerifyStatus = "pass"
	VerifyStatusNone    VerifyStatus = "none"
)

type VerifyResult struct {
	status    VerifyStatus
	err       error
	msg       string
	domainKey *domainkey.DomainKey
}

func (v *VerifyResult) Status() VerifyStatus {
	return v.status
}
func (v *VerifyResult) Error() error {
	return v.err
}
func (v *VerifyResult) Message() string {
	return v.msg
}

type ChainValidationResult string

const (
	ChainValidationResultPass ChainValidationResult = "pass"
	ChainValidationResultFail ChainValidationResult = "fail"
	ChainValidationResultNone ChainValidationResult = "none"
)

func isChainValidationResult(s string) bool {
	switch ChainValidationResult(s) {
	case ChainValidationResultPass, ChainValidationResultFail, ChainValidationResultNone:
		return true
	default:
		return false
	}
}

type Signature struct {
	InstanceNumber           int
	ARCSeal                  *ARCSeal
	ARCMessageSignature      *ARCMessageSignature
	ARCAuthenticationResults *ARCAuthenticationResults
	VerifyResult             *VerifyResult
}

func (arc *Signature) Verify(headers []string, bodyHash string, domainKey *domainkey.DomainKey) {
	if arc.ARCSeal == nil || arc.ARCMessageSignature == nil {
		arc.VerifyResult = &VerifyResult{
			status: VerifyStatusNeutral,
			err:    fmt.Errorf("arc is not found"),
			msg:    "arc is not found",
		}
		return
	}
	if domainKey == nil {
		domKey, err := domainkey.LookupARCDomainKey(arc.ARCSeal.Selector, arc.ARCSeal.Domain)
		if errors.Is(err, domainkey.ErrNoRecordFound) {
			arc.VerifyResult = &VerifyResult{
				status: VerifyStatusPermErr,
				err:    fmt.Errorf("domain key is not found: %v", err),
				msg:    "domain key is not found",
			}
			return
		} else if err != nil {
			arc.VerifyResult = &VerifyResult{
				status: VerifyStatusTempErr,
				err:    fmt.Errorf("failed to lookup domain key: %v", err),
				msg:    "failed to lookup domain key",
			}
			return
		}
		domainKey = &domKey
	}
	sealResult := arc.ARCSeal.Verify(headers, domainKey)
	amsResult := arc.ARCMessageSignature.Verify(headers, bodyHash, domainKey)

	// ARC-Authentication-ResultsとARC-Message-Signatureの検証結果が両方ともpassの場合はARCの検証結果をpassとする
	if sealResult.status == VerifyStatusPass && amsResult.status == VerifyStatusPass {
		arc.VerifyResult = &VerifyResult{
			status:    VerifyStatusPass,
			err:       nil,
			msg:       "good signature",
			domainKey: domainKey,
		}
		return
	}

	if sealResult.status != VerifyStatusPass {
		arc.VerifyResult = &VerifyResult{
			status:    sealResult.status,
			err:       sealResult.err,
			msg:       sealResult.msg,
			domainKey: domainKey,
		}
		return
	}

	if amsResult.status != VerifyStatusPass {
		arc.VerifyResult = &VerifyResult{
			status:    amsResult.status,
			err:       amsResult.err,
			msg:       amsResult.msg,
			domainKey: domainKey,
		}
		return
	}
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

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
