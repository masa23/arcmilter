package arc

import (
	"fmt"
	"strings"

	"github.com/masa23/arcmilter/mmauth/internal/header"
)

type Signatures []*Signature

// インスタンス番号を指定してSignatureを取得する
func (s *Signatures) GetInstance(i int) *Signature {
	if s == nil {
		return nil
	}
	for _, sig := range *s {
		if sig.instanceNumber == i {
			return sig
		}
	}
	sig := &Signature{
		instanceNumber: i,
	}
	*s = append(*s, sig)
	return sig
}

// 最大のインスタンス番号を取得する
func (s *Signatures) GetMaxInstance() int {
	if s == nil {
		return 0
	}
	max := 0
	for _, sig := range *s {
		if sig.GetInstanceNumber() > max {
			max = sig.GetInstanceNumber()
		}
	}
	return max
}

// 最後のARCのVerify結果を文字列で取得する
func (s *Signatures) GetVerifyResultString() string {
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
	return fmt.Sprintf("arc=%s (i=%d %s)", ah.VerifyResult.Status(), ah.GetInstanceNumber(), ah.VerifyResult.Message())
}

// 最後のARCのVerify結果を取得する
func (s *Signatures) GetVerifyResult() VerifyStatus {
	if s == nil {
		return VerifyStatusNone
	}
	max := s.GetMaxInstance()
	if max == 0 {
		return VerifyStatusNone
	}

	// 最後のインスタンスの結果を取得
	ah := s.GetInstance(max)
	if ah == nil {
		return VerifyStatusNone
	}
	return ah.VerifyResult.Status()
}

// 既存のARC-SealのCV結果をチェックしarc.ChainValidationResultを返す
// i=1がNone以外の場合はFail
// それ以外のインスタンスがPassでなければFail
func (s *Signatures) GetARCChainValidation() ChainValidationResult {
	if s == nil {
		return ChainValidationResultNone
	}
	max := s.GetMaxInstance()
	// インスタンスがない場合はNone
	if max == 0 {
		return ChainValidationResultNone
	}

	// ここからインスタンスの結果をチェック
	for i := 1; i <= max; i++ {
		a := s.GetInstance(i)
		seal := a.GetARCSeal()
		if i == 1 {
			// 最初のインスタンスはnone以外許されない
			if seal.ChainValidation == ChainValidationResultNone {
				continue
			}
			return ChainValidationResultFail
		}
		// それ以外のインスタンスはPassでなければならない
		if seal.ChainValidation != ChainValidationResultPass {
			return ChainValidationResultFail
		}
	}
	return ChainValidationResultPass
}

// ARCヘッダをパースする
func ParseARCHeaders(headers []string) (*Signatures, error) {
	var sigs Signatures

	for _, h := range headers {
		k, _ := header.ParseHeaderField(h)
		switch strings.ToLower(k) {
		case "arc-seal":
			ret, err := ParseARCSeal(h)
			if err != nil {
				return nil, fmt.Errorf("failed to parse arc-seal: %v", err)
			}
			// インスタンス番号が50以上の場合はエラー
			if ret.InstanceNumber > 50 {
				return nil, fmt.Errorf("instance number is too large")
			}
			as := sigs.GetInstance(ret.InstanceNumber)
			as.arcSeal = ret
		case "arc-authentication-results":
			ret, err := ParseARCAuthenticationResults(h)
			if err != nil {
				return nil, fmt.Errorf("failed to parse arc-authentication-results: %v", err)
			}
			// インスタンス番号が50以上の場合はエラー
			if ret.InstanceNumber > 50 {
				return nil, fmt.Errorf("instance number is too large")
			}
			as := sigs.GetInstance(ret.InstanceNumber)
			as.arcAuthenticationResults = ret
		case "arc-message-signature":
			ret, err := ParseARCMessageSignature(h)
			if err != nil {
				return nil, fmt.Errorf("failed to parse arc-message-signature: %v", err)
			}
			// インスタンス番号が50以上の場合はエラー
			if ret.InstanceNumber > 50 {
				return nil, fmt.Errorf("instance number is too large")
			}
			as := sigs.GetInstance(ret.InstanceNumber)
			as.arcMessageSignature = ret
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
		if ah.arcSeal == nil || ah.arcAuthenticationResults == nil || ah.arcMessageSignature == nil {
			return nil, fmt.Errorf("arc headers are missing")
		}
	}

	return &sigs, nil
}

// ARCヘッダをSealで署名する順番にソートする
func (s *Signatures) GetARCHeaders() []string {
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
		if arc.arcAuthenticationResults != nil && arc.arcMessageSignature != nil && arc.arcSeal != nil {
			ret = append(ret, arc.arcAuthenticationResults.Raw())
			ret = append(ret, arc.arcMessageSignature.Raw())
			ret = append(ret, arc.arcSeal.Raw())
		}
	}
	return ret
}
