package dkim

import (
	"fmt"
	"strings"

	"github.com/masa23/arcmilter/mmauth/internal/header"
)

type Signatures []*Signature

func (d *Signatures) GetResult() VerifyStatus {
	// DKIM署名がない場合はNone
	if d == nil {
		return VerifyStatusNone
	}
	if len(*d) == 0 {
		return VerifyStatusNone
	}
	for _, sig := range *d {
		if sig.VerifyResult.Status() != VerifyStatusPass {
			return sig.VerifyResult.Status()
		}
	}
	return VerifyStatusPass
}

func ParseDKIMHeaders(headers []string) (*Signatures, error) {
	var sigs Signatures
	for _, h := range headers {
		k, _ := header.ParseHeaderField(h)
		switch strings.ToLower(k) {
		case "dkim-signature":
			sig, err := ParseSignature(h)
			if err != nil {
				return nil, fmt.Errorf("failed to parse dkim-signature: %v", err)
			}
			sigs = append(sigs, sig)
		}
	}
	return &sigs, nil
}
