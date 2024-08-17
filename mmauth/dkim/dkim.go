package dkim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/masa23/arcmilter/mmauth/domainkey"
	"github.com/masa23/arcmilter/mmauth/internal/canonical"
	"github.com/masa23/arcmilter/mmauth/internal/header"
)

// 正規化
type Canonicalization canonical.Canonicalization

const (
	CanonicalizationSimple  Canonicalization = "simple"
	CanonicalizationRelaxed Canonicalization = "relaxed"
)

// DKIMの署名アルゴリズム
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
	Limit     int64
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

type Signature struct {
	Algorithm           SignatureAlgorithm // a algorithm
	Signature           string             // b signature
	BodyHash            string             // bh body hash
	Canonicalization    string             // c canonicalization
	Domain              string             // d domain
	Headers             string             // h headers
	Identity            string             // i identity
	Limit               int64              // l limit length
	QueryType           string             // q query
	Selector            string             // s selector
	Timestamp           int64              // t timestamp
	Version             int                // v version
	SignatureExpiration int64              // x signature expiration
	VerifyResult        *VerifyResult
	raw                 string
	canonnAndAlog       *CanonicalizationAndAlgorithm
}

func (ds *Signature) GetCanonicalizationAndAlgorithm() *CanonicalizationAndAlgorithm {
	return ds.canonnAndAlog
}

func (ds *Signature) String() string {
	return fmt.Sprintf("a=%s; bh=%s;\r\n"+
		"        c=%s; d=%s;\r\n"+
		"        h=%s;\r\n"+
		"        s=%s; t=%d; v=%d;\r\n"+
		"        b=%s",
		ds.Algorithm, ds.BodyHash,
		ds.Canonicalization, ds.Domain,
		ds.Headers,
		ds.Selector, ds.Timestamp, ds.Version,
		header.WrapSignatureWithBreaks(ds.Signature),
	)
}

func (ds *Signature) ResultString() string {
	if ds.VerifyResult == nil || ds.VerifyResult.status == VerifyStatusNeutral || ds.VerifyResult.status == VerifyStatusNone {
		return "dkim=none"
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("dkim=%s (%s)", ds.VerifyResult.Status(), ds.VerifyResult.Message()))

	if ds.Domain != "" {
		result.WriteString(fmt.Sprintf(" header.d=%s", ds.Domain))
	}
	if ds.Selector != "" {
		result.WriteString(fmt.Sprintf(" header.s=%s", ds.Selector))
	}
	if ds.Identity != "" {
		result.WriteString(fmt.Sprintf(" header.i=%s", ds.Identity))
	}
	return result.String()
}

// DKIM-SignatureヘッダをパースしDKIMSignatureを返す
func ParseSignature(s string) (*Signature, error) {
	result := &Signature{}
	result.raw = s

	// ヘッダと値に分割
	k, v := header.ParseHeaderField(s)
	if !strings.EqualFold(k, "dkim-signature") {
		return nil, fmt.Errorf("invalid header field")
	}
	params, err := header.ParseHeaderParams(v)
	if err != nil {
		return nil, fmt.Errorf("failed to parse header field: %v", err)
	}

	for key, value := range params {
		value = header.StripWhiteSpace(value)
		switch key {
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
			result.Signature = value
		case "bh":
			result.BodyHash = value
		case "c":
			result.Canonicalization = value
		case "d":
			result.Domain = value
		case "h":
			result.Headers = value
		case "i":
			result.Identity = value
		case "l":
			limit, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid limit for 'l' field: %s", value)
			}
			if limit < 0 {
				return nil, fmt.Errorf("invalid limit for 'l' field: %s", value)
			}
			result.Limit = limit
		case "q":
			result.QueryType = value
		case "s":
			result.Selector = value
		case "t":
			timestamp, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid timestamp")
			}
			result.Timestamp = timestamp
		case "v":
			version, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid version")
			}
			result.Version = version
		case "x":
			expiration, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid signature expiration")
			}
			result.SignatureExpiration = expiration
		}
	}

	canHeader, canBody, err := header.ParseHeaderCanonicalization(result.Canonicalization)
	if err != nil {
		return nil, err
	}
	result.canonnAndAlog = &CanonicalizationAndAlgorithm{
		Header:    Canonicalization(canHeader),
		Body:      Canonicalization(canBody),
		Algorithm: result.Algorithm,
		Limit:     result.Limit,
		HashAlgo:  hashAlgo(result.Algorithm),
	}

	return result, nil
}

// DKIMSignatureに署名を行う
func (d *Signature) Sign(headers []string, key crypto.Signer) error {
	// DKIM Version Check
	if d.Version != 1 {
		return errors.New("dkim: invalid version")
	}
	// headersのヘッダ名を抽出する
	var h []string
	for _, header := range headers {
		k, _, ok := strings.Cut(header, ":")
		if !ok {
			continue
		}
		h = append(h, k)
	}
	canHeader, _, err := header.ParseHeaderCanonicalization(d.Canonicalization)
	if err != nil {
		return err
	}
	d.Headers = strings.Join(h, ":")
	// timestampを設定
	if d.Timestamp == 0 {
		d.Timestamp = time.Now().Unix()
	}
	headers = append(headers, "DKIM-Signature: "+d.String())
	signature, err := header.Signer(headers, key, canHeader)
	if err != nil {
		return err
	}
	d.Signature = signature
	return nil
}

// DKIMSignatureを検証する
// domainKeyがnilの場合はLookupDomainKeyを実行
func (d *Signature) Verify(headers []string, bodyHash string, domainKey *domainkey.DomainKey) {
	// domainKeyがnilの場合はLookupDomainKeyを実行
	if domainKey == nil {
		domKey, err := domainkey.LookupDKIMDomainKey(d.Selector, d.Domain)
		if errors.Is(err, domainkey.ErrNoRecordFound) {
			d.VerifyResult = &VerifyResult{
				status: VerifyStatusPermErr,
				err:    fmt.Errorf("domain key is not found: %v", err),
				msg:    "domain key is not found",
			}
		} else if err != nil {
			d.VerifyResult = &VerifyResult{
				status: VerifyStatusTempErr,
				err:    fmt.Errorf("failed to lookup domain key: %v", err),
				msg:    "failed to lookup domain key",
			}
		}
		domainKey = &domKey
	}

	// ToDo: テストモードの確認
	testFlagMsg := ""
	if domainKey.IsTestFlag() {
		testFlagMsg = " test mode"
	}

	// service typeの確認
	if !domainKey.IsService(domainkey.ServiceTypeEmail) {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("domain key service type is invalid: %v", domainKey.ServiceType),
			msg:       "service type is invalid" + testFlagMsg,
			domainKey: domainKey,
		}
	}

	// i=がある場合はfromDomainと一致しているか確認
	from := header.ExtractHeader(headers, "From")
	fromDomain, err := header.ParseAddressDomain(from)
	if err != nil {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to parse from domain: %v", err),
			msg:       "failed to parse from domain" + testFlagMsg,
			domainKey: domainKey,
		}
	}
	if d.Identity != "" {
		if !strings.HasSuffix(d.Identity, "@"+fromDomain) && !strings.HasSuffix(d.Identity, "."+fromDomain) {
			d.VerifyResult = &VerifyResult{
				status: VerifyStatusFail,
				err:    fmt.Errorf("DKIM-Signature identity domain mismatch: Identify=%s fromDomain=%s", d.Identity, fromDomain),
				msg:    "identity is mismatch" + testFlagMsg,
			}
		}
	}

	// DKIM-Signatureがない場合はneutral
	if d.raw == "" {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusNeutral,
			err:       errors.New("DKIM-Signature is not found"),
			msg:       "sign is not found" + testFlagMsg,
			domainKey: domainKey,
		}
	}
	// バージョンを検証
	if d.Version != 1 {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("DKIM-Signature version is invalid: %d", d.Version),
			msg:       "version is invalid" + testFlagMsg,
			domainKey: domainKey,
		}
	}
	// exireを検証
	// TimestampとSignatureExpirationがセットされてない場合は検証しない
	if d.SignatureExpiration != 0 {
		// 現在時刻がSignatureExpirationを超えていたらFail
		now := time.Now().Unix()
		if now > d.SignatureExpiration {
			d.VerifyResult = &VerifyResult{
				status:    VerifyStatusFail,
				err:       fmt.Errorf("DKIM-Signature is expired: now=%d expiration=%d", now, d.SignatureExpiration),
				msg:       "signature is expired" + testFlagMsg,
				domainKey: domainKey,
			}
		}
		if d.Timestamp > d.SignatureExpiration {
			d.VerifyResult = &VerifyResult{
				status:    VerifyStatusPermErr,
				err:       fmt.Errorf("DKIM-Signature timestamp is invalid: timestamp=%d expiration=%d", d.Timestamp, d.SignatureExpiration),
				msg:       "timestamp is invalid" + testFlagMsg,
				domainKey: domainKey,
			}
		}
	}
	// ボディーハッシュを検証
	if d.BodyHash != bodyHash {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusFail,
			err:       fmt.Errorf("DKIM-Signature body hash is not match: %s != %s", d.BodyHash, bodyHash),
			msg:       "body hash is not match" + testFlagMsg,
			domainKey: domainKey,
		}
	}

	// ヘッダの抽出と連結
	h := header.ExtractHeadersDKIM(headers, strings.Split(d.Headers, ":"))
	h = append(h, header.DeleteSignature(d.raw))

	// ヘッダの正規化
	var s string
	for _, header := range h {
		s += canonical.Header(header, canonical.Canonicalization(d.canonnAndAlog.Header))
	}
	// 末尾のCRLFを削除
	s = strings.TrimSuffix(s, "\r\n")

	// 署名をbase64デコード
	signature, err := base64Decode(d.Signature)
	if err != nil {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusFail,
			err:       fmt.Errorf("failed to decode signature: %v", err),
			msg:       "invalid signature" + testFlagMsg,
			domainKey: domainKey,
		}
	}

	// 署名するヘッダをハッシュ化
	hash := d.canonnAndAlog.HashAlgo.New()
	hash.Write([]byte(s))

	// 署名を検証
	// public keyをbase64デコード
	decoded, err := base64Decode(domainKey.PublicKey)
	if err != nil {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to decode public key: %v", err),
			msg:       "invalid public key" + testFlagMsg,
			domainKey: domainKey,
		}
	}

	// 公開鍵をパース
	pub, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("failed to parse public key: %v", err),
			msg:       "invalid public key" + testFlagMsg,
			domainKey: domainKey,
		}
	}

	// RSAかed25519の公開鍵か確認
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		// 署名を検証
		if err := rsa.VerifyPKCS1v15(pub, d.canonnAndAlog.HashAlgo, hash.Sum(nil), signature); err != nil {
			d.VerifyResult = &VerifyResult{
				status:    VerifyStatusFail,
				err:       fmt.Errorf("failed to verify signature: %v", err),
				msg:       "invalid signature" + testFlagMsg,
				domainKey: domainKey,
			}
		}
	case ed25519.PublicKey:
		// 署名を検証
		if !ed25519.Verify(pub, hash.Sum(nil), signature) {
			d.VerifyResult = &VerifyResult{
				status:    VerifyStatusFail,
				err:       fmt.Errorf("failed to verify signature: %v", err),
				msg:       "invalid signature" + testFlagMsg,
				domainKey: domainKey,
			}
		}
	default:
		d.VerifyResult = &VerifyResult{
			status:    VerifyStatusPermErr,
			err:       fmt.Errorf("invalid public key type: %T", pub),
			msg:       "invalid public key" + testFlagMsg,
			domainKey: domainKey,
		}
	}

	d.VerifyResult = &VerifyResult{
		status:    VerifyStatusPass,
		err:       nil,
		msg:       "good signature" + testFlagMsg,
		domainKey: domainKey,
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
