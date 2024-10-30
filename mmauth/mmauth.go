package mmauth

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/masa23/arcmilter/mmauth/internal/bodyhash"
	"github.com/masa23/arcmilter/mmauth/internal/canonical"
)

const (
	crlf = "\r\n"
)

type Canonicalization canonical.Canonicalization

const (
	CanonicalizationSimple  Canonicalization = "simple"
	CanonicalizationRelaxed Canonicalization = "relaxed"
)

// DKIM ARCの署名アルゴリズム
type SignatureAlgorithm string

const (
	SignatureAlgorithmRSA_SHA1       SignatureAlgorithm = "rsa-sha1"
	SignatureAlgorithmRSA_SHA256     SignatureAlgorithm = "rsa-sha256"
	SignatureAlgorithmED25519_SHA256 SignatureAlgorithm = "ed25519-sha256"
)

// 認証ヘッダを保持する構造体
type AuthenticationHeaders struct {
	DKIMSignatures *DKIMSignatures
	ARCSignatures  *ARCSignatures
}

func parseAuthentications(headers headers) (*AuthenticationHeaders, error) {
	d, err := ParseDKIMHeaders(headers)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dkim headers: %v", err)
	}
	a, err := ParseARCHeaders(headers)
	if err != nil {
		return nil, fmt.Errorf("failed to parse arc headers: %v", err)
	}
	return &AuthenticationHeaders{
		DKIMSignatures: d,
		ARCSignatures:  a,
	}, nil
}

func (a *AuthenticationHeaders) BodyHashCanonAndAlgo() []BodyCanonicalizationAndAlgorithm {
	var ret []BodyCanonicalizationAndAlgorithm
	for _, dkim := range *a.DKIMSignatures {
		_, body, err := parseHeaderCanonicalization(dkim.Canonicalization)
		if err != nil {
			continue
		}
		bca := BodyCanonicalizationAndAlgorithm{
			Body:      body,
			Algorithm: hashAlgo(SignatureAlgorithm(dkim.Algorithm)),
			Limit:     dkim.Limit,
		}
		if !isCcanonicalizationBodyAndAlgorithm(bca, ret) {
			ret = append(ret, bca)
		}
	}

	for _, arc := range *a.ARCSignatures {
		_, body, err := parseHeaderCanonicalization(arc.ARCMessageSignature.Canonicalization)
		if err != nil {
			continue
		}
		bca := BodyCanonicalizationAndAlgorithm{
			Body:      body,
			Algorithm: hashAlgo(SignatureAlgorithm(arc.ARCMessageSignature.Algorithm)),
		}
		if !isCcanonicalizationBodyAndAlgorithm(bca, ret) {
			ret = append(ret, bca)
		}
	}

	return ret
}

// DKIMとARCの署名の検証を行うための構造体
type MMAuth struct {
	AuthenticationHeaders *AuthenticationHeaders
	Headers               headers
	pw                    *io.PipeWriter
	pr                    *io.PipeReader
	pclose                bool
	done                  chan struct{}
	err                   error
	bodyHashList          []BodyCanonicalizationAndAlgorithm
	bodyHashed            []BodyHash
	mutex                 sync.Mutex
}

// 生成すべきBodyHashの種類を追加する
func (m *MMAuth) AddBodyHash(bca BodyCanonicalizationAndAlgorithm) {
	if isCcanonicalizationBodyAndAlgorithm(bca, m.bodyHashList) {
		return
	}
	m.bodyHashList = append(m.bodyHashList, bca)
}

// メールの分解とハッシュの計算を行う
func (m *MMAuth) parsedMail() {
	var err error
	defer func() {
		close(m.done)
		m.pr.Close()
	}()

	// ヘッダの取得
	buf := bufio.NewReader(m.pr)
	m.Headers, err = readHeader(buf)
	if err != nil {
		m.err = err
		return
	}

	// 署名のヘッダを取得
	m.AuthenticationHeaders, err = parseAuthentications(m.Headers)
	if err != nil {
		m.err = fmt.Errorf("failed to parse auth headers: %v", err)
		return
	}

	// ヘッダから必要なBodyHashの種類を全て取得しハッシュ生成対象に追加する
	bca := m.AuthenticationHeaders.BodyHashCanonAndAlgo()
	for _, bh := range bca {
		m.AddBodyHash(bh)
	}

	mbh := &multiBodyHash{}
	mbh.bodyHash(m.bodyHashList)
	b := make([]byte, 1024)
	for {
		n, err := buf.Read(b)
		if err != nil {
			if err == io.EOF {
				break
			}
			m.err = fmt.Errorf("failed to read body: %v", err)
			return
		}
		if _, err := mbh.Write(b[:n]); err != nil {
			m.err = fmt.Errorf("failed to write bodyhash: %v", err)
			return
		}
	}
	if err := mbh.Close(); err != nil {
		m.err = fmt.Errorf("failed to close bodyhash: %v", err)
		return
	}
	m.bodyHashed = mbh.Get()
}

// BodyHashの種別
type BodyHash struct {
	Algorithm *BodyCanonicalizationAndAlgorithm
	BodyHash  string
	Limit     int64
}

// 同時に複数のBodyHashを計算するための構造体
type multiBodyHash struct {
	bodyHashList []struct {
		*bodyhash.BodyHash
		*BodyCanonicalizationAndAlgorithm
		Limit int64
	}
}

// 同時に複数のBodyHashを計算するための構造体の初期化
func (mh *multiBodyHash) bodyHash(bca []BodyCanonicalizationAndAlgorithm) {
	for i, v := range bca {
		mh.bodyHashList = append(mh.bodyHashList, struct {
			*bodyhash.BodyHash
			*BodyCanonicalizationAndAlgorithm
			Limit int64
		}{
			BodyHash:                         bodyhash.NewBodyHash(canonical.Canonicalization(v.Body), v.Algorithm, v.Limit),
			BodyCanonicalizationAndAlgorithm: &bca[i],
			Limit:                            v.Limit,
		})
	}
}

// メール本文の書き込みを行う
func (mh *multiBodyHash) Write(p []byte) (n int, err error) {
	for _, v := range mh.bodyHashList {
		if _, err := v.Write(p); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// メール本文の書き込みを終了する
func (mh *multiBodyHash) Close() error {
	for _, v := range mh.bodyHashList {
		if err := v.Close(); err != nil {
			return err
		}
	}
	return nil
}

// ハッシュ値を取得する
func (mh *multiBodyHash) Get() []BodyHash {
	var ret []BodyHash
	for _, v := range mh.bodyHashList {
		ret = append(ret, BodyHash{
			Algorithm: v.BodyCanonicalizationAndAlgorithm,
			BodyHash:  v.Get(),
			Limit:     v.Limit,
		})
	}
	return ret
}

// DKIM、ARCの署名を行うための構造体の初期化
func NewMMAuth() *MMAuth {
	pr, pw := io.Pipe()
	done := make(chan struct{})
	m := &MMAuth{
		pw:   pw,
		pr:   pr,
		done: done,
	}

	// メールデータを読み込んで解析する
	go m.parsedMail()

	return m
}

// ヘッダ、本文の書き込み
func (m *MMAuth) Write(p []byte) (n int, err error) {
	n, err = m.pw.Write(p)
	if errors.Is(err, io.ErrClosedPipe) {
		return n, m.err
	}
	return
}

// メールメッセージ処理の終了
func (m *MMAuth) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 既に終了している場合は何もしない
	if m.pclose {
		return nil
	}

	// メールデータの書き込みを終了する
	err := m.pw.Close()
	m.pclose = true
	<-m.done
	return err
}

// 付与されているDKIM・ARCの署名検証を行う
func (m *MMAuth) Verify() {
	for _, d := range *m.AuthenticationHeaders.DKIMSignatures {
		can := d.GetCanonicalizationAndAlgorithm()
		if can != nil {
			bodyHash := m.GetBodyHash(BodyCanonicalizationAndAlgorithm{
				Body:      Canonicalization(can.Body),
				Algorithm: can.HashAlgo,
				Limit:     d.Limit,
			})
			d.Verify(m.Headers, bodyHash, nil)
		}
	}
	// 一番最後のARCの署名を検証する
	max := m.AuthenticationHeaders.ARCSignatures.GetMaxInstance()
	if max > 0 {
		arc := m.AuthenticationHeaders.ARCSignatures.GetInstance(max)
		can := arc.ARCMessageSignature.GetCanonicalizationAndAlgorithm()
		if can != nil {
			bodyHash := m.GetBodyHash(BodyCanonicalizationAndAlgorithm{
				Body:      Canonicalization(can.Body),
				Algorithm: can.HashAlgo,
				Limit:     0,
			})
			arc.Verify(m.Headers, bodyHash, nil)
		}
	}
}

func (m *MMAuth) GetBodyHash(bca BodyCanonicalizationAndAlgorithm) string {
	for _, bh := range m.bodyHashed {
		if bh.Algorithm.Algorithm == bca.Algorithm && bh.Algorithm.Body == bca.Body && bh.Limit == bca.Limit {
			return bh.BodyHash
		}
	}
	return ""
}
