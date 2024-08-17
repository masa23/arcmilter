package bodyhash

// bodyhash bh=を計算する

import (
	"crypto"
	_ "crypto/sha1"   // sha1を使う
	_ "crypto/sha256" // sha256を使う
	"encoding/base64"
	"hash"
	"io"

	"github.com/masa23/arcmilter/mmauth/internal/canonical"
)

type BodyHash struct {
	hashAlgo crypto.Hash
	w        io.WriteCloser
	hasher   hash.Hash
	limit    int64
}

// メール本文の書き込みを行う
// ハッシュ値を計算する
func (b *BodyHash) Write(p []byte) (n int, err error) {
	// limitが設定されている場合はlimitを超えないように制限する
	if b.limit > 0 {
		l := int64(len(p))
		if l > b.limit {
			p = p[:b.limit]
			b.limit = 0
		} else {
			b.limit -= l
		}
	}
	return b.w.Write(p)
}

// メール本文の書き込みを終了する
func (b *BodyHash) Close() error {
	return b.w.Close()
}

// ハッシュ値を取得する
// 取得前にClose()を呼ぶこと
func (b *BodyHash) Get() string {
	hash := b.hasher.Sum(nil)
	return base64.StdEncoding.EncodeToString(hash)
}

// Canonicalizationとハッシュアルゴリズムを指定してBodyHasherを生成する
func NewBodyHash(canon canonical.Canonicalization, hashAlgo crypto.Hash, limit int64) *BodyHash {
	if limit < 0 {
		limit = 0
	}
	hasher := hashAlgo.New()
	bh := &BodyHash{
		hashAlgo: hashAlgo,
		hasher:   hasher,
		limit:    limit,
	}
	switch canon {
	case canonical.Simple:
		bh.w = canonical.SimpleBody(hasher)
	case canonical.Relaxed:
		bh.w = canonical.RelaxedBody(hasher)
	default:
		// 指定が不明の場合はSimpleを使う
		bh.w = canonical.SimpleBody(hasher)
	}
	return bh
}
