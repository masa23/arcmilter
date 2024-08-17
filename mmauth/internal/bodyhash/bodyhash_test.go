package bodyhash

import (
	"crypto"
	"testing"

	"github.com/masa23/arcmilter/mmauth/internal/canonical"
)

func TestBodyHash(t *testing.T) {
	testCases := []struct {
		name             string
		body             string
		canonicalization canonical.Canonicalization
		hashAlgo         crypto.Hash
		limit            int64
		want             string
	}{
		{
			name:             "simple_rsa256_limit_0",
			body:             "\r\ntest",
			canonicalization: canonical.Simple,
			hashAlgo:         crypto.SHA256,
			limit:            0,
			want:             "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
		},
		{
			name:             "relaxed_1_rsa256_limit_0",
			body:             "\r\ntest",
			canonicalization: canonical.Relaxed,
			hashAlgo:         crypto.SHA256,
			limit:            0,
			want:             "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
		},
		{
			name:             "relaxed_2_rsa256_limit_0",
			body:             "hoge  \r\ntest\r\n  \r\n",
			canonicalization: canonical.Relaxed,
			hashAlgo:         crypto.SHA256,
			limit:            0,
			want:             "LqSAdhsGjY2uv8fGWJMIM2akhHN9NyGGEUlN+xik7jE=",
		},
		{
			name:             "simple_rsa256_limit_6",
			body:             "\r\ntest_aaaa",
			canonicalization: canonical.Simple,
			hashAlgo:         crypto.SHA256,
			limit:            6,
			want:             "XgF6uYzcgcROQtd83d1Evx8x2uW+SniFx69skZp5azo=",
		},
		{
			name:             "relaxed_rsa256_limit_18",
			body:             "hoge  \r\ntest\r\n  \r\n\n\nbbbb",
			canonicalization: canonical.Relaxed,
			hashAlgo:         crypto.SHA256,
			limit:            18,
			want:             "LqSAdhsGjY2uv8fGWJMIM2akhHN9NyGGEUlN+xik7jE=",
		},
		{
			name:             "simple_rsa1_limit_0",
			body:             "\r\ntest",
			canonicalization: canonical.Simple,
			hashAlgo:         crypto.SHA1,
			limit:            0,
			want:             "RncHNkkRgpHaoq2sZDSLD5ey4Pc=",
		},
		{
			name:             "relaxed_1_rsa1_limit_0",
			body:             "\r\ntest",
			canonicalization: canonical.Relaxed,
			hashAlgo:         crypto.SHA1,
			limit:            0,
			want:             "RncHNkkRgpHaoq2sZDSLD5ey4Pc=",
		},
		{
			name:             "relaxed_2_rsa1_limit_0",
			body:             "hoge  \r\ntest\r\n  \r\n",
			canonicalization: canonical.Relaxed,
			hashAlgo:         crypto.SHA1,
			limit:            0,
			want:             "A7Vq/LMkg+KV7mmH87z7XbR1/kQ=",
		},
		{
			name:             "simple_rsa1_limit_6",
			body:             "\r\ntest_aaaa",
			canonicalization: canonical.Simple,
			hashAlgo:         crypto.SHA1,
			limit:            6,
			want:             "RncHNkkRgpHaoq2sZDSLD5ey4Pc=",
		},
		{
			name:             "relaxed_rsa1_limit_18",
			body:             "hoge  \r\ntest\r\n  \r\n\n\nbbbb",
			canonicalization: canonical.Relaxed,
			hashAlgo:         crypto.SHA1,
			limit:            18,
			want:             "A7Vq/LMkg+KV7mmH87z7XbR1/kQ=",
		},
		{
			name:             "relaxed_rsa1_limit_-1",
			body:             "hoge  \r\ntest\r\n  \r\n",
			canonicalization: canonical.Relaxed,
			hashAlgo:         crypto.SHA1,
			limit:            -1,
			want:             "A7Vq/LMkg+KV7mmH87z7XbR1/kQ=",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bh := NewBodyHash(tc.canonicalization, tc.hashAlgo, tc.limit)
			bh.Write([]byte(tc.body))
			bh.Close()
			got := bh.Get()
			if got != tc.want {
				t.Errorf("want %s, but got %s", tc.want, got)
			}
		})
	}
}
