package msg64

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"github.com/coyove/common/shoco"
)

func gen() []byte {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=`%\"|<>"

	ln := r.Intn(256)
	ret := []byte{}
	for i := 0; i < ln; i++ {
		ret = append(ret, table[r.Intn(len(table))])
	}

	return ret
}

func TestEncodeDecode(t *testing.T) {
	for c := 0; c < 100000; c++ {
		src := gen()
		buf := Encode(src)
		plain := Decode(buf)

		if plain == nil {
			t.Fatal("decoding failed nil")
		}

		if len(plain) != len(src) {
			t.Fatal("decoding failed", len(plain))
		}

		if !bytes.Equal(src, plain) {
			t.Fatal("decoding failed", buf)
		}

		buf[len(buf)/2]++
		plain = Decode(buf)
		if len(plain) != 0 {
			t.Fatalf("m-decoding failed: %v, %v", len(plain), len(src))
		}
	}
}

func BenchmarkEncode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Decode(Encode(gen()))
	}
}

func BenchmarkShocoCompress(b *testing.B) {
	for i := 0; i < b.N; i++ {
		shoco.Decompress(shoco.Compress(string(gen())))
	}
}
