package bitsop

import (
	"math/rand"
	"testing"
	"time"

	"github.com/coyove/goflyway/pkg/shoco"
)

func gen() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=`%\"|<>"

	ln := r.Intn(256)
	ret := ""
	for i := 0; i < ln; i++ {
		ret += string(table[r.Intn(len(table))])
	}

	return ret
}

func TestCompress(t *testing.T) {
	len1, len2 := 0, 0

	test := func(str string) {
		buf := Compress(str)

		str2 := Decompress(buf)
		if str2 != str {
			t.Errorf("error: \n%s\n%s", str, str2)
		}

		buf2 := shoco.Compress(str)
		len1 += len(buf)
		len2 += len(buf2)
	}

	for i := 0; i < 100000; i++ {
		test(gen())
	}

	test("abcdefgabcdef")            // 13
	test("abc")                      // 3
	test("")                         // 0
	test("http://www.google.com")    // 0
	test("https://www.facebook.com") // 0

	t.Log(float64(len1) / float64(len2))
}

func BenchmarkCompress(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Decompress(Compress(gen()))
	}
}

func BenchmarkShocoCompress(b *testing.B) {
	for i := 0; i < b.N; i++ {
		shoco.Decompress(shoco.Compress(gen()))
	}
}
