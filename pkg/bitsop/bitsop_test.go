package bitsop

import (
	"math/rand"
	"testing"
	"time"

	"github.com/coyove/goflyway/pkg/shoco"
)

func gen() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const table = "abcdefghijklmnopqrstuvwxyz0123456789-."

	ln := r.Intn(256)
	ret := ""
	for i := 0; i < ln; i++ {
		ret += string(table[r.Intn(len(table))])
	}

	return ret
}

func TestCompress(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	len1, len2 := 0, 0

	test := func(str string) {
		mark := byte(r.Intn(4))
		buf := Compress(mark, str)

		mark2, str2 := Decompress(buf)
		if mark2 != mark || str2 != str {
			t.Errorf("error: \n%s\n%s", str, str2)
		}

		buf2 := shoco.Compress(string(mark) + str)
		len1 += len(buf)
		len2 += len(buf2)
	}

	for i := 0; i < 100000; i++ {
		test(gen())
	}

	test("abcdefgabcdef") // 13
	test("abc")           // 3

	t.Log(float64(len1) / float64(len2))
}

func BenchmarkCompress(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Decompress(Compress(0x01, gen()))
	}
}

func BenchmarkShocoCompress(b *testing.B) {
	for i := 0; i < b.N; i++ {
		shoco.Decompress(shoco.Compress(gen()))
	}
}
