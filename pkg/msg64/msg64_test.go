package msg64

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

func TestEncodePayload(t *testing.T) {
	var p struct {
		A string
		B int
	}

	len1, len2 := 0, 0

	rand.Seed(time.Now().UnixNano())
	test := func(str string) {
		var p2 struct {
			A string
			B int
		}

		p.A = "www.freeformatter.com"
		p.B = rand.Intn(65536)

		buf := Encode("", &p)

		t.Error(Base41Encode(buf))

		str2 := Decode(buf, &p2)
		if str2 != str {
			t.Errorf("error: \n%s\n%s", str, str2)
		}

		if p.A != p2.A || p.B != p2.B {
			t.Errorf("error: \n%v\n%v", p, p2)
		}

		len1 += len(str)
		len2 += len(buf)
	}

	for i := 0; i < 1000; i++ {
		test(gen())
	}

	t.Log(float64(len2) / float64(len1))
}

func TestEncode(t *testing.T) {
	len1, len2, len3 := 0, 0, 0

	test := func(str string, v bool) {
		buf := Encode(str, nil)
		str2 := Decode(buf, nil)
		if str2 != str {
			t.Errorf("error: \n%s\n%s", str, str2)
		}

		buf2 := shoco.Compress(str)
		len1 += len(buf)
		len2 += len(buf2)
		len3 += len(str)

		if v {
			t.Log(str, buf)
		}
	}

	for i := 0; i < 10000; i++ {
		test(gen(), false)
	}

	test("abcdefgabcdef", true)            // 13
	test("abc", true)                      // 3
	test("", true)                         // 0
	test("http://www.google.com", true)    // 0
	test("https://www.facebook.com", true) // 0

	ebuf := []byte{214, 89, 106, 197, 0, 33, 1, 56, 226, 171, 243, 234, 40, 71, 25}
	t.Log(Decode(ebuf, nil))
	ebuf[2] = 105
	t.Log(Decode(ebuf, nil))
	t.Log(Decode([]byte{0}, nil))

	t.Log(float64(len1)/float64(len2), float64(len1)/float64(len3))
}

func BenchmarkEncode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Decode(Encode(gen(), nil), nil)
	}
}

func BenchmarkEncodePayload(b *testing.B) {
	var p struct {
		A string
		B int
	}

	for i := 0; i < b.N; i++ {
		Decode(Encode(gen(), &p), &p)
	}
}

func BenchmarkShocoCompress(b *testing.B) {
	for i := 0; i < b.N; i++ {
		shoco.Decompress(shoco.Compress(gen()))
	}
}
