package msg64

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func genBytes() []byte {
	ln := rand.Intn(256) + 256
	buf := make([]byte, ln)

	for i := 0; i < ln; i++ {
		buf[i] = byte(rand.Intn(256))
	}

	return buf
}

func TestBase41(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	test := func() {
		buf := genBytes()
		b, ok := Base41Decode(Base41Encode(buf))

		if !ok || !bytes.Equal(b, buf) {
			t.Error(b, buf)
		}
	}

	for i := 0; i < 65536; i++ {
		test()
	}
}

func TestBase41Error(t *testing.T) {
	valid := func(in string) bool {
		for _, r := range in {
			if !strings.ContainsRune(base41Table, r) {
				return false
			}
		}

		return len(in) >= 2 || len(in) == 0
	}

	for i := 0; i < 65536; i++ {
		str := gen()
		_, ok := Base41Decode(str)
		if ok != valid(str) {
			t.Error("error testing failed:", str, ok, valid(str))
		}
	}
}

func BenchmarkBase41(b *testing.B) {
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < b.N; i++ {
		Base41Decode(Base41Encode(genBytes()))
	}
}

func BenchmarkBase32(b *testing.B) {
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < b.N; i++ {
		base32.StdEncoding.DecodeString(base32.StdEncoding.EncodeToString(genBytes()))
	}
}

func BenchmarkBase64(b *testing.B) {
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < b.N; i++ {
		base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString(genBytes()))
	}
}
