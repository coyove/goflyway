package proxy

import (
	"math/rand"
	"testing"
	"time"
)

func randomSkip() (string, []byte) {
	ret := ""
	retB := []byte{}
	_rand := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 64; i++ {
		ret += string('a' + byte(_rand.Intn(26)))
		if i < 10 {
			retB = append(retB, byte(_rand.Intn(256)))
		}
	}

	return ret, retB
}

func TestSkip32String(t *testing.T) {
	t.Log("Testing skip32 encoding and decoding")

	v, k := randomSkip()
	if v != Skip32DecodeString(k, Skip32EncodeString(k, v)) {
		t.Error("Skip32 failed")
	}
}

func TestSkip32StringNoPadding(t *testing.T) {
	t.Log("Testing skip32 encoding and decoding (w/o padding)")

	v, k := randomSkip()
	if v != Skip32DecodeStringNoPadding(k, Skip32EncodeStringNoPadding(k, v)) {
		t.Error("Skip32 failed")
	}
}

func TestSkip32StringBlank(t *testing.T) {
	t.Log("Testing blank skip32 encoding and decoding")

	_, k := randomSkip()
	if "" != Skip32DecodeString(k, Skip32EncodeString(k, "")) {
		t.Error("Skip32 failed")
	}
}

func BenchmarkSkipString(b *testing.B) {
	for n := 0; n < b.N; n++ {
		v, k := randomSkip()
		if v != Skip32DecodeString(k, Skip32EncodeString(k, v)) {
			b.Error("Skip32 failed")
		}
		// randomSkip()
	}
}
