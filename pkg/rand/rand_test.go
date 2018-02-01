package rand

import (
	"encoding/binary"
	"math/rand"
	"testing"
	"time"
)

func TestRand(t *testing.T) {
	r := new(Rand)

	for i := 0; i < 10; i++ {
		t.Log(r.Fetch(100))
	}
}

func BenchmarkRand(b *testing.B) {
	r := new(Rand)

	for i := 0; i < b.N; i++ {
		r.Intn(100)
	}
}

func BenchmarkRand64Raw(b *testing.B) {
	r := new(Rand)
	buf := make([]byte, 8)
	for i := 0; i < b.N; i++ {
		r.Read(buf)
		binary.BigEndian.Uint64(buf)
	}
}

func BenchmarkMathRand(b *testing.B) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < b.N; i++ {
		r.Intn(100)
	}
}

func BenchmarkMathRand64Raw(b *testing.B) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < b.N; i++ {
		r.Uint64()
	}
}
