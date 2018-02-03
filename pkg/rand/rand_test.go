package rand

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	//"encoding/binary"
	"math/rand"
	"testing"
	"time"
)

func TestRand(t *testing.T) {
	r := New()
	sum := uint64(0)
	count := 10000
	for i := 0; i < count; i++ {
		go atomic.AddUint64(&sum, uint64(r.Intn(11)))
	}
	t.Log(float64(sum) / float64(count))
}

func BenchmarkRand(b *testing.B) {
	r := New()

	for i := 0; i < b.N; i++ {
		r.Intn(100)
	}
}

func BenchmarkRandRandom(b *testing.B) {
	r := New()
	buf := make([]byte, 1024)

	for i := 0; i < b.N; i++ {
		r.Read(buf[:r.Intn(1024)])
	}
}

func BenchmarkMathRandRandom(b *testing.B) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	buf := make([]byte, 1024)

	for i := 0; i < b.N; i++ {
		n := r.Intn(1024)
		for j := 0; j <= n-8; j += 8 {
			binary.BigEndian.PutUint64(buf[j:j+8], r.Uint64())
		}

		for j := 0; j < n%8; j++ {
			buf[len(buf)-1-j] = byte(r.Intn(256))
		}
	}
}

var dummy = 0

func BenchmarkRandMulti(b *testing.B) {
	r := New()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			dummy += r.Intn(100)
		}
	})
}

func BenchmarkMathRandMulti(b *testing.B) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var mu sync.Mutex

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mu.Lock()
			dummy += r.Intn(100)
			mu.Unlock()
		}
	})
}

func BenchmarkMathRand(b *testing.B) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < b.N; i++ {
		r.Intn(100)
	}
}

func BenchmarkRand64(b *testing.B) {
	r := New()

	for i := 0; i < b.N; i++ {
		r.Uint64()
	}
}

func BenchmarkMathRand64(b *testing.B) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < b.N; i++ {
		r.Uint64()
	}
}

func BenchmarkRandRead32(b *testing.B) {
	r := New()
	buf := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		r.Read(buf)
	}
}

func BenchmarkRandRead32_2(b *testing.B) {
	r := New()
	buf := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(buf, r.Uint64())
		binary.BigEndian.PutUint64(buf[8:], r.Uint64())
		binary.BigEndian.PutUint64(buf[16:], r.Uint64())
		binary.BigEndian.PutUint64(buf[24:], r.Uint64())
	}
}

func BenchmarkMathRandRead32(b *testing.B) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	buf := make([]byte, 32)

	for i := 0; i < b.N; i++ {
		for j := 0; j < 32; j++ {
			buf[j] = byte(r.Intn(256))
		}
	}
}

func BenchmarkMathRandRead32_2(b *testing.B) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	buf := make([]byte, 32)

	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(buf, r.Uint64())
		binary.BigEndian.PutUint64(buf[8:], r.Uint64())
		binary.BigEndian.PutUint64(buf[16:], r.Uint64())
		binary.BigEndian.PutUint64(buf[24:], r.Uint64())
	}
}
