package rand

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"
)

const bufferLen = 2016 // don't exceed 1<<32-1 and keep an integral multiple of 16 bytes
const racingLoops = 1e7
const budget = (1 << 20) / bufferLen

// Rand is a concurrent random number generator struct
type Rand struct {
	off       uint64
	reloading uint32 // 0 = Normal, 1 = Reloading buffer
	counter   uint32
	block     cipher.Block
	buffer    [bufferLen]byte
}

// New returns a new Rand struct
func New() *Rand {
	r := &Rand{}
	if _, err := rand.Read(r.buffer[:]); err != nil {
		panic(err)
	}

	r.block, _ = aes.NewCipher(r.buffer[:16])
	return r
}

// Int63 returns an int63 number
func (src *Rand) Int63() int64 {
	return int64(src.Uint64() & 0x7fffffffffffffff)
}

// Int31 returns an int31 number
func (src *Rand) Int31() int32 {
	return int32(src.Int63() >> 32)
}

// Uint64 returns an uint64 number
// It has many duplicated code from Read(), but to achieve best performance, this redundancy is necessary
func (src *Rand) Uint64() uint64 {
	i := 0
AGAIN:
	if i++; i > racingLoops {
		panic(fmt.Sprintf("racing loop in Uint64()"))
	}

	offEnd := atomic.AddUint64(&src.off, 8)
	offStart := offEnd - 8

	if offEnd > bufferLen {
		if atomic.CompareAndSwapUint32(&src.reloading, 0, 1) {
			if src.counter++; src.counter >= budget {
				if _, err := rand.Read(src.buffer[:]); err != nil {
					panic(err)
				}
				src.counter = 0
			} else {
				src.block.Encrypt(src.buffer[:], src.buffer[:])
			}

			atomic.StoreUint64(&src.off, 0)
			atomic.StoreUint32(&src.reloading, 0)
		}

		goto AGAIN
	}

	return binary.BigEndian.Uint64(src.buffer[offStart:offEnd])
}

// Intn returns an integer within [0, n)
func (src *Rand) Intn(n int) int {
	if n <= 0 {
		panic("invalid argument to Intn")
	}
	if n <= 1<<31-1 {
		return int(src.Int31n(int32(n)))
	}
	return int(src.Int63n(int64(n)))
}

// Int63n returns an integer within [0, n)
func (src *Rand) Int63n(n int64) int64 {
	if n <= 0 {
		panic("invalid argument to Int63n")
	}
	if n&(n-1) == 0 { // n is power of two, can mask
		return src.Int63() & (n - 1)
	}
	max := int64((1 << 63) - 1 - (1<<63)%uint64(n))
	v := src.Int63()
	for v > max {
		v = src.Int63()
	}
	return v % n
}

// Int31n returns an integer within [0, n)
func (src *Rand) Int31n(n int32) int32 {
	if n <= 0 {
		panic("invalid argument to Int31n")
	}
	if n&(n-1) == 0 { // n is power of two, can mask
		return src.Int31() & (n - 1)
	}
	max := int32((1 << 31) - 1 - (1<<31)%uint32(n))
	v := src.Int31()
	for v > max {
		v = src.Int31()
	}
	return v % n
}

// Perm returns an array of shuffled integers from 0 to n-1
func (src *Rand) Perm(n int) []int {
	m := make([]int, n)
	// Note we start from 1, different from the Go official
	for i := 1; i < n; i++ {
		j := src.Intn(i + 1)
		m[i] = m[j]
		m[j] = i
	}
	return m
}

// Read reads bytes into buf
// Notice that this method is lock-free but with pitfalls
func (src *Rand) Read(buf []byte) error {
	n := uint64(len(buf))

	if n > bufferLen {
		return fmt.Errorf("rand: don't read more than %d bytes in a single Read()", bufferLen)
	}

	i := 0
AGAIN:
	if i++; i > racingLoops {
		return fmt.Errorf("racing loop in Read()")
	}

	offEnd := atomic.AddUint64(&src.off, n)
	offStart := offEnd - n

	if offEnd > bufferLen {
		if atomic.CompareAndSwapUint32(&src.reloading, 0, 1) {
			// Got the spot, start reloading
			// At this point there could be other goroutines being already at "copy" stage
			// The following operation may corrupt what they copy
			if src.counter++; src.counter >= budget {
				if _, err := rand.Read(src.buffer[:]); err != nil {
					return err
				}
				src.counter = 0
			} else {
				src.block.Encrypt(src.buffer[:], src.buffer[:])
			}

			atomic.StoreUint64(&src.off, 0)
			atomic.StoreUint32(&src.reloading, 0)
		}

		goto AGAIN
	}

	// copy stage
	copy(buf, src.buffer[offStart:offEnd])
	return nil
}

// Fetch fetches n bytes
func (src *Rand) Fetch(n int) []byte {
	buf := make([]byte, n)
	if err := src.Read(buf); err != nil {
		panic(err)
	}
	return buf
}
