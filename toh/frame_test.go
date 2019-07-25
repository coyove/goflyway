package toh

import (
	"bytes"
	"crypto/aes"
	"io/ioutil"
	"math/rand"
	"testing"
)

func TestFrame(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(rand.Uint64())
	}

	blk, _ := aes.NewCipher(key)

	data := make([]byte, 128)
	rand.Read(data)

	ff := func() *frame {
		f := &frame{
			idx:     rand.Uint32(),
			connIdx: rand.Uint64(),
			data:    make([]byte, rand.Intn(len(data))),
		}
		if rand.Intn(2) == 0 {
			f.data = nil
		} else {
			copy(f.data, data[:len(f.data)])
		}
		return f
	}

	for i := 0; i < 1e4; i++ {
		f := ff()
		root := f

		for j := 0; j < 3; j++ {
			if rand.Intn(3-j) == 0 {
				break
			}
			f.next = ff()
			f = f.next
		}

		r := ioutil.NopCloser(root.marshal(blk))

		for {
			f2, ok := parseframe(r, blk)
			if !ok || f2.idx == 0 {
				break
			}

			if root.idx != f2.idx {
				t.Fatal(root, f2)
			}

			if !bytes.Equal(root.data, f2.data) {
				t.Fatal(root.data, f2.data)
			}

			root = root.next
		}
	}
}
