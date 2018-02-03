package proxy

import (
	"encoding/base64"
	"strconv"
	"testing"
	"time"
)

func TestCipher(t *testing.T) {
	c := &Cipher{}
	c.Init(strconv.Itoa(int(time.Now().Unix())))
	t.Log("Testing Cipher")

	test := func(m byte) {
		p := make([]byte, c.Rand.Intn(20)+16)
		iv := [16]byte{}
		c.Rand.Read(p)
		c.Rand.Read(iv[:])

		str := base64.StdEncoding.EncodeToString(p)
		if c.Decrypt(c.Encrypt(str, &iv), &iv) != str {
			t.Error(str)
		}
	}

	for i := 0; i < 100; i++ {
		test(byte(c.Rand.Intn(256)))
	}
}

func BenchmarkJibber(b *testing.B) {
	r := &Cipher{}
	r.Init("12345678")

	for i := 0; i < b.N; i++ {
		r.Jibber()
	}
}
