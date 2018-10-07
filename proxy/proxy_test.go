package proxy

import (
	"encoding/base64"
	"strconv"
	"testing"
	"time"
)

func TestCipher(t *testing.T) {
	c := NewCipher(strconv.Itoa(int(time.Now().Unix())), false)
	t.Log("Testing Cipher")

	test := func(m byte) {
		p := make([]byte, c.Rand.Intn(20)+16)
		iv := [16]byte{}
		c.Rand.Read(p)
		c.Rand.Read(iv[:])

		str := base64.StdEncoding.EncodeToString(p)
		if xstr, _ := c.Decrypt(c.Encrypt(str, iv), iv); xstr != str {
			t.Error(str, xstr)
		}
	}

	for i := 0; i < 100; i++ {
		test(byte(c.Rand.Intn(256)))
	}
}

func BenchmarkJibber(b *testing.B) {
	r := NewCipher("12345678", false)

	for i := 0; i < b.N; i++ {
		r.Jibber()
	}
}
