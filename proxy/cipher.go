package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	"github.com/coyove/common/rand"
	"github.com/coyove/goflyway/pkg/msg64"
)

type _CipherMode byte

const (
	ivLen            = 16
	sslRecordLen     = 18 * 1024 // 18kb
	streamBufferSize = 512
)

const (
	FullCipher _CipherMode = iota
	PartialCipher
	NoneCipher
)

type Cipher struct {
	IO     io_t
	Key    string
	keyBuf []byte
	Block  cipher.Block
	GCM    cipher.AEAD
	Rand   *rand.Rand
	Mode   _CipherMode
	Alias  string
}

func (gc *Cipher) getCipherStream(key [ivLen]byte) cipher.Stream {
	if key == [ivLen]byte{} {
		return nil
	}

	return cipher.NewCTR(gc.Block, key[:])
}

// NewCipher createa a new cipher object
func NewCipher(key string, mode _CipherMode) *Cipher {
	gc := &Cipher{}

	gc.Rand = rand.New()
	gc.Mode = mode
	gc.Key = key
	gc.keyBuf = []byte(key)

	for len(gc.keyBuf) < 16 {
		gc.keyBuf = append(gc.keyBuf, gc.keyBuf...)
	}

	gc.Block, _ = aes.NewCipher(gc.keyBuf[:16])
	if gc.Block == nil {
		panic("invalid key")
	}

	gc.GCM, _ = cipher.NewGCM(gc.Block)
	if gc.GCM == nil {
		panic("invalid AEAD")
	}

	alias := make([]byte, 16)
	gc.Block.Encrypt(alias, gc.keyBuf)
	gc.Alias = fmt.Sprintf("%x", alias)[:7]

	return gc
}

func (gc *Cipher) Jibber() string {
	const (
		vowels = "aeioutr" // t, r are specials
		cons   = "bcdfghlmnprst"
	)

	s := gc.Rand.Intn(20)
	b := (vowels + cons)[s]

	var ret buffer
	ret.WriteByte(b)
	ln := gc.Rand.Intn(10) + 5

	if s < 7 {
		ret.WriteByte(cons[gc.Rand.Intn(13)])
	}

	for i := 0; i < ln; i += 2 {
		ret.WriteByte(vowels[gc.Rand.Intn(7)])
		ret.WriteByte(cons[gc.Rand.Intn(13)])
	}

	ret.Truncate(ln)
	return ret.String()
}

type clientRequest struct {
	Real  string
	Query string
	Auth  string
	Opt   Options

	// IV will also be used as nonce and it will be stored in plain text without marshalling
	IV [ivLen]byte
}

func (cr *clientRequest) Marshal() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(byte(cr.Opt))
	buf.WriteByte(byte(cr.Opt >> 8))
	tmp := []byte(cr.Real)
	tmp = append(tmp, 1)
	tmp = append(tmp, []byte(cr.Query)...)
	tmp = append(tmp, 1)
	tmp = append(tmp, []byte(cr.Auth)...)
	buf.Write(msg64.Encode(tmp))
	return buf.Bytes()
}

func (cr *clientRequest) Unmarshal(buf []byte) error {
	if len(buf) < 5 {
		return fmt.Errorf("invalid buffer")
	}
	cr.Opt = Options(uint32(buf[1])<<8 + uint32(buf[0]))

	buf = buf[2:]

	tmp := msg64.Decode(buf)
	if len(tmp) == 0 {
		return fmt.Errorf("invalid msg64 buffer")
	}

	parts := bytes.Split(tmp, []byte{1})
	if len(parts) < 3 {
		return fmt.Errorf("invalid buffer")
	}
	cr.Real = string(parts[0])
	cr.Query = string(parts[1])
	cr.Auth = string(parts[2])

	return nil
}

func (gc *Cipher) newRequest() *clientRequest {
	r := &clientRequest{}
	gc.Rand.Read(r.IV[:])
	return r
}

// Encrypt encrypts a string
func (gc *Cipher) Encrypt(text string, iv [ivLen]byte) string {
	return base64.URLEncoding.EncodeToString(gc.GCM.Seal(
		nil, iv[:12], []byte(text), nil,
	))
}

// Decrypt decrypts a string
func (gc *Cipher) Decrypt(text string, iv [ivLen]byte) (string, error) {
	buf, err := base64.URLEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}

	buf, err = gc.GCM.Open(nil, iv[:12], buf, nil)
	return string(buf), err
}
