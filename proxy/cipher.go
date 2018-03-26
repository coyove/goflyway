package proxy

import (
	"fmt"

	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/msg64"
	"github.com/coyove/goflyway/pkg/rand"

	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
)

const (
	ivLen            = 16
	sslRecordLen     = 18 * 1024 // 18kb
	streamBufferSize = 512
)

var primes = []int16{
	11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
	73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
	157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
	241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337,
	347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433,
	439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
	547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
	643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743,
	751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857,
	859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971,
	977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
	1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193,
	1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301,
	1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439,
	1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549,
	1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657,
}

type Cipher struct {
	IO io_t

	Key     string
	Block   cipher.Block
	Rand    *rand.Rand
	Partial bool
	Alias   string

	keyBuf []byte
}

func xor(blk cipher.Block, iv [ivLen]byte, buf []byte) []byte {
	bsize := blk.BlockSize()
	x := make([]byte, len(buf)/bsize*bsize+bsize)

	for i := 0; i < len(x); i += bsize {
		blk.Encrypt(x[i:], iv[:])

		for i := len(iv) - 1; i >= 0; i-- {
			if iv[i]++; iv[i] != 0 {
				break
			}
		}
	}

	for i := 0; i < len(buf); i++ {
		buf[i] ^= x[i]
	}

	return buf
}

func (gc *Cipher) getCipherStream(key *[ivLen]byte) cipher.Stream {
	if key == nil {
		return nil
	}

	return cipher.NewCTR(gc.Block, (*key)[:])
}

// Init inits the Cipher struct with key
func (gc *Cipher) Init(key string) (err error) {
	gc.Key = key
	gc.keyBuf = []byte(key)

	for len(gc.keyBuf) < 32 {
		gc.keyBuf = append(gc.keyBuf, gc.keyBuf...)
	}

	gc.Block, err = aes.NewCipher(gc.keyBuf[:32])
	gc.Rand = rand.New()

	alias := make([]byte, 16)
	gc.Block.Encrypt(alias, gc.keyBuf)
	gc.Alias = fmt.Sprintf("%X", alias[:3])

	return
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
	Query      string  `json:"q,omitempty"`
	Auth       string  `json:"a,omitempty"`
	WSToken    string  `json:"w,omitempty"`
	WSCallback byte    `json:"c,omitempty"`
	Opt        Options `json:"o"`
	Filler     uint64  `json:"f"`

	iv [ivLen]byte
}

func (gc *Cipher) newRequest() *clientRequest {
	r := &clientRequest{}
	gc.Rand.Read(r.iv[:])
	// generate a random uint64 number, this will make encryptHost() outputs different lengths of data
	r.Filler = 2 << uint64(gc.Rand.Intn(21)*3+1)
	return r
}

func (gc *Cipher) genIV(init *[4]byte, out *[ivLen]byte) {
	mul := uint32(primes[init[0]]) * uint32(primes[init[1]]) * uint32(primes[init[2]]) * uint32(primes[init[3]])
	seed := binary.LittleEndian.Uint32(gc.keyBuf[:4])

	for i := 0; i < ivLen/4; i++ {
		seed = (mul * seed) % 0x7fffffff
		binary.LittleEndian.PutUint32(out[i*4:], seed)
	}
}

// Xor is an inplace xor method, and it just returns buf then
func (gc *Cipher) Xor(buf []byte, full *[ivLen]byte, quad *[4]byte) []byte {
	if full != nil {
		return xor(gc.Block, *full, buf)
	}

	var iv [ivLen]byte
	gc.genIV(quad, &iv)
	return xor(gc.Block, iv, buf)
}

// Encrypt encrypts a string
func (gc *Cipher) Encrypt(text string, iv *[ivLen]byte) string {
	sum := msg64.Crc16s(0, text)
	buf := make([]byte, len(text)+2)
	binary.BigEndian.PutUint16(buf, sum)
	copy(buf[2:], text)
	return base64.URLEncoding.EncodeToString(xor(gc.Block, *iv, buf))
}

// Decrypt decrypts a string
func (gc *Cipher) Decrypt(text string, iv *[ivLen]byte) string {
	buf, err := base64.URLEncoding.DecodeString(text)
	if err != nil || len(buf) < 2 {
		return ""
	}

	buf = xor(gc.Block, *iv, buf)
	sum := binary.BigEndian.Uint16(buf)

	if msg64.Crc16b(0, buf[2:]) != sum {
		logg.D("invalid checksum: ", text)
		return ""
	}

	return string(buf[2:])
}
