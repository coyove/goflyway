package proxy

import (
	"github.com/coyove/goflyway/pkg/counter"
	"github.com/coyove/goflyway/pkg/logg"

	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	IV_LENGTH          = 16
	SSL_RECORD_MAX     = 18 * 1024 // 18kb
	STREAM_BUFFER_SIZE = 512
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

type GCipher struct {
	Key       []byte
	KeyString string
	Block     cipher.Block
	Partial   bool
	Rand      *rand.Rand
}

type InplaceCTR struct {
	b       cipher.Block
	ctr     []byte
	out     []byte
	outUsed int
	ptr     int
}

// From src/crypto/cipher/ctr.go
func (x *InplaceCTR) XorBuffer(buf []byte) {
	for i := 0; i < len(buf); i++ {
		if x.outUsed >= len(x.out)-x.b.BlockSize() {
			// refill
			remain := len(x.out) - x.outUsed
			copy(x.out, x.out[x.outUsed:])
			x.out = x.out[:cap(x.out)]
			bs := x.b.BlockSize()
			for remain <= len(x.out)-bs {
				x.b.Encrypt(x.out[remain:], x.ctr)
				remain += bs

				// Increment counter
				for i := len(x.ctr) - 1; i >= 0; i-- {
					x.ctr[i]++
					if x.ctr[i] != 0 {
						break
					}
				}
			}
			x.out = x.out[:remain]
			x.outUsed = 0
		}

		if x.ptr == 0 && len(buf) > 10 {
			if buf[0] == 0x1f && buf[1] == 0x8b {
				// ignore the first 10 bytes of gzip
				x.ptr = 10
				x.XorBuffer(buf[10:])
				return
			}
		}

		buf[i] ^= x.out[x.outUsed]
		x.outUsed++
		x.ptr++
	}
}

func _xor(blk cipher.Block, iv, buf []byte) []byte {
	bsize := blk.BlockSize()
	x := make([]byte, len(buf)/bsize*bsize+bsize)

	for i := 0; i < len(x); i += bsize {
		blk.Encrypt(x[i:], iv)

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

func (gc *GCipher) GetCipherStream(key []byte) *InplaceCTR {
	if key == nil {
		return nil
	}

	if len(key) != IV_LENGTH {
		logg.E("iv is not 128bit long: ", key)
		return nil
	}

	dup := func(in []byte) []byte {
		ret := make([]byte, len(in))
		copy(ret, in)
		return ret
	}

	return &InplaceCTR{
		b: gc.Block,
		// key must be duplicated because it gets modified during XorBuffer
		ctr:     dup(key),
		out:     make([]byte, 0, STREAM_BUFFER_SIZE),
		outUsed: 0,
	}
}

func (gc *GCipher) New() (err error) {
	gc.Key = []byte(gc.KeyString)

	for len(gc.Key) < 32 {
		gc.Key = append(gc.Key, gc.Key...)
	}

	gc.Block, err = aes.NewCipher(gc.Key[:32])
	gc.Rand = gc.NewRand()

	return
}

func (gc *GCipher) GenerateIV(ss ...byte) []byte {
	ret := make([]byte, IV_LENGTH)

	var mul uint32 = 1
	for _, s := range ss {
		mul *= uint32(primes[s])
	}

	var seed uint32 = binary.LittleEndian.Uint32(gc.Key[:4])

	for i := 0; i < IV_LENGTH/4; i++ {
		seed = (mul * seed) % 0x7fffffff
		binary.LittleEndian.PutUint32(ret[i*4:], seed)
	}

	return ret
}

func (gc *GCipher) Encrypt(buf []byte, ss ...byte) []byte {
	r := gc.NewRand()

	if len(ss) < 2 {
		b, b2 := byte(r.Intn(256)), byte(r.Intn(256))
		return append(_xor(gc.Block, gc.GenerateIV(b, b2), buf), b, b2)
	}

	return _xor(gc.Block, gc.GenerateIV(ss...), buf)
}

func (gc *GCipher) Decrypt(buf []byte, ss ...byte) []byte {
	if len(buf) < 2 {
		return []byte{}
	}

	if len(ss) < 2 {
		b, b2 := byte(buf[len(buf)-2]), byte(buf[len(buf)-1])
		return _xor(gc.Block, gc.GenerateIV(b, b2), buf[:len(buf)-2])
	}

	return _xor(gc.Block, gc.GenerateIV(ss...), buf)
}

func (gc *GCipher) EncryptString(text string) string {
	return Base32Encode(gc.Encrypt([]byte(text)))
}

func (gc *GCipher) DecryptString(text string) string {
	buf, err := Base32Decode(text)
	if err != nil {
		return ""
	}

	return string(gc.Decrypt(buf))
}

func (gc *GCipher) NewRand() *rand.Rand {
	var k int64 = int64(binary.BigEndian.Uint64(gc.Key[:8]))
	var k2 int64 = counter.GetCounter()

	return rand.New(rand.NewSource(k2 ^ k))
}

func (gc *GCipher) RandomIV(options byte, ss ...byte) (string, []byte) {
	_rand := gc.NewRand()
	ln := IV_LENGTH + 1
	pad := _rand.Intn(4)
	retB := make([]byte, 1+pad+IV_LENGTH+4+IV_LENGTH)

	retB[0] = options

	// +---+-------+-----------+--------+
	// | 1 | pad 0 | iv 128bit | gen 4b |
	// +---+-------+-----------+--------+

	for i := pad + 1; i < ln; i++ {
		retB[i] = byte(_rand.Intn(255) + 1)
		retB[i+IV_LENGTH+4] = retB[i]
	}

	for len(ss) < 4 {
		ss = append(ss, byte(_rand.Intn(256)))
	}

	ss = ss[:4]
	return base64.StdEncoding.EncodeToString(append(_xor(gc.Block, gc.GenerateIV(ss...), retB[:ln+pad]), ss...)), retB[ln+4+pad:]
}

func (gc *GCipher) ReverseIV(key string) (byte, []byte) {
	if key == "" {
		return 0xff, nil
	}

	buf, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(buf) < 5 {
		return 0xff, nil
	}

	b, b2, b3, b4 := buf[len(buf)-4], buf[len(buf)-3], buf[len(buf)-2], buf[len(buf)-1]
	buf = _xor(gc.Block, gc.GenerateIV(b, b2, b3, b4), buf[:len(buf)-4])

	if len(buf) < IV_LENGTH+1 {
		return 0xff, nil
	}

	idx := 1
	for idx = 1; idx < len(buf); idx++ {
		if buf[idx] != 0 {
			break
		}
	}

	if len(buf[idx:]) != IV_LENGTH {
		return 0xff, nil
	}

	return buf[0], buf[idx:]
}

type IOConfig struct {
	Bucket  *TokenBucket
	Chunked bool
}

func (i *IOConfig) Dup() *IOConfig {
	return &IOConfig{
		Bucket:  i.Bucket,
		Chunked: i.Chunked,
	}
}

func (gc *GCipher) blockedIO(target, source interface{}, key []byte, options *IOConfig) {
	var wg sync.WaitGroup

	wg.Add(2)
	go gc.ioCopyOrWarn(target.(io.Writer), source.(io.Reader), key, options, &wg)
	go gc.ioCopyOrWarn(source.(io.Writer), target.(io.Reader), key, options, &wg)
	wg.Wait()
}

func (gc *GCipher) Bridge(target, source net.Conn, key []byte, options *IOConfig) {

	targetTCP, targetOK := target.(*net.TCPConn)
	sourceTCP, sourceOK := source.(*net.TCPConn)

	if targetOK && sourceOK {
		// copy from source, decrypt, to target
		go gc.ioCopyAndClose(targetTCP, sourceTCP, key, options)

		// copy from target, encrypt, to source
		go gc.ioCopyAndClose(sourceTCP, targetTCP, key, options)
	} else {
		go func() {
			gc.blockedIO(target, source, key, options)
			source.Close()
			target.Close()
		}()
	}
}

func (gc *GCipher) WrapIO(dst io.Writer, src io.Reader, key []byte, options *IOConfig) *IOCopyCipher {

	return &IOCopyCipher{
		Dst:     dst,
		Src:     src,
		Key:     key,
		Partial: gc.Partial,
		Cipher:  gc,
		Config:  options,
	}
}

func (gc *GCipher) ioCopyAndClose(dst, src *net.TCPConn, key []byte, options *IOConfig) {
	ts := time.Now()

	if _, err := gc.WrapIO(dst, src, key, options).DoCopy(); err != nil {
		logg.E("tcp.copy ", int(time.Now().Sub(ts).Seconds()), "s: ", err)
	}

	dst.CloseWrite()
	src.CloseRead()
}

func (gc *GCipher) ioCopyOrWarn(dst io.Writer, src io.Reader, key []byte, options *IOConfig, wg *sync.WaitGroup) {
	ts := time.Now()

	if _, err := gc.WrapIO(dst, src, key, options).DoCopy(); err != nil {
		logg.E("io.copy ", int(time.Now().Sub(ts).Seconds()), "s: ", err)
	}

	wg.Done()
}

type IOCopyCipher struct {
	Dst    io.Writer
	Src    io.Reader
	Key    []byte
	Cipher *GCipher
	Config *IOConfig

	// can be altered outside
	Partial bool
}

func (cc *IOCopyCipher) DoCopy() (written int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			logg.E("wtf, ", r)
		}
	}()

	buf := make([]byte, 32*1024)
	ctr := cc.Cipher.GetCipherStream(cc.Key)
	encrypted := 0
	chunked := cc.Config != nil && cc.Config.Chunked

	for {
		nr, er := cc.Src.Read(buf)
		if nr > 0 {
			xbuf := buf[0:nr]
			xs := 0

			if cc.Partial && encrypted == SSL_RECORD_MAX {
				goto direct_transmission
			}

			if ctr != nil {
				if written == 0 {
					// ignore the header
					if bytes.HasPrefix(xbuf, OK_HTTP) {
						xs = len(OK_HTTP)
					} else if bytes.HasPrefix(xbuf, OK_SOCKS) {
						xs = len(OK_SOCKS)
					}
				}

				if encrypted+nr > SSL_RECORD_MAX && cc.Partial {
					ctr.XorBuffer(xbuf[:SSL_RECORD_MAX-encrypted])
					encrypted = SSL_RECORD_MAX
					// we are done, the traffic coming later will be transfered as is
				} else {
					ctr.XorBuffer(xbuf[xs:])
					encrypted += (nr - xs)
				}

			}

		direct_transmission:
			if cc.Config != nil && cc.Config.Bucket != nil {
				cc.Config.Bucket.Consume(int64(len(xbuf)))
			}

			var nw int
			var ew error
			if chunked {
				hlen := strconv.FormatInt(int64(nr), 16)
				if _, ew = cc.Dst.Write([]byte(hlen + "\r\n")); ew == nil {
					if nw, ew = cc.Dst.Write(xbuf); ew == nil {
						_, ew = cc.Dst.Write([]byte("\r\n"))
					}
				}

			} else {
				nw, ew = cc.Dst.Write(xbuf)
			}

			if nw > 0 {
				written += int64(nw)
			}

			if ew != nil {
				err = ew
				break
			}

			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	if chunked {
		cc.Dst.Write([]byte("0\r\n\r\n"))
	}

	return written, err
}

type IOReaderCipher struct {
	Src    io.Reader
	Key    []byte
	Cipher *GCipher

	ctr *InplaceCTR
}

func (rc *IOReaderCipher) Init() *IOReaderCipher {
	rc.ctr = rc.Cipher.GetCipherStream(rc.Key)
	return rc
}

func (rc *IOReaderCipher) Read(p []byte) (n int, err error) {
	n, err = rc.Src.Read(p)
	if n > 0 && rc.ctr != nil {
		rc.ctr.XorBuffer(p[:n])
	}

	return
}
