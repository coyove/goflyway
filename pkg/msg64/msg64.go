package msg64

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/coyove/goflyway/pkg/rand"
)

var crc16Table [256]uint16
var r *rand.Rand

func init() {
	for i := 0; i < 256; i++ {
		crc16Table[i] = uint16(0x1021 * i)
	}
	r = rand.New()
}

func Crc16n(crc uint16, b byte) uint16 {
	crc = ((crc << 8) & 0xFF00) ^ crc16Table[((crc>>8)&0xFF)^uint16(b)]
	return crc
}

func Crc16b(crc uint16, v []byte) uint16 {
	for i := 0; i < len(v); i++ {
		crc = ((crc << 8) & 0xFF00) ^ crc16Table[((crc>>8)&0xFF)^uint16(v[i])]
	}
	return crc
}

func Crc16s(crc uint16, v string) uint16 {
	for i := 0; i < len(v); i++ {
		crc = ((crc << 8) & 0xFF00) ^ crc16Table[((crc>>8)&0xFF)^uint16(v[i])]
	}
	return crc
}

type bitsArray struct {
	idx      int
	bit8     [8]byte
	underlay []byte
}

func (b *bitsArray) push(bit byte) {
	b.bit8[b.idx] = bit
	b.idx++

	if b.idx == 8 {
		n := byte(0)
		for i := 0; i < 8; i++ {
			n += b.bit8[i] << byte(7-i)
		}

		b.underlay = append(b.underlay, n)
		b.idx = 0
	}
}

func (b *bitsArray) Push(bits ...byte) {
	for _, bit := range bits {
		if bit != 0 && bit != 1 {
			panic("bit can only be 0 or 1")
		}

		b.push(bit)
	}
}

func (b *bitsArray) PushByte(n byte, w int) {
	if w > 8 || w < 1 {
		return
	}

	for i := w - 1; i >= 0; i-- {
		b.push((n >> byte(i)) & 0x01)
	}
}

func (b *bitsArray) Write(buf []byte) (int, error) {
	for _, by := range buf {
		b.PushByte(by, 8)
	}

	return len(buf), nil
}

func (b *bitsArray) GetBytes() []byte {
	buf := b.underlay

	if b.idx != 0 {
		n := byte(0)
		for i := 0; i < b.idx; i++ {
			n += b.bit8[i] << byte(7-i)
		}
		buf = append(buf, n)
	}

	return buf
}

func (b *bitsArray) RemainingBitsToOneByte() int {
	return (8 - b.idx) % 8
}

var table = []byte{
	/* 000000 0:  */ 'a',
	/* 000001 1:  */ 'b',
	/* 000010 2:  */ 'c',
	/* 000011 3:  */ 'd',
	/* 000100 4:  */ 'e',
	/* 000101 5:  */ 'f',
	/* 000110 6:  */ 'g',
	/* 000111 7:  */ 'h',
	/* 001000 8:  */ 'i',
	/* 001001 9:  */ 'j',
	/* 001010 10: */ 'k',
	/* 001011 11: */ 'l',
	/* 001100 12: */ 'm',
	/* 001101 13: */ 'n',
	/* 001110 14: */ 'o',
	/* 001111 15: */ 'p',
	/* 010000 16: */ 'q',
	/* 010001 17: */ 'r',
	/* 010010 18: */ 's',
	/* 010011 19: */ 't',
	/* 010100 20: */ 'u',
	/* 010101 21: */ 'v',
	/* 010110 22: */ 'w',
	/* 010111 23: */ 'x',
	/* 011000 24: */ 'y',
	/* 011001 25: */ 'z',
	/* 011010 26: */ '0',
	/* 011011 27: */ '1',
	/* 011100 28: */ '2',
	/* 011101 29: */ '3',
	/* 011110 30: */ '4',
	/* 011111 31: */ '5',
	/* 100000 32: */ '6',
	/* 100001 33: */ '7',
	/* 100010 34: */ '8',
	/* 100011 35: */ '9',
	/* 100100 36: */ 'A',
	/* 100101 37: */ 'B',
	/* 100110 38: */ 'C',
	/* 100111 39: */ 'D',
	/* 101000 40: */ 'E',
	/* 101001 41: */ 'F',
	/* 101010 42: */ '-',
	/* 101011 43: */ '.',
	/* 101100 44: */ '_',
	/* 101101 45: */ 'H',
	/* 101110 46: */ ':',
	/* 101111 47: */ '/',
	/* 110000 48: */ 'S',
	/* 110001 49: */ '#',
	/* 110010 50: */ '+',
	/* 110011 51: */ '%',
	/* 110100 52: */ ',',
	/* 110101 53: */ '!',
	/* 110110 54: */ '=',
	/* 110111 55: */ '&',
	/* 111000 56: */ '*',
	/* 111001 57: */ '(',
	/* 111010 58: */ ')',

	// control bits

	// 111011 59: SEP, separator
	// 111100 60: HASH, followed by 15 bits
	// 111101 61: CAPS, followed by 5 bits
	// 111110 62: RAW, followed by 8 bits, a raw byte
	// 111111 63: END, end of the message
}

const (
	_SEP  = 59
	_HASH = 60
	_CAPS = 61
	_RAW  = 62
	_END  = 63
)

var itable = map[byte]byte{
	'a': 0, 'b': 1, 'c': 2, 'd': 3, 'e': 4, 'f': 5, 'g': 6,
	'h': 7, 'i': 8, 'j': 9, 'k': 10, 'l': 11, 'm': 12, 'n': 13,
	'o': 14, 'p': 15, 'q': 16, 'r': 17, 's': 18, 't': 19,
	'u': 20, 'v': 21, 'w': 22, 'x': 23, 'y': 24, 'z': 25,
	'0': 26, '1': 27, '2': 28, '3': 29, '4': 30,
	'5': 31, '6': 32, '7': 33, '8': 34, '9': 35,
	'A': 36, 'B': 37, 'C': 38, 'D': 39, 'E': 40, 'F': 41,
	'-': 42, '.': 43, '_': 44, 'H': 45, ':': 46, '/': 47,
	'S': 48, '#': 49, '+': 50, '%': 51, ',': 52, '!': 53,
	'=': 54, '&': 55, '*': 56, '(': 57, ')': 58,
}

func charToIdx(b byte) (byte, byte, int) {
	if b > 'F' && b <= 'Z' && b != 'S' && b != 'H' {
		return _CAPS, b - 'A', 11
	}

	b2, ok := itable[b]
	if !ok {
		return _RAW, b, 14
	}

	return b2, 0, 6
}

// Encode encodes a string and a struct into a buffer
func Encode(str string, payload interface{}) []byte {
	ln := len(str)
	b := &bitsArray{underlay: make([]byte, 0, ln*2)}
	crc := Crc16s(0, str)

	var pbuf *bytes.Buffer
	if payload != nil {
		pbuf = &bytes.Buffer{}
		tmp, _ := json.Marshal(payload)
		json.Compact(pbuf, tmp)
		crc = Crc16b(crc, pbuf.Bytes())
	}

	if strings.HasPrefix(str, "https://") {
		b.PushByte(3, 2)
		str = str[8:]
	} else if strings.HasPrefix(str, "http://") {
		b.PushByte(2, 2)
		str = str[7:]
	} else {
		b.PushByte(0, 2)
	}

	ln = len(str)
	inserted := false
	for i := 0; i < ln; i++ {
		if !inserted && r.Intn(ln-i) == 0 {
			b.PushByte(_HASH, 6)
			b.PushByte(byte(crc>>8), 7)
			b.PushByte(byte(crc), 8)
			inserted = true
		}

		n, n2, w := charToIdx(str[i])
		switch w {
		case 6:
			b.PushByte(n, w)
		case 11:
			b.PushByte(n, 6)
			b.PushByte(n2, 5)
		case 14:
			b.PushByte(n, 6)
			b.PushByte(n2, 8)
		}
	}

	if payload != nil {
		b.PushByte(_SEP, 6)
		b.Write(pbuf.Bytes())
	}

	w := b.RemainingBitsToOneByte()
	b.PushByte(0xFF, w)

	return b.GetBytes()
}

type msgReader struct {
	buf          []byte
	idx, readidx int
	beforeEOF    bool
	crc          uint16
}

func (m *msgReader) Read(buf []byte) (int, error) {
	if m.beforeEOF {
		return 0, io.EOF
	}

	for i := 0; i < len(buf); i++ {
		b, ok := m.read(8)
		if !ok {
			m.beforeEOF = true
			return i, nil
		}

		buf[i] = b
		m.crc = Crc16n(m.crc, b)
	}

	return len(buf), nil
}

func (m *msgReader) read(w int) (byte, bool) {
	if m.readidx >= len(m.buf) {
		return 0, false
	}

	curbyte := m.buf[m.readidx]
	// j := 1
	n := byte(0)

	if m.idx+w > 8 {
		// we need next byte
		if m.readidx+1 >= len(m.buf) {
			return 0xFF, false
		}

		nextbyte := m.buf[m.readidx+1]

		b16 := uint16(curbyte)<<8 + uint16(nextbyte)

		// for i := idx; i < idx+w; i++ {
		// 	n += byte((b16 >> uint16(15-i) & 0x1) << byte(w-j))
		// 	j++
		// }
		n = byte((b16 >> uint(16-m.idx-w)) & (1<<uint(w) - 1))

		m.idx += w - 8
		m.readidx++

		return n, true
	}
	// for i := idx; i < idx+w; i++ {
	// 	n += (curbyte >> byte(7-i) & 0x1) << byte(w-j)
	// 	j++
	// }
	n = byte((curbyte >> uint(8-m.idx-w)) & (1<<uint(w) - 1))

	m.idx += w
	if m.idx == 8 {
		m.idx = 0
		m.readidx++
	}

	return n, true
}

// Decode decodes the buffer into a struct and a string
func Decode(buf []byte, payload interface{}) string {
	src := &msgReader{buf: buf}

	ret := make([]byte, 0, len(buf))
	b, ok := src.read(2)
	if !ok {
		return ""
	}

	if b == 3 {
		ret = append(ret, 'h', 't', 't', 'p', 's', ':', '/', '/')
	} else if b == 2 {
		ret = append(ret, 'h', 't', 't', 'p', ':', '/', '/')
	}

	var crc uint16
READ:
	for b, ok := src.read(6); ok; b, ok = src.read(6) {
		switch b {
		case _END:
			break READ
		case _RAW:
			b2, ok2 := src.read(8)
			if !ok2 {
				break READ
			}

			ret = append(ret, b2)
		case _CAPS:
			b2, ok2 := src.read(5)
			if !ok2 {
				break READ
			}
			ret = append(ret, b2+'A')
		case _HASH:
			b2, ok2 := src.read(7)
			b3, ok3 := src.read(8)
			if !ok3 || !ok2 {
				break READ
			}

			crc = uint16(b2)<<8 + uint16(b3)
		case _SEP:
			src.crc = Crc16b(0, ret)
			dec := json.NewDecoder(src)
			if payload != nil {
				if dec.Decode(payload) != nil {
					return ""
				}
			}
			goto VERIFY
		default:
			ret = append(ret, table[b])
		}
	}

	src.crc = Crc16b(0, ret)

VERIFY:
	if (src.crc & 0x7FFF) == crc {
		return string(ret)
	}

	return ""
}
