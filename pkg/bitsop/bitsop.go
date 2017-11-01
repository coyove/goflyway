package bitsop

import (
	"strings"
)

type BitsArray struct {
	idx      int
	bit8     [8]byte
	underlay []byte
}

func NewBitsArray(ln int) *BitsArray {
	return &BitsArray{
		underlay: make([]byte, 0, ln),
	}
}

func (b *BitsArray) push(bit byte) {
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

func (b *BitsArray) Push(bits ...byte) {
	for _, bit := range bits {
		if bit != 0 && bit != 1 {
			panic("bit can only be 0 or 1")
		}

		b.push(bit)
	}
}

func (b *BitsArray) PushByte(n byte, w int) {
	if w > 8 || w < 1 {
		return
	}

	for i := w - 1; i >= 0; i-- {
		b.push((n >> byte(i)) & 0x01)
	}
}

func (b *BitsArray) GetBytes() []byte {
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

func (b *BitsArray) RemainingBitsToOneByte() int {
	return (8 - b.idx) % 8
}

var table = map[byte]byte{
	/* 000000 */ 0: 'a',
	/* 000001 */ 1: 'b',
	/* 000010 */ 2: 'c',
	/* 000011 */ 3: 'd',
	/* 000100 */ 4: 'e',
	/* 000101 */ 5: 'f',
	/* 000110 */ 6: 'g',
	/* 000111 */ 7: 'h',
	/* 001000 */ 8: 'i',
	/* 001001 */ 9: 'j',
	/* 001010 */ 10: 'k',
	/* 001011 */ 11: 'l',
	/* 001100 */ 12: 'm',
	/* 001101 */ 13: 'n',
	/* 001110 */ 14: 'o',
	/* 001111 */ 15: 'p',
	/* 010000 */ 16: 'q',
	/* 010001 */ 17: 'r',
	/* 010010 */ 18: 's',
	/* 010011 */ 19: 't',
	/* 010100 */ 20: 'u',
	/* 010101 */ 21: 'v',
	/* 010110 */ 22: 'w',
	/* 010111 */ 23: 'x',
	/* 011000 */ 24: 'y',
	/* 011001 */ 25: 'z',
	/* 011010 */ 26: '0',
	/* 011011 */ 27: '1',
	/* 011100 */ 28: '2',
	/* 011101 */ 29: '3',
	/* 011110 */ 30: '4',
	/* 011111 */ 31: '5',
	/* 100000 */ 32: '6',
	/* 100001 */ 33: '7',
	/* 100010 */ 34: '8',
	/* 100011 */ 35: '9',
	/* 100100 */ 36: 'A',
	/* 100101 */ 37: 'B',
	/* 100110 */ 38: 'C',
	/* 100111 */ 39: 'D',
	/* 101000 */ 40: 'E',
	/* 101001 */ 41: 'F',
	/* 101010 */ 42: '-',
	/* 101011 */ 43: '.',
	/* 101100 */ 44: '_',
	/* 101101 */ 45: 'H',
	/* 101110 */ 46: ':',
	/* 101111 */ 47: '/',
	/* 110000 */ 48: '?',
	/* 110001 */ 49: '#',
	/* 110010 */ 50: '+',
	/* 110011 */ 51: '%',
	/* 110100 */ 52: ',',
	/* 110101 */ 53: '!',
	/* 110110 */ 54: '=',
	/* 110111 */ 55: '&',
	/* 111000 */ 56: '*',
	/* 111001 */ 57: '(',
	/* 111010 */ 58: ')',
	/* 111011 */ 59: 'S',
	/* 111100 */ 60: 'N',

	// 111101    61: caps
	// 111110    62: raw
	// 111111    63: end
}

var itable = map[byte]byte{
	'a': 0, 'b': 1, 'c': 2, 'd': 3, 'e': 4, 'f': 5, 'g': 6,
	'h': 7, 'i': 8, 'j': 9, 'k': 10, 'l': 11, 'm': 12, 'n': 13,
	'o': 14, 'p': 15, 'q': 16, 'r': 17, 's': 18, 't': 19,
	'u': 20, 'v': 21, 'w': 22, 'x': 23, 'y': 24, 'z': 25,
	'0': 26, '1': 27, '2': 28, '3': 29, '4': 30,
	'5': 31, '6': 32, '7': 33, '8': 34, '9': 35,
	'A': 36, 'B': 37, 'C': 38, 'D': 39, 'E': 40, 'F': 41,
	'-': 42, '.': 43, '_': 44, 'H': 45, ':': 46, '/': 47,
	'?': 48, '#': 49, '+': 50, '%': 51, ',': 52, '!': 53,
	'=': 54, '&': 55, '*': 56, '(': 57, ')': 58, 'S': 59, 'N': 60,
}

func charToIdx(b byte) (byte, byte, int) {
	if b > 'F' && b <= 'Z' && b != 'S' && b != 'N' && b != 'H' {
		return 61, itable[b+'a'-'A'], 11
	}

	b2, ok := itable[b]
	if !ok {
		return 62, b, 14
	}

	return b2, 0, 6
}

func Compress(str string) []byte {
	b := NewBitsArray(len(str))

	if strings.HasPrefix(str, "https://") {
		b.PushByte(3, 2)
		str = str[8:]
	} else if strings.HasPrefix(str, "http://") {
		b.PushByte(2, 2)
		str = str[7:]
	} else {
		b.PushByte(0, 2)
	}

	for i := 0; i < len(str); i++ {
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

	w := b.RemainingBitsToOneByte()
	b.PushByte(0xFF, w)

	return b.GetBytes()
}

func Decompress(buf []byte) string {
	idx := 0
	readidx := 0

	_read := func(w int) (byte, bool) {
		if readidx >= len(buf) {
			return 0, false
		}

		curbyte := buf[readidx]
		j := 1
		n := byte(0)

		if idx+w > 8 {
			// we need next byte
			if readidx+1 >= len(buf) {
				return 0xFF, false
			}

			nextbyte := buf[readidx+1]

			b16 := uint16(curbyte)<<8 + uint16(nextbyte)

			for i := idx; i < idx+w; i++ {
				n += byte((b16 >> uint16(15-i) & 0x1) << byte(w-j))
				j++
			}

			idx = idx + w - 8
			readidx++

			return n, true
		} else {
			for i := idx; i < idx+w; i++ {
				n += (curbyte >> byte(7-i) & 0x1) << byte(w-j)
				j++
			}

			idx += w
			if idx == 8 {
				idx = 0
				readidx++
			}

			return n, true
		}
	}

	ret := make([]byte, 0, len(buf))
	b, ok := _read(2)
	if !ok {
		return ""
	}

	if b == 3 {
		ret = append(ret, 'h', 't', 't', 'p', 's', ':', '/', '/')
	} else if b == 2 {
		ret = append(ret, 'h', 't', 't', 'p', ':', '/', '/')
	}

	for b, ok := _read(6); ok; b, ok = _read(6) {
		if b == 63 {
			break
		} else if b == 62 {
			b2, ok2 := _read(8)
			if !ok2 {
				break
			}

			ret = append(ret, b2)
		} else if b == 61 {
			b2, ok2 := _read(5)
			if !ok2 {
				break
			}
			ret = append(ret, table[b2]-'a'+'A')
		} else {
			ret = append(ret, table[b])
		}
	}

	return string(ret)
}
