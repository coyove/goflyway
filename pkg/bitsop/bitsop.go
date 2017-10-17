package bitsop

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

var table = []byte{
	/* 00000 */ 0, // a
	/* 00001 */ 1,
	/* 00010 */ 2,
	/* 00011 */ 3,
	/* 00100 */ 4,
	/* 00101 */ 5,
	/* 00110 */ 6,
	/* 00111 */ 7,
	/* 01000 */ 8,
	/* 01001 */ 9,
	/* 01010 */ 10,
	/* 01011 */ 11,
	/* 01100 */ 12,
	/* 01101 */ 13,
	/* 01110 */ 14,
	/* 01111 */ 15,
	/* 10000 */ 16,
	/* 10001 */ 17,
	/* 10010 */ 18,
	/* 10011 */ 19,
	/* 10100 */ 20,
	/* 10101 */ 21,
	/* 10110 */ 22,
	/* 10111 */ 23, //     x
	/* 11000 */ 24, //     y
	/* 11001 */ 25, //     z
	/* 11010 */ 26, //     0
	/* 11011 */ 27, //     1
	/* 11100 */ 28, //     2
	/* 11101 */ 29, //     3
	/* 11110 */ 30, //     4
	/* 11111000 */ 248, // 5
	/* 11111001 */ 249, // 6
	/* 11111010 */ 250, // 7
	/* 11111011 */ 251, // 8
	/* 11111100 */ 252, // 9
	/* 11111101 */ 253, // -
	/* 11111110 */ 254, // .
	/* 11111111 */ 255, // end
}

func charToIdx(b byte) (byte, int) {
	if b >= 'a' && b <= 'z' {
		return table[b-'a'], 5
	} else if b >= '0' && b <= '4' {
		return table[b-'0'+26], 5
	} else if b >= '5' && b <= '9' {
		return table[b-'0'+26], 8
	} else if b == '-' {
		return table[36], 8
	} else if b == '.' {
		return table[37], 8
	} else {
		return 0xFF, 0
	}
}

func idxToChar(b byte) byte {
	if b >= 0 && b <= 25 {
		return 'a' + b
	} else if b >= 26 && b <= 30 {
		return '0' + b - 26
	} else if b >= 248 && b <= 252 {
		return '5' + b - 248
	} else if b == 253 {
		return '-'
	} else if b == 254 {
		return '.'
	} else {
		return 0
	}
}

func Compress(str string) []byte {
	b := NewBitsArray(len(str))

	for i := 0; i < len(str); i++ {
		n, w := charToIdx(str[i])
		b.PushByte(n, w)
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

	for b, ok := _read(5); ok; b, ok = _read(5) {
		if b<<3>>3 == 31 {
			b2, ok2 := _read(3)
			if !ok2 {
				break
			}

			b = b<<3 + b2
		}

		ret = append(ret, idxToChar(b))
	}

	return string(ret)
}
