package proxy

import (
	"bytes"
	"fmt"
	"time"
)

var _ = fmt.Sprintf

/*
   SKIP32 -- 32 bit block cipher based on SKIPJACK.
   Written by Greg Rose, QUALCOMM Australia, 1999/04/27.
   In common: F-table, G-permutation, key schedule.
   Different: 24 round feistel structure.
   Based on:  Unoptimized test implementation of SKIPJACK algorithm
              Panu Rissanen <bande@lut.fi>
   SKIPJACK and KEA Algorithm Specifications
   Version 2.0
   29 May 1998
   Not copyright, no rights reserved.

   This is a golang implementation of skip32 algorithm written by coyove
*/

var ftable = []byte{
	0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1,
	0xaf, 0xf9, 0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e,
	0x4e, 0x38, 0x44, 0x28, 0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7,
	0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53, 0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19,
	0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2, 0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93,
	0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8, 0x55, 0xb9, 0xda, 0x85,
	0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90, 0x35, 0xd5,
	0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
	0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47,
	0x4a, 0x1d, 0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4,
	0xde, 0xc7, 0x67, 0x18, 0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74,
	0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4, 0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87,
	0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40, 0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4,
	0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5, 0xad, 0x04, 0x23, 0x9c,
	0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2, 0x0c, 0xef,
	0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
	0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6,
	0xbb, 0xac, 0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01,
	0x05, 0x59, 0x2a, 0x46,
}

var base36table = "abcdefghijklmnopqrstuvwxyz0123456789-"

func _skip32_g(key []byte, k int, w int) int {
	var g1, g2, g3, g4, g5, g6 byte

	g1 = byte(w>>8) & 0xff
	g2 = byte(w) & 0xff

	g3 = ftable[g2^key[(4*k)%10]] ^ g1
	g4 = ftable[g3^key[(4*k+1)%10]] ^ g2
	g5 = ftable[g4^key[(4*k+2)%10]] ^ g3
	g6 = ftable[g5^key[(4*k+3)%10]] ^ g4

	return (int(g5) << 8) + int(g6)
}

// key length = 10, buf length = 4
func _skip32(key []byte, buf []byte, encrypt bool) {
	var k, i, kstep int
	var wl, wr int

	/* sort out direction */
	if encrypt {
		kstep, k = 1, 0
	} else {
		kstep, k = -1, 23
	}

	/* pack into words */
	wl = (int(buf[0]) << 8) + int(buf[1])
	wr = (int(buf[2]) << 8) + int(buf[3])

	/* 24 feistel rounds, doubled up */
	for i = 0; i < 12; i++ {
		wr = wr ^ (_skip32_g(key, k, wl) ^ k)
		k += kstep
		wl = wl ^ (_skip32_g(key, k, wr) ^ k)
		k += kstep
	}

	/* implicitly swap halves while unpacking */
	buf[0] = byte(wr >> 8)
	buf[1] = byte(wr) & 0xFF
	buf[2] = byte(wl >> 8)
	buf[3] = byte(wl) & 0xFF

}

func _left_shift(buf []byte) {
	lead := buf[0]
	copy(buf[0:], buf[1:])
	buf[len(buf)-1] = lead
}

func _right_shift(buf []byte) {
	lead := buf[len(buf)-1]
	copy(buf[1:], buf[0:])
	buf[0] = lead
}

func Skip32Encode(key, buf []byte, padding bool) []byte {
	if len(key) > 10 {
		key = key[:10]
	}

	ln := len(buf)
	if ln == 0 {
		return buf
	}

	if padding {
		ts := int32(time.Now().UnixNano())
		buf = append(buf, byte(ts>>24), byte(ts>>16), byte(ts>>8), byte(ts))
	} else {
		ln -= 3
	}

	for c := 0; c < 4; c++ {
		for i := 0; i < ln; i += 4 {
			_skip32(key, buf[i:i+4], true)
		}
		_left_shift(buf)
	}

	return buf
}

func Skip32Decode(key, buf []byte, padding bool) []byte {
	if len(key) > 10 {
		key = key[:10]
	}

	ln := len(buf)
	if ln < 5 && padding {
		// buf must contain at least 1 byte + 4 bytes padding
		return buf
	}

	if ln == 0 {
		return buf
	}

	if padding {
		ln -= 4
	} else {
		ln -= 3
	}

	for c := 0; c < 4; c++ {
		_right_shift(buf)
		for i := 0; i < ln; i += 4 {
			_skip32(key, buf[i:i+4], false)
		}
	}

	if !padding {
		return buf
	}

	return buf[:ln]
}

func Base36Encode(buf []byte) string {
	ret := bytes.Buffer{}
	padded := false

	if len(buf)%2 != 0 {
		buf = append(buf, 0)
		padded = true
	}

	for i := 0; i < len(buf); i += 2 {
		n := int(buf[i])<<8 + int(buf[i+1])

		ret.WriteString(base36table[n%36 : n%36+1])
		n /= 36

		ret.WriteString(base36table[n%37 : n%37+1])
		n /= 37

		if n < 36 {
			// cheers
			ret.WriteString(base36table[n : n+1])
		} else {
			m := n % 36
			ret.WriteString("-" + base36table[m:m+1])
		}

		if padded && i == len(buf)/4*2 {
			ret.WriteString(".")
		}
	}

	return ret.String()
}

func Base36Decode(text string) []byte {
	ret := bytes.Buffer{}
	padded := false

	i := -1

	var _next func(int) (int, bool)
	_next = func(p int) (int, bool) {
		i++

		if i >= len(text) {
			return 0, false
		}

		b := text[i]

		if b >= 'a' && b <= 'z' {
			return int(b - 'a'), true
		} else if b >= '0' && b <= '9' {
			return int(b-'0') + 26, true
		} else if b == '-' {
			if p == 2 {
				return 36, true
			}

			n, ok := _next(p)
			if !ok {
				return 0, false
			}
			return n + 36, true
		} else if b == '.' && !padded {
			padded = true
			return _next(p)
		}

		return 0, false
	}

	for {
		var ok bool
		var n1, n2, n3 int

		if n1, ok = _next(1); !ok {
			break
		}

		if n2, ok = _next(2); !ok {
			break
		}

		if n3, ok = _next(3); !ok {
			break
		}

		n := n3*37*36 + n2*36 + n1
		b1 := n / 256
		b2 := n - b1*256

		ret.WriteByte(byte(b1))
		ret.WriteByte(byte(b2))
	}

	buf := ret.Bytes()
	if padded && len(buf) > 0 {
		buf = buf[:len(buf)-1]
	}
	return buf
}

func Skip32EncodeString(key []byte, text string) string {
	return Base36Encode(Skip32Encode(key, []byte(text), true))
}

func Skip32DecodeString(key []byte, text string) string {
	return string(Skip32Decode(key, Base36Decode(text), true))
}

func Skip32EncodeStringNoPadding(key []byte, text string) string {
	return Base36Encode(Skip32Encode(key, []byte(text), false))
}

func Skip32DecodeStringNoPadding(key []byte, text string) string {
	return string(Skip32Decode(key, Base36Decode(text), false))
}
