package msg64

const base = 41
const base2 = base * 2
const bad = base + 1

const base41Table = "ABCDEFghijklmnopqrstuvwxyz0123456789=+.-_ABCDEFghijklmnopqrstuvwxyz0123456789&+.-_ABCDEFghijklmnopqrstuvwxyz0123456789?+/-_"

var offTable = [base * 3]byte{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, base, 0, 0, 0, 0,

	base, base, base, base, base, base, base, base, base, base,
	base, base, base, base, base, base, base, base, base, base,
	base, base, base, base, base, base, base, base, base, base,
	base, base, base, base, base, base, 0, base, base, base, base,

	base2, base2, base2, base2, base2, base2, base2, base2, base2, base2,
	base2, base2, base2, base2, base2, base2, base2, base2, base2, base2,
	base2, base2, base2, base2, base2, base2, base2, base2, base2, base2,
	base2, base2, base2, base2, base2, base2, 0, base2, base2, base2, base2,
}

// Base41Encode encodes bytes to string
func Base41Encode(buf []byte) string {
	i, ln, idx := 0, len(buf), 0
	off := base2
	ret := make([]byte, ln*3/2+1)

	for i < ln {
		x := int(buf[i])
		if i+1 == ln {
			m := x / base
			ret[idx] = base41Table[m+off]
			off = int(offTable[m+off])
			idx++
			x -= m*base - off
			ret[idx] = base41Table[x]
			idx++
			break
		}

		x = x<<8 + int(buf[i+1])
		m := x / base / base
		ret[idx] = base41Table[m+off]
		off = int(offTable[m+off])
		idx++
		x -= m * base * base
		m = x / base
		ret[idx] = base41Table[m+off]
		off = int(offTable[m+off])
		idx++
		x -= m*base - off
		ret[idx] = base41Table[x]
		off = int(offTable[x])
		idx++
		i += 2
	}

	return string(ret[:idx])
}

var decodeTable = [256]byte{
	42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
	42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
	42 /*   */, 42 /* ! */, 42 /* " */, 42 /* # */, 42 /* $ */, 42 /* % */, 36 /* & */, 42, /* ' */
	42 /* ( */, 42 /* ) */, 42 /* * */, 37 /* + */, 42 /* , */, 39 /* - */, 38 /* . */, 38, /* / */
	26 /* 0 */, 27 /* 1 */, 28 /* 2 */, 29 /* 3 */, 30 /* 4 */, 31 /* 5 */, 32 /* 6 */, 33, /* 7 */
	34 /* 8 */, 35 /* 9 */, 42 /* : */, 42 /* ; */, 42 /* < */, 36 /* = */, 42 /* > */, 36, /* ? */
	42 /* @ */, 00 /* A */, 01 /* B */, 02 /* C */, 03 /* D */, 04 /* E */, 05 /* F */, 42, /* G */
	42 /* H */, 42 /* I */, 42 /* J */, 42 /* K */, 42 /* L */, 42 /* M */, 42 /* N */, 42, /* O */
	42 /* P */, 42 /* Q */, 42 /* R */, 42 /* S */, 42 /* T */, 42 /* U */, 42 /* V */, 42, /* W */
	42 /* X */, 42 /* Y */, 42 /* Z */, 42 /* [ */, 42 /* \ */, 42 /* ] */, 42 /* ^ */, 40, /* _ */
	42 /* ` */, 42 /* a */, 42 /* b */, 42 /* c */, 42 /* d */, 42 /* e */, 42 /* f */, 06, /* g */
	07 /* h */, 8 /*  i */, 9 /*  j */, 10 /* k */, 11 /* l */, 12 /* m */, 13 /* n */, 14, /* o */
	15 /* p */, 16 /* q */, 17 /* r */, 18 /* s */, 19 /* t */, 20 /* u */, 21 /* v */, 22, /* w */
	23 /* x */, 24 /* y */, 25 /* z */, 42 /* { */, 42 /* | */, 42 /* } */, 42 /* ~ */, 42,
	42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
	42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
	42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
	42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
	42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
	42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
	42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
	42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
}

// Base41Decode decodes string to bytes
func Base41Decode(str string) ([]byte, bool) {
	i, ln, idx := 0, len(str), 0
	ret := make([]byte, ln*2/3)

	for i < ln {
		x1 := int(decodeTable[str[i]])
		if i+1 == ln || x1 == bad {
			return nil, false
		}

		x2 := int(decodeTable[str[i+1]])
		if x2 == bad {
			return nil, false
		}

		if i+2 == ln {
			ret[idx] = byte(x1*base + x2)
			idx++
			break
		}

		x3 := int(decodeTable[str[i+2]])
		if x3 == bad {
			return nil, false
		}

		x := x1*base*base + x2*base + x3
		m := x / 256
		ret[idx] = byte(m)
		idx++
		ret[idx] = byte(x - m*256)
		idx++
		i += 3
	}

	return ret[:idx], true
}
