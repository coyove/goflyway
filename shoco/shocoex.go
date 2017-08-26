package shoco

import (
	"../lookup"

	"fmt"
	"strings"
)

func CompressHost(text string) []byte {
	if i := lookup.IPAddressToInteger(text); i > 0 {
		return []byte{
			127,
			byte(i >> 24), byte(i << 8 >> 24), byte(i << 16 >> 24), byte(i),
		}
	}

	if li := strings.LastIndex(text, "."); li > 0 {
		buf := Compress(text[:li])
		idx := getTLDIndex(strings.ToUpper(text[li+1:]))

		if idx == 0 {
			panic("serious wrong host: " + text)
		}

		if idx < 127 {
			return append([]byte{byte(idx)}, buf...)
		} else {
			h := uint16(idx) / 256
			l := uint16(idx) - h*256
			h = h | 0x80

			return append([]byte{byte(h), byte(l)}, buf...)
		}
	} else {
		panic("serious wrong host: " + text)
	}
}

func DecompressHost(buf []byte) string {
	if len(buf) < 2 {
		return ""
	}

	if uint8(buf[0]) == 127 && len(buf) == 5 {
		return fmt.Sprintf("%d.%d.%d.%d", buf[1], buf[2], buf[3], buf[4])
	}

	var idx, xs int
	if uint8(buf[0]) < 127 {
		idx = int(buf[0])
		xs = 1
	} else {
		idx = int(buf[1])
		idx += (int(buf[0]) - 128) * 256

		xs = 2
	}

	return Decompress(buf[xs:]) + "." + strings.ToLower(getIndexTLD(idx))
}
