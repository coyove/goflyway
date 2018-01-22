package aclrouter

import (
	"testing"
)

func TestIPLookup(t *testing.T) {
	table := linesToRange(PrivateIP)
	table = sortLookupTable(table)

	in := 0
	for i := 0; i < 1<<32; i++ {

		if isIPInLookupTableI(uint32(i), table) {
			in++
		}
	}

	if in != 34668544 { // 256 * 256 * 256 * 2 + 256 * 256 * (16 + 1)
		t.Error("error IP lookup")
	}
}
