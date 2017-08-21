package lookup

import (
	"../logg"

	"net"
	"strconv"
	"strings"
)

var IPv4LookupTable [][]uint32

func init() {
	IPv4LookupTable = make([][]uint32, 0)
	lastIPStart, lastIPEnd := -1, -1

	for _, iprange := range strings.Split(CHN_IP, "\n") {
		p := strings.Split(iprange, " ")
		ipstart, ipend := IPAddressToInteger(p[0]), IPAddressToInteger(p[1])

		if lastIPStart == -1 {
			lastIPStart, lastIPEnd = ipstart, ipend
			continue
		}

		if ipstart != lastIPEnd+1 {
			IPv4LookupTable = append(IPv4LookupTable, []uint32{uint32(lastIPStart), uint32(lastIPEnd)})
			lastIPStart = ipstart
		}

		lastIPEnd = ipend
	}
}

func IPInLookupTable(ip string) bool {
	m := uint32(IPAddressToInteger(ip))
	if m == 0 {
		return false
	}

	var rec func([][]uint32) bool
	rec = func(r [][]uint32) bool {
		if len(r) == 0 {
			return false
		}

		mid := len(r) / 2
		if m >= r[mid][0] && m < r[mid][1] {
			return true
		}

		if m < r[mid][0] {
			return rec(r[:mid])
		}

		return rec(r[mid+1:])
	}

	return rec(IPv4LookupTable)
}

func LookupIP(host string) string {
	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		logg.L("dns lookup: ", err)
		return ""
	}

	return ip.String()
}

func IPAddressToInteger(ip string) int {
	p := strings.Split(ip, ".")
	if len(p) != 4 {
		return 0
	}

	np := 0
	for i := 0; i < 4; i++ {
		n, _ := strconv.Atoi(p[i])
		for j := 3; j > i; j-- {
			n *= 256
		}
		np += n
	}

	return np
}

func LookupIPInt(host string) int {
	return IPAddressToInteger(LookupIP(host))
}
