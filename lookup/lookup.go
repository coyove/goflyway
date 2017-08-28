package lookup

import (
	. "../config"
	"../logg"

	"net"
	"strconv"
	"strings"
)

var IPv4LookupTable [][]uint32
var IPv4PrivateLookupTable [][]uint32

type China_list_t map[string]interface{}

var ChinaList China_list_t

func init() {
	IPv4LookupTable, IPv4PrivateLookupTable = make([][]uint32, 0), make([][]uint32, 0)

	fill := func(table *[][]uint32, iplist string) {
		lastIPStart, lastIPEnd := -1, -1

		for _, iprange := range strings.Split(iplist, "\n") {
			p := strings.Split(iprange, " ")
			ipstart, ipend := IPAddressToInteger(p[0]), IPAddressToInteger(p[1])

			if lastIPStart == -1 {
				lastIPStart, lastIPEnd = ipstart, ipend
				continue
			}

			if ipstart != lastIPEnd+1 {
				*table = append(*table, []uint32{uint32(lastIPStart), uint32(lastIPEnd)})
				lastIPStart = ipstart
			}

			lastIPEnd = ipend
		}
	}

	fill(&IPv4LookupTable, CHN_IP)
	fill(&IPv4PrivateLookupTable, PRIVATE_IP)
}

func IPInLookupTable(ip string, table [][]uint32) bool {
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

	return rec(table)
}

func IsChineseWebsite(host string) bool {
	subs := strings.Split(host, ".")
	if len(subs) <= 1 {
		return false
	}

	top := ChinaList
	for i := len(subs) - 1; i >= 0; i-- {
		sub := subs[i]
		if top[sub] == nil {
			if v, eol := top["_"].(bool); v && eol {
				return true
			}

			return false
		}

		top = top[sub].(China_list_t)
	}

	return true
}

func IsChineseIP(ip string) bool {
	if *G_ProxyAll {
		return false
	}

	return IPInLookupTable(ip, IPv4LookupTable)
}

func IsPrivateIP(ip string) bool {
	return IPInLookupTable(ip, IPv4PrivateLookupTable)
}

func LookupIP(host string) string {
	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		logg.L("[DNS] ", err)
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
		n, err := strconv.Atoi(p[i])
		// exception: 68.media.tumblr.com
		if err != nil {
			return 0
		}

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
