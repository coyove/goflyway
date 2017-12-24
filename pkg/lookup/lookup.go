package lookup

import (
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
)

var IPv4LookupTable [][]uint32
var IPv4PrivateLookupTable [][]uint32

type China_list_t map[string]interface{}

var ChinaList China_list_t
var listLoaded bool

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

		if lastIPStart > -1 && lastIPEnd >= lastIPStart {
			*table = append(*table, []uint32{uint32(lastIPStart), uint32(lastIPEnd)})
		}
	}

	fill(&IPv4LookupTable, CHN_IP)
	fill(&IPv4PrivateLookupTable, PRIVATE_IP)
}

func LoadOrCreateChinaList(raw string) bool {
	if listLoaded {
		return false
	}

	if raw == "" {
		buf, err := ioutil.ReadFile("./chinalist.txt")
		if err != nil {
			return false
		}

		raw = string(buf)
	}

	ChinaList = make(China_list_t)

	for _, domain := range strings.Split(raw, "\n") {
		subs := strings.Split(strings.Trim(domain, "\r "), ".")
		if len(subs) == 0 || len(domain) == 0 || domain[0] == '#' {
			continue
		}

		top := ChinaList
		for i := len(subs) - 1; i >= 0; i-- {
			if top[subs[i]] == nil {
				top[subs[i]] = make(China_list_t)
			}

			if i == 0 {
				// end
				top[subs[0]] = 0
			} else {
				top = top[subs[i]].(China_list_t)
			}
		}
	}

	listLoaded = true
	return true
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

// Exceptions are those Chinese websites who have oversea servers or CDNs,
// if you lookup their IPs outside China, you get foreign IPs based on your VPS's geolocation, which are of course undesired results.
// Using white list to filter these exceptions
func IsChineseWebsite(host string) bool {
	top := ChinaList
	if top == nil {
		return false
	}

	subs := strings.Split(host, ".")
	if len(subs) <= 1 {
		return false
	}

	for i := len(subs) - 1; i >= 0; i-- {
		sub := subs[i]
		if top[sub] == nil {
			return false
		}

		switch top[sub].(type) {
		case China_list_t:
			top = top[sub].(China_list_t)
		case int:
			return top[sub].(int) == 0
		default:
			return false
		}
	}

	return true
}

func IsChineseIP(ip string) bool {
	return IPInLookupTable(ip, IPv4LookupTable)
}

func IsPrivateIP(ip string) bool {
	return IPInLookupTable(ip, IPv4PrivateLookupTable)
}

func LookupIPv4(host string) (string, error) {
	if host[0] == '[' && host[len(host)-1] == ']' {
		// ipv6, we return empty, but also no error
		return "", nil
	}

	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return "", err
	}

	return ip.String(), nil
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

func BytesToIPv4(buf []byte) string {
	if len(buf) != net.IPv4len {
		return ""
	}

	return fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
}

func BytesToIPv6(buf []byte) string {
	if len(buf) != net.IPv6len {
		return ""
	}

	hex := func(b byte) string {
		h := strconv.FormatInt(int64(b), 16)
		if len(h) == 1 {
			h = "0" + h
		}
		return h
	}

	return fmt.Sprintf("[%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s]",
		hex(buf[0]), hex(buf[1]), hex(buf[2]), hex(buf[3]),
		hex(buf[4]), hex(buf[5]), hex(buf[6]), hex(buf[7]),
		hex(buf[8]), hex(buf[9]), hex(buf[10]), hex(buf[11]),
		hex(buf[12]), hex(buf[13]), hex(buf[14]), hex(buf[15]))
}
