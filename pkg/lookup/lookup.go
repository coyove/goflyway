package lookup

import (
	"fmt"
	"io/ioutil"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/coyove/goflyway/pkg/config"
)

type matchTree map[string]interface{}

type ipRange struct{ start, end uint32 }

type lookupi interface {
	isDomainMatched(domain string) bool
}

type lookup struct {
	DomainFastMatch matchTree
	DomainSlowMatch []*regexp.Regexp

	IPv4Table []ipRange
}

var (
	// White are those which should be accessed directly
	White struct {
		lookup
		PrivateIPv4Table []ipRange
	}

	// Black are those which should be banned
	// Note that non-White doesn't necessarily mean Black
	Black struct {
		lookup
	}
)

func init() {
	White.IPv4Table, White.PrivateIPv4Table = make([]ipRange, 0), make([]ipRange, 0)
	White.DomainSlowMatch, Black.DomainSlowMatch = make([]*regexp.Regexp, 0), make([]*regexp.Regexp, 0)
	Black.IPv4Table = make([]ipRange, 0)

	fill := func(table *[]ipRange, iplist string) {
		list := linesToRange(iplist)
		fillLookupTable(table, list)
	}

	fill(&White.IPv4Table, ChinaIP)
	fill(&White.PrivateIPv4Table, PrivateIP)
}

// LoadACL loads ACL config, if empty, it loads chinalist.txt
func LoadACL(acl string) error {
	if acl == "" {
		return loadChinaList()
	}

	buf, err := ioutil.ReadFile(acl)
	if err != nil {
		return err
	}

	cf, err := config.ParseConf(string(buf))
	if err != nil {
		return err
	}

	cf.Iterate("bypass_list", func(key string) {
		fmt.Println(key)
	})

	// cf.Iterate("proxy_list", func(key string) {
	// 	fmt.Println(key)
	// })

	// cf.Iterate("outbound_block_list", func(key string) {
	// 	fmt.Println(key)
	// })
	fmt.Println(IsPrivateIP("127.0.0.1"), IsPrivateIP("127.0.0.255"))
	return nil
}

func loadChinaList() error {
	buf, err := ioutil.ReadFile("./chinalist.txt")
	if err != nil {
		return err
	}

	raw := string(buf)
	White.DomainFastMatch = make(matchTree)

	for _, domain := range strings.Split(raw, "\n") {
		subs := strings.Split(strings.Trim(domain, "\r "), ".")
		if len(subs) == 0 || len(domain) == 0 || domain[0] == '#' {
			continue
		}

		top := White.DomainFastMatch
		for i := len(subs) - 1; i >= 0; i-- {
			if top[subs[i]] == nil {
				top[subs[i]] = make(matchTree)
			}

			if i == 0 {
				// end
				top[subs[0]] = 0
			} else {
				top = top[subs[i]].(matchTree)
			}
		}
	}

	return nil
}

func isIPInLookupTable(ip string, table []ipRange) bool {
	m := uint32(IPv4ToInt(ip))
	if m == 0 {
		return false
	}

	var rec func([]ipRange) bool
	rec = func(r []ipRange) bool {
		if len(r) == 0 {
			return false
		}

		mid := len(r) / 2
		if m >= r[mid].start && m <= r[mid].end {
			return true
		}

		if m < r[mid].start {
			return rec(r[:mid])
		}

		return rec(r[mid+1:])
	}

	return rec(table)
}

func IsHost(master lookupi, host string) bool {
	return master.isDomainMatched(host)
}

func IsWhiteIP(ip string) bool {
	return isIPInLookupTable(ip, White.IPv4Table) || isIPInLookupTable(ip, White.PrivateIPv4Table)
}

func IsBlackIP(ip string) bool {
	return isIPInLookupTable(ip, Black.IPv4Table)
}

func IsPrivateIP(ip string) bool {
	return isIPInLookupTable(ip, White.PrivateIPv4Table)
}

// LookupIPv4 returns the IP address of host
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

// IPv4ToInt converts an IP string to its integer representation
func IPv4ToInt(ip string) uint32 {
	p := strings.Split(ip, ".")
	if len(p) != 4 {
		return 0
	}

	np := uint32(0)
	for i := 0; i < 4; i++ {
		n, err := strconv.Atoi(p[i])
		// exception: 68.media.tumblr.com
		if err != nil {
			return 0
		}

		np += uint32(n) << uint32((3-i)*8)
	}

	return np
}
