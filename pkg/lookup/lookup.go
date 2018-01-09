package lookup

import (
	"errors"
	"io/ioutil"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/coyove/goflyway/pkg/config"
)

type matchTree map[string]interface{}

type ipRange struct{ start, end uint32 }

type lookup struct {
	Always          bool
	DomainFastMatch matchTree
	DomainSlowMatch []*regexp.Regexp
	IPv4Table       []ipRange
}

func (lk *lookup) init() {
	lk.IPv4Table = make([]ipRange, 0)
	lk.DomainSlowMatch = make([]*regexp.Regexp, 0)
	lk.DomainFastMatch = make(matchTree)
}

const (
	Black = iota
	White
	Gray
)

// ACL stands for Access Control List
type ACL struct {
	Black lookup // Black are those which should be banned, first to check
	White lookup // White are those which should be accessed directly
	Gray  lookup // Gray are those which should be proxied

	PrivateIPv4Table []ipRange
	RemoteDNS        bool
	Legacy           bool
}

func (acl *ACL) init() {
	acl.White.init()
	acl.Gray.init()
	acl.Black.init()
	acl.PrivateIPv4Table = sortLookupTable(linesToRange(PrivateIP))
	acl.RemoteDNS = true
}

// LoadACL loads ACL config, which can be chinalist.txt or SS ACL
// note that it will always return a valid ACL struct, but may be empty
func LoadACL(path string) (*ACL, error) {
	acl := &ACL{}
	acl.init()

	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return acl, err
	}

	if strings.HasSuffix(path, "chinalist.txt") {
		return loadChinaList(buf)
	}

	cf, err := config.ParseConf(string(buf))
	if err != nil {
		return acl, err
	}

	acl.Gray.Always = cf.HasSection("proxy_all")
	acl.White.Always = cf.HasSection("bypass_all")
	acl.RemoteDNS = !cf.HasSection("local_dns")

	if acl.Gray.Always && acl.White.Always {
		return acl, errors.New("proxy_all and bypass_all collide")
	}

	cf.Iterate("bypass_list", func(key string) { acl.White.tryAddACLSingleRule(key) })
	acl.White.sortLookupTable()

	cf.Iterate("proxy_list", func(key string) { acl.Gray.tryAddACLSingleRule(key) })
	acl.Gray.sortLookupTable()

	cf.Iterate("outbound_block_list", func(key string) { acl.Black.tryAddACLSingleRule(key) })
	acl.Black.sortLookupTable()

	// fmt.Println(IPv4ToInt("47.97.161.219"))
	// fmt.Println(acl.White.IPv4Table)
	return acl, nil
}

func loadChinaList(buf []byte) (*ACL, error) {
	acl := &ACL{}
	acl.init()
	acl.White.IPv4Table = sortLookupTable(linesToRange(ChinaIP))
	acl.Gray.Always = true
	acl.Legacy = true

	raw := string(buf)
	for _, domain := range strings.Split(raw, "\n") {
		subs := strings.Split(strings.Trim(domain, "\r "), ".")
		if len(subs) == 0 || len(domain) == 0 || domain[0] == '#' {
			continue
		}

		top := acl.White.DomainFastMatch
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

	return acl, nil
}

func isIPInLookupTable(ip string, table []ipRange) bool {
	m := uint32(IPv4ToInt(ip))
	if m == 0 {
		return false
	}

	return isIPInLookupTableI(m, table)
}

func isIPInLookupTableI(ip uint32, table []ipRange) bool {
	var rec func([]ipRange) bool
	rec = func(r []ipRange) bool {
		if len(r) == 0 {
			return false
		}

		mid := len(r) / 2
		if ip >= r[mid].start && ip <= r[mid].end {
			return true
		}

		if ip < r[mid].start {
			return rec(r[:mid])
		}

		return rec(r[mid+1:])
	}

	return rec(table)
}

func (acl *ACL) IsPrivateIP(ip string) bool {
	return isIPInLookupTable(ip, acl.PrivateIPv4Table)
}

// LookupIPv4 returns the IP address of host
func (acl *ACL) LookupIPv4(host string) (string, error) {
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

// IPv4ToInt converts an IPv4 string to its integer representation
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
