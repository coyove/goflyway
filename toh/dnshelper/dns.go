package dnshelper

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coyove/common/lru"
	"github.com/miekg/dns"
)

var (
	DefaultResolver   string
	defaultResolvermu sync.Mutex
	DNSCache          = lru.NewCache(1024)
)

func LookupIPv4(host string, local bool) (net.IP, error) {
	if local {
		return dnsNonRecursiveQueryIPv4(host)
	}
	if c, ok := DNSCache.Get(host); ok {
		return c.(net.IP), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return net.IPv4zero, err
	}
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 != nil {
			DNSCache.Add(host, ip4)
			return ip4, nil
		}
	}
	return net.IPv4zero, fmt.Errorf("empty answer")
}

func dnsNonRecursiveQueryIPv4(host string) (net.IP, error) {
	if idx := strings.LastIndex(host, ":"); idx > -1 {
		host = host[:idx]
	}
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	if c, ok := DNSCache.Get(host); ok {
		return c.(net.IP), nil
	}

	c := &dns.Client{Timeout: time.Millisecond * 100}
	m := &dns.Msg{}
	m.Id = dns.Id()
	m.RecursionDesired = false
	m.Question = []dns.Question{dns.Question{host, dns.TypeA, dns.ClassINET}}

	// For now we use some hacks to get system's default resolver address
	for i := 0; i < 4 && DefaultResolver == ""; i++ {
		defaultResolvermu.Lock()
		if DefaultResolver == "" {
			resolv := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					DefaultResolver = address
					return nil, fmt.Errorf("abort")
				},
			}
			resolv.LookupIPAddr(context.TODO(), strconv.Itoa(int(rand.Uint64()))+".com")
		}
		defaultResolvermu.Unlock()
	}

	if DefaultResolver == "" {
		return net.IPv4zero, fmt.Errorf("failed to get default resolver")
	}

	in, _, err := c.Exchange(m, DefaultResolver)
	if err != nil {
		return net.IPv4zero, err
	}

	for _, ans := range in.Answer {
		switch a := ans.(type) {
		case *dns.A:
			DNSCache.Add(host, a.A)
			return a.A, nil
		case *dns.CNAME:
			return dnsNonRecursiveQueryIPv4(a.Target)
		default:
			return net.IPv4zero, fmt.Errorf("unknown answer: %v", ans)
		}
	}

	return net.IPv4zero, fmt.Errorf("empty answer")
}
