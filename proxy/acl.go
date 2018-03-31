package proxy

import (
	"encoding/base64"
	"net"
	"net/http"

	acr "github.com/coyove/goflyway/pkg/aclrouter"
	"github.com/coyove/goflyway/pkg/logg"
)

const (
	ruleProxy = iota
	rulePass
	ruleBlock
)

type Rule struct {
	IP     string
	Ans    byte
	OldAns byte
	R      byte
}

func (proxy *ProxyClient) canDirectConnect(host string) (r byte, ext string) {
	host, _ = splitHostPort(host)

	if c, ok := proxy.DNSCache.Get(host); ok && c.(*Rule) != nil {
		return c.(*Rule).Ans, " (cached)"
	}

	rule, ipstr, err := proxy.ACL.Check(host, !proxy.ACL.RemoteDNS)
	if err != nil {
		logg.E(err)
	}

	priv := false
	defer func() {
		if proxy.Policy.IsSet(PolicyGlobal) && !priv {
			r = ruleProxy
			ext += " (global)"
		} else {
			proxy.DNSCache.Add(host, &Rule{ipstr, r, r, rule})
		}
	}()

	switch rule {
	case acr.RuleIPv6:
		return ruleProxy, " (ipv6-proxy)" // By default we proxy IPv6 destination
	case acr.RuleMatchedPass:
		return rulePass, " (match-pass)"
	case acr.RuleProxy, acr.RuleMatchedProxy:
		return ruleProxy, " (match-proxy)"
	case acr.RuleBlock:
		return ruleBlock, " (match-block)"
	case acr.RulePrivate:
		priv = true
		return rulePass, " (private-ip)"
	case acr.RulePass:
		if !proxy.ACL.RemoteDNS {
			return rulePass, " (trust-local-pass)"
		}
		r = rulePass
	default:
		r = ruleProxy
	}

	if proxy.Policy.IsSet(PolicyGlobal) {
		return
	}

	// We have doubts, so query the upstream
	cr := proxy.Cipher.newRequest()
	cr.Opt.Set(doDNS)
	cr.Auth = proxy.UserAuth
	cr.Query = host

	dnsloc := "http://" + proxy.Upstream
	trueloc := "http://" + proxy.genHost() + "/" + proxy.encryptHost("dns", cr)

	if proxy.URLHeader == "" {
		dnsloc = trueloc
	}

	req, _ := http.NewRequest("GET", dnsloc, nil)

	if proxy.URLHeader != "" {
		req.Header.Add(proxy.URLHeader, trueloc)
	}

	resp, err := proxy.tpq.RoundTrip(req)
	if err != nil {
		if e, _ := err.(net.Error); e != nil && e.Timeout() {
			// proxy.tpq.Dial = (&net.Dialer{Timeout: 2 * time.Second}).Dial
		} else {
			logg.E(err)
		}
		return r, " (network-err)"
	}

	tryClose(resp.Body)
	ip, err := base64.StdEncoding.DecodeString(resp.Header.Get(dnsRespHeader))
	if err != nil || ip == nil || len(ip) != net.IPv4len {
		return r, " (remote-err)"
	}

	ipstr = net.IP(ip).String()
	switch rule, _, _ = proxy.ACL.Check(ipstr, true); rule {
	case acr.RulePass, acr.RuleMatchedPass:
		return rulePass, " (remote-pass)"
	case acr.RuleProxy, acr.RuleMatchedProxy:
		return ruleProxy, " (remote-proxy)"
	case acr.RuleBlock:
		return ruleBlock, " (remote-block)"
	case acr.RulePrivate:
		return ruleProxy, " (remote-private-ip)"
	default:
		return ruleProxy, " (remote-unknown)"
	}
}

func (proxy *ProxyClient) GetRemoteConfig() string {
	cr := proxy.Cipher.newRequest()
	cr.Opt.Set(doDNS)
	cr.Auth = proxy.UserAuth
	cr.Query = "~"

	dnsloc := "http://" + proxy.Upstream
	trueloc := "http://" + proxy.genHost() + "/" + proxy.encryptHost("config", cr)

	if proxy.URLHeader == "" {
		dnsloc = trueloc
	}

	req, _ := http.NewRequest("GET", dnsloc, nil)

	if proxy.URLHeader != "" {
		req.Header.Add(proxy.URLHeader, trueloc)
	}

	resp, err := proxy.tpq.RoundTrip(req)
	if err != nil {
		logg.E(err)
		return ""
	}

	tryClose(resp.Body)

	return proxy.Cipher.Decrypt(resp.Header.Get(dnsRespHeader), &cr.iv)
}
