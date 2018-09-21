package proxy

import (
	"encoding/base64"
	"net"
	"net/http"

	acr "github.com/coyove/goflyway/pkg/aclrouter"
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
		switch c.(*Rule).Ans {
		case ruleProxy:
			return ruleProxy, "Proxy (cached)"
		case rulePass:
			return rulePass, "Pass (cached)"
		case ruleBlock:
			return ruleBlock, "Block (cached)"
		default:
			panic("?")
		}
	}

	rule, ipstr, err := proxy.ACL.Check(host, !proxy.ACL.RemoteDNS)
	if err != nil {
		proxy.Logger.E("ACL", err)
	}

	priv := false
	defer func() {
		if proxy.Policy.IsSet(PolicyGlobal) && !priv {
			r = ruleProxy
			ext += "Global"
		} else {
			proxy.DNSCache.Add(host, &Rule{ipstr, r, r, rule})
		}
	}()

	switch rule {
	case acr.RuleIPv6:
		return ruleProxy, "Proxy (IPv6)" // By default we proxy IPv6 destination
	case acr.RuleMatchedPass:
		return rulePass, "Pass"
	case acr.RuleProxy, acr.RuleMatchedProxy:
		return ruleProxy, "Proxy"
	case acr.RuleBlock:
		return ruleBlock, "Block"
	case acr.RulePrivate:
		priv = true
		return rulePass, "Private IP"
	case acr.RulePass:
		if !proxy.ACL.RemoteDNS {
			return rulePass, "Pass (trust local DNS)"
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
		// if e, _ := err.(net.Error); e != nil && e.Timeout() {
		// 	// proxy.tpq.Dial = (&net.Dialer{Timeout: 2 * time.Second}).Dial
		// } else {
		// 	proxy.Logger.E("ACL", err)
		// }
		return r, "Network error: " + err.Error()
	}

	tryClose(resp.Body)
	ip, err := base64.StdEncoding.DecodeString(resp.Header.Get(dnsRespHeader))
	if err != nil || ip == nil || len(ip) != net.IPv4len {
		return r, "Bad response"
	}

	ipstr = net.IP(ip).String()
	switch rule, _, _ = proxy.ACL.Check(ipstr, true); rule {
	case acr.RulePass, acr.RuleMatchedPass:
		return rulePass, "Pass (remote rule)"
	case acr.RuleProxy, acr.RuleMatchedProxy:
		return ruleProxy, "Proxy (remote rule)"
	case acr.RuleBlock:
		return ruleBlock, "Block (remote rule)"
	case acr.RulePrivate:
		return ruleProxy, "Private IP (remote rule)"
	default:
		return ruleProxy, "Unknown"
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
		proxy.Logger.E("ACL", err)
		return ""
	}

	tryClose(resp.Body)

	return proxy.Cipher.Decrypt(resp.Header.Get(dnsRespHeader), &cr.iv)
}
