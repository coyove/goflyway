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
		return c.(*Rule).Ans, "Cached"
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
		return ruleProxy, "IPv6 Proxy" // By default we proxy IPv6 destination
	case acr.RuleMatchedPass:
		return rulePass, "Pass Rule"
	case acr.RuleProxy, acr.RuleMatchedProxy:
		return ruleProxy, "Proxy Rule"
	case acr.RuleBlock:
		return ruleBlock, "Block Rule"
	case acr.RulePrivate:
		priv = true
		return rulePass, "Private IP"
	case acr.RulePass:
		if !proxy.ACL.RemoteDNS {
			return rulePass, "Pass Trust Local DNS"
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
			proxy.Logger.E("ACL", err)
		}
		return r, "Network Err"
	}

	tryClose(resp.Body)
	ip, err := base64.StdEncoding.DecodeString(resp.Header.Get(dnsRespHeader))
	if err != nil || ip == nil || len(ip) != net.IPv4len {
		return r, "Remote Bad Resp"
	}

	ipstr = net.IP(ip).String()
	switch rule, _, _ = proxy.ACL.Check(ipstr, true); rule {
	case acr.RulePass, acr.RuleMatchedPass:
		return rulePass, "Pass Remote Rule"
	case acr.RuleProxy, acr.RuleMatchedProxy:
		return ruleProxy, "Proxy Remote Rule"
	case acr.RuleBlock:
		return ruleBlock, "Block Remote Rule"
	case acr.RulePrivate:
		return ruleProxy, "Private IP Remote Rule"
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
