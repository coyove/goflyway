package proxy

import (
	. "../config"
	"../logg"
	"../lookup"

	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ProxyHttpServer struct {
	Tr       *http.Transport
	TrDirect *http.Transport
	Upstream string
}

func (proxy *ProxyHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && r.Header.Get("X-Host-Lookup") != "" {
		if Skip32DecodeString(G_KeyBytes, r.Header.Get(dnsHeaderID)) == *G_Key {
			w.Write([]byte(lookup.LookupIP(r.Header.Get(dnsHeader))))
			return
		}
	}

	if r.RequestURI == "/dns-lookup-cache" {
		PrintCache(w, r)
		return
	}

	if !*G_NoPA {
		if proxy.Upstream != "" && !basicAuth(getAuth(r)) {
			// only the downstream needs pa
			w.Header().Set("Proxy-Authenticate", "Basic realm=zzz")
			w.WriteHeader(407)
			return
		}
	}

	if r.Method == "CONNECT" {
		// dig tunnel
		hij, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}

		proxyClient, _, err := hij.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_bridge := func(host, rkey string) {
			targetSiteCon, err := net.Dial("tcp", host)
			if err != nil {
				logg.E("[HOST] - ", err)
				return
			}

			// response HTTP 200 OK to downstream, and it will not be xored in IOCopyCipher
			proxyClient.Write(OK200)
			TwoWayBridge(targetSiteCon, proxyClient, rkey)
		}

		if proxy.Upstream != "" {
			// we are inside GFW and should pass data to upstream
			host := r.URL.Host
			if proxy.CanDirectConnect(host) {
				_bridge(host, "")
				return
			}

			if !hasPort.MatchString(host) {
				host += ":80"
			}

			host = EncryptHost(host)

			upstreamConn, err := net.Dial("tcp", proxy.Upstream)
			if err != nil {
				logg.E("[UPSTREAM] - ", err)
				return
			}

			rkey, rhost := RandomKey(), dummyHosts[NewRand().Intn(len(dummyHosts))]
			upstreamConn.Write([]byte(fmt.Sprintf(
				"CONNECT www.%s.com HTTP/1.1\r\nHost: www.%s.com\r\nX-Forwarded-Host: %s\r\n%s: %s\r\n\r\n", rhost, rhost, host, rkeyHeader, rkey)))

			TwoWayBridge(proxyClient, upstreamConn, rkey)
		} else {
			// we are outside GFW and should pass data to the real target
			host := DecryptHost(r.Header.Get("X-Forwarded-Host"))
			rkey := r.Header.Get(rkeyHeader)

			_bridge(host, rkey)
		}
	} else {
		// normal http requests
		var err error
		var rkey string
		// log.Println(proxy.Upstream, "got request", r.URL.Path, r.Host, r.Method, r.URL.String())

		if !r.URL.IsAbs() {
			http.Error(w, "abspath only", 500)
			return
		}

		direct := false
		if proxy.Upstream != "" {
			// encrypt req to pass GFW
			if proxy.CanDirectConnect(r.Host) {
				direct = true
			} else {
				rkey = EncryptRequest(r)
			}
		} else {
			// decrypt req from inside GFW
			rkey = DecryptRequest(r)
		}

		r.Header.Del("Proxy-Authorization")
		r.Header.Del("Proxy-Connection")

		var resp *http.Response

		if direct {
			resp, err = proxy.TrDirect.RoundTrip(r)
		} else {
			resp, err = proxy.Tr.RoundTrip(r)
		}

		if err != nil {
			if proxy.Upstream != "" && !direct {
				DecryptRequest(r)
			}

			logg.E("[PRT] - ", err.Error(), " - ", r.URL)
			http.Error(w, err.Error(), 500)
			return
		}

		origBody := resp.Body
		defer origBody.Close()

		if resp.StatusCode >= 400 {
			if proxy.Upstream != "" && !direct {
				DecryptRequest(r)
			}

			logg.L("[", resp.Status, "] - ", r.URL)
		}

		// http.ResponseWriter will take care of filling the correct response length
		// Setting it now, might impose wrong value, contradicting the actual new
		// body the user returned.
		// We keep the original body to remove the header only if things changed.
		// This will prevent problems with HEAD requests where there's no body, yet,
		// the Content-Length header should be set.
		if origBody != resp.Body {
			resp.Header.Del("Content-Length")
		}

		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)

		if *G_UnsafeHttp {
			rkey = ""
		}

		nr, err := (&IOCopyCipher{Dst: w, Src: resp.Body, Key: ReverseRandomKey(rkey)}).DoCopy()
		tryClose(resp.Body)

		if err != nil {
			logg.E("io copy: ", err, " - bytes: ", nr)
		}
	}
}

func (proxy *ProxyHttpServer) CanDirectConnect(host string) bool {
	host = strings.ToLower(host)
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	if lookup.IPAddressToInteger(host) != 0 { // host is just an ip
		return lookup.IsPrivateIP(host) || lookup.IsChineseIP(host)
	}

	if ip, ok := G_Cache.Get(host); ok && ip.(string) != "" { // we have cached the host
		return lookup.IsPrivateIP(ip.(string)) || lookup.IsChineseIP(ip.(string))
	}

	// lookup at local in case host points to a private ip
	ip := lookup.LookupIP(host)
	if lookup.IsPrivateIP(ip) {
		G_Cache.Add(host, ip)
		return true
	}

	// if it is a foreign ip, just return false
	// but if it is a chinese ip, we withhold and query the upstream to double check
	maybeChinese := lookup.IsChineseIP(ip)
	if !maybeChinese {
		G_Cache.Add(host, ip)
		return false
	}

	// lookup at upstream
	client := http.Client{Timeout: time.Second}
	req, _ := http.NewRequest("GET", "http://"+proxy.Upstream, nil)
	req.Header.Add(dnsHeader, host)
	req.Header.Add(dnsHeaderID, Skip32EncodeString(G_KeyBytes, *G_Key))
	resp, err := client.Do(req)

	if err != nil {
		logg.W("[REMOTE LOOKUP] ", err)
		return maybeChinese
	}

	ipbuf, err := ioutil.ReadAll(resp.Body)
	tryClose(resp.Body)

	if err != nil {
		logg.W("[REMOTE LOOKUP] ", err)
		return maybeChinese
	}

	G_Cache.Add(host, string(ipbuf))
	return lookup.IsChineseIP(string(ipbuf))
}

func Start(localaddr, upstream string) {
	upstreamUrl, err := url.Parse("http://" + upstream)
	if err != nil {
		logg.F(err)
	}

	proxy := &ProxyHttpServer{
		Tr: &http.Transport{
			TLSClientConfig: tlsSkip,
			Proxy:           http.ProxyURL(upstreamUrl),
		},
		TrDirect: &http.Transport{TLSClientConfig: tlsSkip},
		Upstream: upstream,
	}

	logg.L("listening on ", localaddr, ", upstream is ", upstream)
	logg.F(http.ListenAndServe(localaddr, proxy))
}

func StartUpstream(addr string) {
	proxy := &ProxyHttpServer{
		Tr: &http.Transport{TLSClientConfig: tlsSkip},
	}

	logg.L("listening on ", addr)
	logg.F(http.ListenAndServe(addr, proxy))
}
