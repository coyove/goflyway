package proxy

import (
	. "../config"
	"../logg"
	"../lookup"
	"../lru"

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
	if r.RequestURI == "/?goflyway-console" {
		handleWebConsole(w, r)
		return
	}

	if !*G_NoPA && !basicAuth(getAuth(r)) {
		w.Header().Set("Proxy-Authenticate", "Basic realm=zzz")
		w.WriteHeader(407)
		return
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

		// we are inside GFW and should pass data to upstream
		host := r.URL.Host
		if !hasPort.MatchString(host) {
			host += ":80"
		}

		if proxy.CanDirectConnect(host) {
			targetSiteCon, err := net.Dial("tcp", host)
			if err != nil {
				logg.E("[HOST] - ", err)
				return
			}

			// response HTTP 200 OK to downstream, and it will not be xored in IOCopyCipher
			proxyClient.Write(OK200)
			TwoWayBridge(targetSiteCon, proxyClient, "")
			return
		}

		host = EncryptHost(host, "*")

		upstreamConn, err := net.Dial("tcp", proxy.Upstream)
		if err != nil {
			logg.E("[UPSTREAM] - ", err)
			return
		}

		rkey := RandomKey()
		payload := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n%s: %s\r\n", host, rkeyHeader, rkey)

		G_RequestDummies.Info(func(k lru.Key, v interface{}, h int64) {
			if v.(string) != "" {
				payload += k.(string) + ": " + v.(string) + "\r\n"
			}
		})

		upstreamConn.Write([]byte(payload + "\r\n"))

		TwoWayBridge(proxyClient, upstreamConn, rkey)

	} else {
		// normal http requests
		var err error
		var rkey string
		// log.Println(proxy.Upstream, "got request", r.URL.Path, r.Host, r.Method, r.URL.String())

		if !r.URL.IsAbs() {
			http.Error(w, "abspath only", http.StatusInternalServerError)
			return
		}

		direct := false
		rUrl := r.URL.String()
		// encrypt req to pass GFW
		if proxy.CanDirectConnect(r.Host) {
			direct = true
		} else {
			rkey = EncryptRequest(r)
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
			logg.E("[HTTP] - ", rUrl, " - ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		origBody := resp.Body
		defer origBody.Close()

		if resp.StatusCode >= 400 {
			logg.L("[", resp.Status, "] - ", rUrl)
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
			logg.E("[COPYC] ", err, " - bytes: ", nr)
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

	if *G_ProxyChina && lookup.IsChineseWebsite(host) {
		return true
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
	req.Header.Add(dnsHeader, EncryptHost(host, "!"))
	resp, err := client.Do(req)

	if err != nil {
		if !err.(net.Error).Timeout() {
			logg.W("[REMOTE LOOKUP] ", err)
		}
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

func StartClient(localaddr, upstream string) {
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
