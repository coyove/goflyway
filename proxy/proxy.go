package proxy

import (
	. "../config"
	"../logg"
	"../lookup"
	"crypto/tls"

	// "bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var hasPort = regexp.MustCompile(`:\d+$`)
var OK200 = []byte("HTTP/1.0 200 OK\r\n\r\n")
var tlsSkip = &tls.Config{InsecureSkipVerify: true}

type ProxyHttpServer struct {
	Tr       *http.Transport
	TrDirect *http.Transport
	Upstream string
}

func TwoWayBridge(target, source net.Conn, key string) {

	targetTCP, targetOK := target.(*net.TCPConn)
	sourceTCP, sourceOK := source.(*net.TCPConn)

	if targetOK && sourceOK {
		go copyAndClose(targetTCP, sourceTCP, key) // copy from source, decrypt, to target
		go copyAndClose(sourceTCP, targetTCP, key) // copy from target, encrypt, to source
	} else {
		go func() {
			var wg sync.WaitGroup
			wg.Add(2)
			go copyOrWarn(target, source, key, &wg)
			go copyOrWarn(source, target, key, &wg)
			wg.Wait()

			source.Close()
			target.Close()
		}()
	}
}

func (proxy *ProxyHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && r.Header.Get("X-Host-Lookup") != "" {
		if Skip32DecodeString(G_KeyBytes, r.Header.Get("X-Host-Lookup-ID")) == *G_Key {
			w.Write([]byte(lookup.LookupIP(r.Header.Get("X-Host-Lookup"))))
			return
		}
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

			rkey := RandomKeyBase36()
			upstreamConn.Write([]byte(fmt.Sprintf(
				"CONNECT www.baidu.com HTTP/1.1\r\nHost: www.baidu.com\r\nX-Forwarded-Host: %s\r\nX-Request-ID: %s\r\n\r\n", host, rkey)))

			TwoWayBridge(proxyClient, upstreamConn, rkey)
		} else {
			// we are outside GFW and should pass data to the real target
			host := DecryptHost(r.Header.Get("X-Forwarded-Host"))
			rkey := r.Header.Get("X-Request-ID")

			_bridge(host, rkey)
		}
	} else {
		// normal http requests
		var err error
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
				EncryptRequest(r)
			}
		} else {
			// decrypt req from inside GFW
			DecryptRequest(r)
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

		if *G_SafeHttp && !direct {
			buf, err := ioutil.ReadAll(resp.Body)
			tryClose(resp.Body)

			if err != nil {
				logg.E("ioutil reading all: ", err)
			}

			if proxy.Upstream == "" {
				buf = Skip32Encode(G_KeyBytes, buf, false)
			} else {
				buf = Skip32Decode(G_KeyBytes, buf, false)
			}

			w.Write(buf)
		} else {
			nr, err := io.Copy(w, resp.Body)
			tryClose(resp.Body)

			if err != nil {
				logg.E("io copy: ", err, " - bytes: ", nr)
			}
		}
	}
}

func (proxy *ProxyHttpServer) CanDirectConnect(host string) bool {
	if *G_ProxyAll {
		return false
	}

	host = strings.ToLower(host)
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	if lookup.IPAddressToInteger(host) != 0 {
		return lookup.IPInLookupTable(host)
	}

	if v, ok := G_Cache.Get(host); ok {
		return lookup.IPInLookupTable(v.(string))
	}

	client := http.Client{Timeout: time.Second}
	req, _ := http.NewRequest("GET", "http://"+proxy.Upstream, nil)
	req.Header.Add("X-Host-Lookup", host)
	req.Header.Add("X-Host-Lookup-ID", Skip32EncodeString(G_KeyBytes, *G_Key))
	resp, err := client.Do(req)

	if err != nil {
		logg.W("host lookup: ", err)
		return false
	}

	ipbuf, err := ioutil.ReadAll(resp.Body)
	tryClose(resp.Body)

	if err != nil {
		logg.W("host lookup: ", err)
		return false
	}

	G_Cache.Add(host, string(ipbuf), 600)
	return lookup.IPInLookupTable(string(ipbuf))
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
