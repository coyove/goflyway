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
	"sync"
)

var hasPort = regexp.MustCompile(`:\d+$`)
var OK200 = []byte("HTTP/1.0 200 OK\r\n\r\n")

type ProxyHttpServer struct {
	Tr       *http.Transport
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
	if !*G_NoPA {
		if proxy.Upstream != "" && !basicAuth(getAuth(r)) {
			// only the downstream needs pa
			w.Header().Set("Proxy-Authenticate", "Basic realm=zzz")
			w.WriteHeader(407)
			return
		}
	}

	if r.Method == "GET" && r.Header.Get("X-Host-Lookup") != "" {
		w.Write([]byte(lookup.LookupIP(r.Header.Get("X-Host-Lookup"))))
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

		if proxy.Upstream != "" {
			// we are inside GFW and should pass data to upstream
			host := r.URL.Host
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

			targetSiteCon, err := net.Dial("tcp", host)
			if err != nil {
				logg.E("[HOST] - ", err)
				return
			}

			// response HTTP 200 OK to downstream, and it will not be xored in IOCopyCipher
			proxyClient.Write(OK200)
			TwoWayBridge(targetSiteCon, proxyClient, rkey)
		}
	} else {
		// normal http requests
		var err error
		// log.Println(proxy.Upstream, "got request", r.URL.Path, r.Host, r.Method, r.URL.String())

		if !r.URL.IsAbs() {
			http.Error(w, "abspath only", 500)
			return
		}

		if proxy.Upstream != "" {
			// encrypt req to pass GFW
			EncryptRequest(r)
		} else {
			// decrypt req from inside GFW
			DecryptRequest(r)
		}

		r.Header.Del("Proxy-Authorization")
		r.Header.Del("Proxy-Connection")

		resp, err := proxy.Tr.RoundTrip(r)
		if err != nil {
			if proxy.Upstream != "" {
				DecryptRequest(r)
			}

			logg.E("[PRT] - ", err.Error(), " - ", r.URL)
			http.Error(w, err.Error(), 500)
			return
		}

		origBody := resp.Body
		defer origBody.Close()

		if resp.StatusCode >= 400 {
			if proxy.Upstream != "" {
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

		if *G_SafeHttp {
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

func Start(localaddr, upstream string) {
	upstreamUrl, err := url.Parse("http://" + upstream)
	if err != nil {
		logg.F(err)
	}

	proxy := &ProxyHttpServer{
		Tr: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(upstreamUrl),
		},
		Upstream: upstream,
	}

	logg.L("listening on ", localaddr, ", upstream is ", upstream)
	logg.F(http.ListenAndServe(localaddr, proxy))
}

func StartUpstream(addr string) {
	proxy := &ProxyHttpServer{
		Tr: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	logg.L("listening on ", addr)
	logg.F(http.ListenAndServe(addr, proxy))
}
