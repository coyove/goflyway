package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"

	"net"
	"net/http"
)

type ServerConfig struct {
	Throttling    int64
	ThrottlingMax int64

	Users map[string]UserConfig

	*GCipher
}

// for multi-users server, not implemented yet
type UserConfig struct {
	Auth          string
	Throttling    int64
	ThrottlingMax int64
}

type ProxyUpstreamHttpServer struct {
	Tr *http.Transport

	*ServerConfig
}

func (proxy *ProxyUpstreamHttpServer) getIOConfig(auth string) *IOConfig {
	var ioc *IOConfig
	if proxy.Throttling > 0 {
		ioc = &IOConfig{NewTokenBucket(proxy.Throttling, proxy.ThrottlingMax)}
	}

	return ioc
}

func (proxy *ProxyUpstreamHttpServer) Write(w http.ResponseWriter, r *http.Request, p []byte, code int) (n int, err error) {
	key := proxy.GCipher.ReverseRandomKey(SafeGetHeader(r, RKEY_HEADER))

	if ctr := proxy.GCipher.GetCipherStream(key); ctr != nil {
		ctr.XorBuffer(p)
	}

	w.WriteHeader(code)
	return w.Write(p)
}

func (proxy *ProxyUpstreamHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if dh := r.Header.Get(DNS_HEADER); r.Method == "GET" && dh != "" {
		if x := DecryptHost(proxy.GCipher, dh, HOST_DOMAIN_LOOKUP); x != "" {
			ip, _ := lookup.LookupIP(x)
			w.Write([]byte(ip))
			return
		}
	}

	var auth string
	if auth = SafeGetHeader(r, AUTH_HEADER); auth != "" {
		auth = proxy.GCipher.DecryptString(auth)
	}

	host, mark := TryDecryptHost(proxy.GCipher, r.Host)
	if mark == HOST_HTTP_CONNECT || mark == HOST_SOCKS_CONNECT || mark == HOST_UDP_ADDRESS {
		// dig tunnel
		hij, ok := w.(http.Hijacker)
		if !ok {
			proxy.Write(w, r, []byte("webserver doesn't support hijacking"), http.StatusInternalServerError)
			return
		}

		downstreamConn, _, err := hij.Hijack()
		if err != nil {
			proxy.Write(w, r, []byte(err.Error()), http.StatusInternalServerError)
			return
		}

		rkey := r.Header.Get(RKEY_HEADER)
		ioc := proxy.getIOConfig(auth)

		if mark != HOST_UDP_ADDRESS {
			// we are outside GFW and should pass data to the real target
			targetSiteConn, err := net.Dial("tcp", host)
			if err != nil {
				logg.E("[HOST] - ", err)
				return
			}

			// response HTTP 200 OK to downstream, and it will not be xored in IOCopyCipher
			if mark == HOST_HTTP_CONNECT {
				downstreamConn.Write(OK_HTTP)
			} else {
				downstreamConn.Write(OK_SOCKS)
			}

			proxy.GCipher.Bridge(targetSiteConn, downstreamConn, rkey, ioc)
		} else {
			panic("not implemented")
		}
	} else {
		// normal http requests
		if !r.URL.IsAbs() {
			proxy.Write(w, r, []byte("abspath only"), http.StatusInternalServerError)
			return
		}

		// decrypt req from inside GFW
		rkey := proxy.DecryptRequest(r)

		r.Header.Del("Proxy-Authorization")
		r.Header.Del("Proxy-Connection")

		resp, err := proxy.Tr.RoundTrip(r)
		if err != nil {
			logg.E("[HTTP] - ", r.URL, " - ", err)
			proxy.Write(w, r, []byte(err.Error()), http.StatusInternalServerError)
			return
		}

		origBody := resp.Body
		defer origBody.Close()

		if resp.StatusCode >= 400 {
			logg.L("[", resp.Status, "] - ", r.URL)
		}

		if origBody != resp.Body {
			resp.Header.Del("Content-Length")
		}

		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)

		iocc := proxy.GCipher.WrapIO(w, resp.Body, rkey, proxy.getIOConfig(auth))
		iocc.Partial = false // HTTP must be fully encrypted

		nr, err := iocc.DoCopy()
		tryClose(resp.Body)

		if err != nil {
			logg.E("[COPYS] ", err, " - bytes: ", nr)
		}
	}
}

func StartServer(addr string, config *ServerConfig) {
	proxy := &ProxyUpstreamHttpServer{
		Tr:           &http.Transport{TLSClientConfig: tlsSkip},
		ServerConfig: config,
	}

	logg.L("listening on ", addr)
	logg.F(http.ListenAndServe(addr, proxy))
}
