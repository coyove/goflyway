package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/pkg/lru"

	"net"
	"net/http"
)

const (
	_RETRY_OPPORTUNITIES = 2
)

type ServerConfig struct {
	Throttling     int64
	ThrottlingMax  int64
	UDPRelayListen int

	Users map[string]UserConfig

	*GCipher
}

// for multi-users server, not implemented yet
type UserConfig struct {
	Auth          string
	Throttling    int64
	ThrottlingMax int64
}

type ProxyUpstream struct {
	Tr *http.Transport

	blacklist *lru.Cache

	*ServerConfig
}

func (proxy *ProxyUpstream) auth(auth string) bool {
	if _, existed := proxy.Users[auth]; existed {
		// we don't have multi-user mode currently
		return true
	}

	return false
}

func (proxy *ProxyUpstream) getIOConfig(auth string) *IOConfig {
	var ioc *IOConfig
	if proxy.Throttling > 0 {
		ioc = &IOConfig{NewTokenBucket(proxy.Throttling, proxy.ThrottlingMax)}
	}

	return ioc
}

func (proxy *ProxyUpstream) Write(w http.ResponseWriter, r *http.Request, p []byte, code int) (n int, err error) {
	key := proxy.GCipher.ReverseRandomKey(SafeGetHeader(r, RKEY_HEADER))

	if ctr := proxy.GCipher.GetCipherStream(key); ctr != nil {
		ctr.XorBuffer(p)
	}

	w.WriteHeader(code)
	return w.Write(p)
}

func (proxy *ProxyUpstream) Hijack(w http.ResponseWriter, r *http.Request) net.Conn {
	hij, ok := w.(http.Hijacker)
	if !ok {
		proxy.Write(w, r, []byte("webserver doesn't support hijacking"), http.StatusInternalServerError)
		return nil
	}

	conn, _, err := hij.Hijack()
	if err != nil {
		proxy.Write(w, r, []byte(err.Error()), http.StatusInternalServerError)
		return nil
	}

	return conn
}

func (proxy *ProxyUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		if !proxy.auth(auth) {
			return
		}
	}

	replyRandom := func() {
		ln := proxy.Rand.Intn(32*1024) + 32*1024
		buf := make([]byte, ln)

		for i := 0; i < ln; i++ {
			buf[i] = byte(proxy.GCipher.Rand.Intn(256))
		}

		w.Write(buf)
	}

	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		logg.W("unknown address: ", r.RemoteAddr)
		replyRandom()
		return
	}

	if h, _ := proxy.blacklist.GetHits(addr); h > _RETRY_OPPORTUNITIES {
		logg.W("repeated access using invalid key, from: ", addr)
		replyRandom()
		return
	}

	if host, mark := TryDecryptHost(proxy.GCipher, r.Host); mark == HOST_HTTP_CONNECT || mark == HOST_SOCKS_CONNECT {
		// dig tunnel
		downstreamConn := proxy.Hijack(w, r)
		if downstreamConn == nil {
			return
		}

		rkey := r.Header.Get(RKEY_HEADER)
		ioc := proxy.getIOConfig(auth)

		if rkey == "" {
			// if the request doesn't have a valid rkey
			// it should be considered as invalid
			replyRandom()
			return
		}

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
	} else if mark == HOST_HTTP_FORWARD {
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
	} else {
		proxy.blacklist.Add(addr, nil)
		replyRandom()
	}
}

func StartServer(addr string, config *ServerConfig) {
	proxy := &ProxyUpstream{
		Tr:           &http.Transport{TLSClientConfig: tlsSkip},
		ServerConfig: config,
		blacklist:    lru.NewCache(128),
	}

	if proxy.UDPRelayListen != 0 {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{
			IP:   net.IPv6zero,
			Port: proxy.UDPRelayListen,
		})

		if err != nil {
			logg.F(err)
		}

		go func() {
			for {
				c, _ := l.Accept()
				go proxy.HandleTCPtoUDP(c)
			}
		}()
	}

	logg.L("listening on ", addr)
	logg.F(http.ListenAndServe(addr, proxy))
}
