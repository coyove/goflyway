package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/pkg/lru"

	"net"
	"net/http"
	"strconv"
	"time"
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

	blacklist  *lru.Cache
	rkeyHeader string

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
	key := proxy.GCipher.ReverseIV(SafeGetHeader(r, proxy.rkeyHeader))

	if ctr := proxy.GCipher.GetCipherStream(key); ctr != nil {
		ctr.XorBuffer(p)
	}

	w.WriteHeader(code)
	return w.Write(p)
}

func (proxy *ProxyUpstream) hijack(w http.ResponseWriter, r *http.Request) net.Conn {
	hij, ok := w.(http.Hijacker)
	if !ok {
		logg.E("webserver doesn't support hijacking")
		return nil
	}

	conn, _, err := hij.Hijack()
	if err != nil {
		logg.E(err.Error())
		return nil
	}

	return conn
}

func (proxy *ProxyUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var auth string
	if proxy.Users != nil {
		if auth = SafeGetHeader(r, AUTH_HEADER); auth != "" {
			auth = proxy.GCipher.DecryptString(auth)
			if proxy.auth(auth) {
				goto AUTH_OK
			}
		}

		return
	}

AUTH_OK:
	replyRandom := func() {
		round := proxy.Rand.Intn(32) + 32

		buf := make([]byte, 2048)
		for r := 0; r < round; r++ {
			ln := proxy.Rand.Intn(1024) + 1024

			for i := 0; i < ln; i++ {
				buf[i] = byte(proxy.Rand.Intn(256))
			}

			w.Write(buf[:ln])
			time.Sleep(time.Duration(proxy.Rand.Intn(100)) * time.Millisecond)
		}
	}

	if dh := r.Header.Get(DNS_HEADER); r.Method == "GET" && dh != "" {
		if x := DecryptHost(proxy.GCipher, dh, HOST_DOMAIN_LOOKUP); x != "" {
			ip, _ := lookup.LookupIP(x)
			w.Write([]byte(ip))
			return
		}
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

	rkeybuf := proxy.GCipher.ReverseIV(SafeGetHeader(r, proxy.rkeyHeader))
	if rkeybuf == nil {
		proxy.blacklist.Add(addr, nil)
		replyRandom()
		return
	}

	if host, mark := TryDecryptHost(proxy.GCipher, r.Host); mark == HOST_HTTP_CONNECT || mark == HOST_SOCKS_CONNECT {
		// dig tunnel
		downstreamConn := proxy.hijack(w, r)
		if downstreamConn == nil {
			return
		}

		ioc := proxy.getIOConfig(auth)

		// we are outside GFW and should pass data to the real target
		targetSiteConn, err := net.Dial("tcp", host)
		if err != nil {
			logg.E("[HOST] - ", err)
			return
		}

		if mark == HOST_HTTP_CONNECT {
			// response HTTP 200 OK to downstream, and it will not be xored in IOCopyCipher
			downstreamConn.Write(OK_HTTP)
		} else {
			downstreamConn.Write(OK_SOCKS)
		}

		proxy.GCipher.Bridge(targetSiteConn, downstreamConn, rkeybuf, ioc)
	} else if mark == HOST_HTTP_FORWARD {
		proxy.decryptRequest(r, rkeybuf)

		resp, err := proxy.Tr.RoundTrip(r)
		if err != nil {
			logg.E("[HTTP] - ", r.URL, " - ", err)
			proxy.Write(w, r, []byte(err.Error()), http.StatusInternalServerError)
			return
		}

		if resp.StatusCode >= 400 {
			logg.D("[", resp.Status, "] - ", r.URL)
		}

		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)

		iocc := proxy.GCipher.WrapIO(w, resp.Body, rkeybuf, proxy.getIOConfig(auth))
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
	word := genWord(config.GCipher)
	proxy := &ProxyUpstream{
		Tr:           &http.Transport{TLSClientConfig: tlsSkip},
		ServerConfig: config,
		blacklist:    lru.NewCache(128),
		rkeyHeader:   "X-" + word,
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
				go proxy.handleTCPtoUDP(c)
			}
		}()
	}

	if port, lerr := strconv.Atoi(addr); lerr == nil {
		addr = (&net.TCPAddr{IP: net.IPv4zero, Port: port}).String()
	}

	logg.L("Hi! ", word, ", server is listening at ", addr)
	logg.F(http.ListenAndServe(addr, proxy))
}
