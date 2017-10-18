package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lru"

	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	_RETRY_OPPORTUNITIES = 2
)

type ServerConfig struct {
	Throttling     int64
	ThrottlingMax  int64
	UDPRelayListen int
	ProxyPassAddr  string
	DummyDomain    string

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
	tp            *http.Transport
	rp            http.Handler
	blacklist     *lru.Cache
	trustedTokens map[string]bool
	rkeyHeader    string

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
		ioc = &IOConfig{Bucket: NewTokenBucket(proxy.Throttling, proxy.ThrottlingMax)}
	}

	return ioc
}

func (proxy *ProxyUpstream) Write(w http.ResponseWriter, r *http.Request, p []byte, code int) (n int, err error) {
	_, key := proxy.GCipher.ReverseIV(SafeGetHeader(r, proxy.rkeyHeader))

	if ctr := proxy.GCipher.GetCipherStream(key); ctr != nil {
		ctr.XorBuffer(p)
	}

	w.WriteHeader(code)
	return w.Write(p)
}

func (proxy *ProxyUpstream) hijack(w http.ResponseWriter) net.Conn {
	hij, ok := w.(http.Hijacker)
	if !ok {
		logg.E("webserver doesn't support hijacking")
		return nil
	}

	conn, _, err := hij.Hijack()
	if err != nil {
		logg.E("hijacking: ", err.Error())
		return nil
	}

	return conn
}

func (proxy *ProxyUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// remote dns lookup
	if r.Method == "GET" && r.ProtoMajor == 1 && r.ProtoMinor == 0 && len(r.RequestURI) > 0 {
		cob := proxy.GCipher.DecryptString(r.RequestURI[1:])
		idx := strings.LastIndex(cob, "|")
		if idx == -1 {
			return
		}

		auth, host := cob[:idx], cob[idx+1:]

		if proxy.Users != nil && !proxy.auth(auth) {
			return
		}

		conn := proxy.hijack(w)
		if conn == nil {
			return
		}

		ip, err := net.ResolveIPAddr("ip4", host)
		if err != nil {
			return
		}

		conn.Write(ip.IP)
		conn.Close()
		return
	}

	replyRandom := func() {
		if proxy.rp == nil {
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
		} else {
			proxy.rp.ServeHTTP(w, r)
		}
	}

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

	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		logg.W("unknown address: ", r.RemoteAddr)
		replyRandom()
		return
	}

	rkey := SafeGetHeader(r, proxy.rkeyHeader)
	options, rkeybuf := proxy.GCipher.ReverseIV(rkey)

	if rkeybuf == nil {
		logg.W("can't find header, check your client's key")
		proxy.blacklist.Add(addr, nil)
		replyRandom()
		return
	}

	if isTrustedToken("unlock", rkeybuf) {
		if proxy.trustedTokens[rkey] {
			proxy.blacklist.Add(addr, nil)
			replyRandom()
			return
		}

		proxy.trustedTokens[rkey] = true
		proxy.blacklist.Remove(addr)
		logg.L("unlock request accepted from: ", addr)
		return
	}

	if h, _ := proxy.blacklist.GetHits(addr); h > _RETRY_OPPORTUNITIES {
		logg.W("repeated access using invalid key, from: ", addr)
		replyRandom()
		return
	}

	if (options&DO_CONNECT) > 0 || (options&DO_SOCKS5) > 0 {
		host := proxy.decryptHost(proxy.GCipher, r.Host, options, rkeybuf[len(rkeybuf)-2:]...)
		if host == "" {
			replyRandom()
			return
		}

		logg.D("CONNECT ", options, " ", host)

		// dig tunnel
		downstreamConn := proxy.hijack(w)
		if downstreamConn == nil {
			return
		}

		ioc := proxy.getIOConfig(auth)

		// we are outside GFW and should pass data to the real target
		targetSiteConn, err := net.Dial("tcp", host)
		if err != nil {
			logg.E(err)
			return
		}

		if (options & DO_OMIT_HDR) == 0 {
			if (options & DO_CONNECT) > 0 {
				downstreamConn.Write(OK_HTTP)
			} else {
				downstreamConn.Write(OK_SOCKS)
			}
		}

		proxy.GCipher.Bridge(targetSiteConn, downstreamConn, rkeybuf, ioc)
	} else if (options & DO_FORWARD) > 0 {
		proxy.decryptRequest(r, options, rkeybuf)
		logg.D(r.Method, " ", r.Host)

		r.Header.Del(proxy.rkeyHeader)
		resp, err := proxy.tp.RoundTrip(r)
		if err != nil {
			logg.E("proxy pass: ", r.URL, ", ", err)
			proxy.Write(w, r, []byte(err.Error()), http.StatusInternalServerError)
			return
		}

		if resp.StatusCode >= 400 {
			logg.D("[", resp.Status, "] - ", r.URL)
		}

		copyHeaders(w.Header(), resp.Header, proxy.GCipher, true)
		w.WriteHeader(resp.StatusCode)

		iocc := proxy.GCipher.WrapIO(w, resp.Body, rkeybuf, proxy.getIOConfig(auth))
		iocc.Partial = false // HTTP must be fully encrypted

		nr, err := iocc.DoCopy()
		tryClose(resp.Body)

		if err != nil {
			logg.E("io.wrap ", nr, "bytes: ", err)
		}
	} else {
		proxy.blacklist.Add(addr, nil)
		replyRandom()
	}
}

func StartServer(addr string, config *ServerConfig) {
	word := genWord(config.GCipher, false)
	proxy := &ProxyUpstream{
		tp: &http.Transport{
			TLSClientConfig: tlsSkip,
		},

		ServerConfig:  config,
		blacklist:     lru.NewCache(128),
		trustedTokens: make(map[string]bool),
		rkeyHeader:    "X-" + word,
	}

	if config.ProxyPassAddr != "" {
		if strings.HasPrefix(config.ProxyPassAddr, "http") {
			u, err := url.Parse(config.ProxyPassAddr)
			if err != nil {
				logg.F(err)
			}

			logg.L("alternatively act as reverse proxy: ", config.ProxyPassAddr)
			proxy.rp = httputil.NewSingleHostReverseProxy(u)
		} else {
			logg.L("alternatively act as file server: ", config.ProxyPassAddr)
			proxy.rp = http.FileServer(http.Dir(config.ProxyPassAddr))
		}
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
