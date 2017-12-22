package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/pkg/lru"
	"github.com/coyove/tcpmux"

	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ServerConfig struct {
	Throttling     int64
	ThrottlingMax  int64
	UDPRelayListen int
	ProxyPassAddr  string

	Mux bool

	Users map[string]UserConfig

	*Cipher
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

	Localaddr string

	*ServerConfig
}

func (proxy *ProxyUpstream) auth(auth string) bool {
	if _, existed := proxy.Users[auth]; existed {
		// we don't have multi-user mode currently
		return true
	}

	return false
}

func (proxy *ProxyUpstream) getIOConfig(auth string) IOConfig {
	var ioc IOConfig
	if proxy.Throttling > 0 {
		ioc.Bucket = NewTokenBucket(proxy.Throttling, proxy.ThrottlingMax)
	}

	ioc.Partial = proxy.Cipher.Partial
	return ioc
}

func (proxy *ProxyUpstream) Write(w http.ResponseWriter, key, p []byte, code int) (n int, err error) {
	if ctr := proxy.Cipher.getCipherStream(key); ctr != nil {
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
	replySomething := func() {
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

	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		logg.W("unknown address: ", r.RemoteAddr)
		replySomething()
		return
	}

	rkey := r.Header.Get(proxy.rkeyHeader)
	options, rkeybuf, authbuf := proxy.Cipher.ReverseIV(rkey)

	if rkeybuf == nil {
		logg.D("cannot find header, check your client's key, from: ", addr)
		proxy.blacklist.Add(addr, nil)
		replySomething()
		return
	}

	var auth string
	if proxy.Users != nil {
		if authbuf == nil || string(authbuf) == "" || !proxy.auth(string(authbuf)) {
			logg.W("user auth failed, from: ", addr)
			return
		}

		auth = string(authbuf)
	}

	if options == 0 {
		r := isTrustedToken("unlock", rkeybuf)

		if r == -1 {
			logg.W("someone is using an old token: ", addr)
			proxy.blacklist.Add(addr, nil)
			replySomething()
			return
		}

		if r == 1 {
			proxy.blacklist.Remove(addr)
			logg.L("unlock request accepted from: ", addr)
			return
		}
	}

	if h, _ := proxy.blacklist.GetHits(addr); h > invalidRequestRetry {
		logg.D("repeated access using invalid key from: ", addr)
		// replySomething()
		// return
	}

	if (options & doDNS) > 0 {
		host := string(rkeybuf)
		ip, err := lookup.LookupIPv4(host)
		if err != nil {
			logg.W(err)
			ip = "127.0.0.1"
		}

		logg.D("dns: ", host, " ", ip)
		w.Header().Add(dnsRespHeader, ip)
		w.WriteHeader(200)

	} else if options.IsSet(doConnect) {
		host := proxy.Cipher.DecryptDecompress(stripURI(r.RequestURI), rkeybuf...)
		if host == "" {
			logg.W("we had a valid rkey, but invalid host, from: ", addr)
			replySomething()
			return
		}

		logg.D("CONNECT ", host)
		downstreamConn := proxy.hijack(w)
		if downstreamConn == nil {
			return
		}

		ioc := proxy.getIOConfig(auth)
		targetSiteConn, err := net.Dial("tcp", host)
		if err != nil {
			logg.E(err)
			downstreamConn.Close()
			return
		}

		var p string
		if options.IsSet(doWebSocket) {
			ioc.WSCtrl = wsServer
			p = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Accept: " + (rkey + rkey)[4:32] + "\r\n\r\n"
		} else {
			p = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nDate: " + time.Now().UTC().Format(time.RFC1123) + "\r\n\r\n"
		}

		downstreamConn.Write([]byte(p))
		go proxy.Cipher.IO.Bridge(downstreamConn, targetSiteConn, rkeybuf, ioc)
	} else if options.IsSet(doForward) {
		if !proxy.decryptRequest(r, rkeybuf) {
			replySomething()
			return
		}

		logg.D(r.Method, " ", r.URL.String())

		r.Header.Del(proxy.rkeyHeader)
		resp, err := proxy.tp.RoundTrip(r)
		if err != nil {
			logg.E("HTTP forward: ", r.URL, ", ", err)
			proxy.Write(w, rkeybuf, []byte(err.Error()), http.StatusInternalServerError)
			return
		}

		if resp.StatusCode >= 400 {
			logg.D("[", resp.Status, "] - ", r.URL)
		}

		copyHeaders(w.Header(), resp.Header, proxy.Cipher, true, rkeybuf)
		w.WriteHeader(resp.StatusCode)

		iocc := proxy.getIOConfig(auth)
		iocc.Partial = false // HTTP must be fully encrypted

		if nr, err := proxy.Cipher.IO.Copy(w, resp.Body, rkeybuf, iocc); err != nil {
			logg.E("copy ", nr, " bytes: ", err)
		}

		tryClose(resp.Body)
	} else {
		proxy.blacklist.Add(addr, nil)
		replySomething()
	}
}

func (proxy *ProxyUpstream) Start() error {
	if proxy.UDPRelayListen != 0 {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{
			IP:   net.IPv6zero,
			Port: proxy.UDPRelayListen,
		})

		if err != nil {
			return err
		}

		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					logg.E(err)
					break
				}

				go proxy.handleTCPtoUDP(c)
			}
		}()
	}

	ln, err := tcpmux.Listen(proxy.Localaddr, proxy.Mux)
	if err != nil {
		return err
	}

	return http.Serve(ln, proxy)
}

func NewServer(addr string, config *ServerConfig) *ProxyUpstream {
	proxy := &ProxyUpstream{
		tp: &http.Transport{TLSClientConfig: tlsSkip},

		ServerConfig:  config,
		blacklist:     lru.NewCache(128),
		trustedTokens: make(map[string]bool),
		rkeyHeader:    "X-" + config.Cipher.Alias,
	}

	tcpmux.Version = config.Cipher.Alias[0] | 0x80

	if config.ProxyPassAddr != "" {
		if strings.HasPrefix(config.ProxyPassAddr, "http") {
			u, err := url.Parse(config.ProxyPassAddr)
			if err != nil {
				logg.F(err)
				return nil
			}

			proxy.rp = httputil.NewSingleHostReverseProxy(u)
		} else {
			proxy.rp = http.FileServer(http.Dir(config.ProxyPassAddr))
		}
	}

	if port, lerr := strconv.Atoi(addr); lerr == nil {
		addr = (&net.TCPAddr{IP: net.IPv4zero, Port: port}).String()
	}

	proxy.Localaddr = addr
	return proxy
}
