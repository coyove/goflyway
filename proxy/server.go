package proxy

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"sync"

	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lru"
	"github.com/coyove/goflyway/pkg/msg64"
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
	Throttling    int64
	ThrottlingMax int64
	WSCBTimeout   int64
	DisableUDP    bool
	ProxyPassAddr string
	ClientAnswer  string

	Users map[string]UserConfig

	*Cipher
}

// UserConfig is for multi-users server, not implemented yet
type UserConfig struct {
	Auth          string
	Throttling    int64
	ThrottlingMax int64
}

// ProxyUpstream is the main struct for upstream server
type ProxyUpstream struct {
	tp        *http.Transport
	rp        http.Handler
	blacklist *lru.Cache
	wsMapping struct {
		sync.RWMutex
		m map[[ivLen]byte]*wsCallback
	}

	Localaddr string
	Listener  net.Listener

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
	return ioc
}

func (proxy *ProxyUpstream) Write(w http.ResponseWriter, key *[ivLen]byte, p []byte, code int) (n int, err error) {
	if ctr := proxy.Cipher.getCipherStream(key); ctr != nil {
		ctr.XORKeyStream(p, p)
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
			w.WriteHeader(404)
			w.Write([]byte(`<html>
<head><title>404 Not Found</title></head>
<body bgcolor="white">
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>`))
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

	dst, cr := proxy.decryptHost(stripURI(r.RequestURI))

	if dst == "" || cr == nil {
		logg.D("invalid request from: ", addr)
		logg.D(stripURI(r.RequestURI))
		proxy.blacklist.Add(addr, nil)
		replySomething()
		return
	}

	if proxy.Users != nil {
		if !proxy.auth(cr.Auth) {
			logg.W("user auth failed, from: ", addr)
			return
		}
	}

	if h, _, _ := proxy.blacklist.GetEx(addr); h > invalidRequestRetry {
		logg.D("repeated access using invalid key from: ", addr)
		// replySomething()
		// return
	}

	if cr.Opt.IsSet(doDNS) {
		host := cr.Query
		if host == "~" {
			w.Header().Add(dnsRespHeader, proxy.Encrypt(proxy.ClientAnswer, &cr.iv))
		} else {
			ip, err := net.ResolveIPAddr("ip4", host)
			if err != nil {
				logg.W(err)
				ip = &net.IPAddr{IP: net.IP{127, 0, 0, 1}}
			}

			logg.D("DNS: ", host, " ", ip.String())
			w.Header().Add(dnsRespHeader, base64.StdEncoding.EncodeToString([]byte(ip.IP.To4())))
		}
		w.WriteHeader(200)

	} else if cr.Opt.IsSet(doConnect) {
		host := dst
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

		ioc := proxy.getIOConfig(cr.Auth)
		ioc.Partial = cr.Opt.IsSet(doPartial)

		var targetSiteConn net.Conn
		var err error

		if cr.Opt.IsSet(doUDPRelay) {
			if proxy.DisableUDP {
				logg.W("client is trying to send UDP data but we disabled it")
				downstreamConn.Close()
				return
			}

			uaddr, _ := net.ResolveUDPAddr("udp", host)

			var rconn *net.UDPConn
			rconn, err = net.DialUDP("udp", nil, uaddr)
			targetSiteConn = &udpBridgeConn{
				UDPConn: rconn,
				udpSrc:  uaddr,
			}
			// rconn.Write([]byte{6, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0, 0, 1, 0, 1})
		} else {
			targetSiteConn, err = net.Dial("tcp", host)
		}

		if err != nil {
			logg.E(err)
			downstreamConn.Close()
			return
		}

		var p buffer
		if cr.Opt.IsSet(doWebSocket) {
			ioc.WSCtrl = wsServer

			var accept buffer
			accept.Writes(r.Header.Get("Sec-WebSocket-Key"), "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

			ans := sha1.Sum(accept.Bytes())
			p.Writes("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Accept: ",
				base64.StdEncoding.EncodeToString(ans[:]), "\r\n\r\n")
		} else {
			p.Writes("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nDate: ", time.Now().UTC().Format(time.RFC1123), "\r\n\r\n")
		}

		downstreamConn.Write(p.Bytes())

		if cr.Opt.IsSet(doMuxWS) {
			logg.D("downstream connection is being upgraded to multiplexer stream")
			proxy.Listener.(*tcpmux.ListenPool).Upgrade(downstreamConn)
		} else {
			go proxy.Cipher.IO.Bridge(downstreamConn, targetSiteConn, &cr.iv, ioc)
		}
	} else if cr.Opt.IsSet(doForward) {
		var err error

		if cr.WSToken != "" {
			token, _ := base64.StdEncoding.DecodeString(cr.WSToken)
			tokenIV := [ivLen]byte{}
			copy(tokenIV[:], token)

			proxy.wsMapping.RLock()
			m := proxy.wsMapping.m[tokenIV]
			proxy.wsMapping.RUnlock()

			// logg.E(cr.WSToken, " ", m)
			if m != nil {
				switch cr.WSCallback {
				case 'b':
					m.Lock()
					w.WriteHeader(200)
					if nr, err := proxy.Cipher.IO.Copy(w, bytes.NewReader(m.rBuf), &cr.iv, proxy.getIOConfig(cr.Auth)); err != nil {
						logg.E("copy ", nr, " bytes: ", err)
					}
					m.rBuf = m.rBuf[0:0]
					m.Unlock()
				case 'c':
					w.WriteHeader(200)
					if nr, err := proxy.Cipher.IO.Copy(m.conn, r.Body, &cr.iv, IOConfig{}); err != nil {
						logg.E("copy ", nr, " bytes: ", err)
					}
				}
			} else {
				w.WriteHeader(404)
			}

			return
		}

		r.URL, err = url.Parse(dst)
		if err != nil {
			replySomething()
			return
		}

		r.Host = r.URL.Host
		proxy.decryptRequest(r, cr)

		logg.D(r.Method, " ", r.URL.String())

		if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
			respErr := func(err error) {
				logg.E(err)
				proxy.Write(w, &cr.iv, []byte(err.Error()), http.StatusInternalServerError)
			}

			reqbuf, err := httputil.DumpRequestOut(r, false)
			if err != nil {
				respErr(err)
				return
			}

			host, port := splitHostPort(r.Host)
			if port == "" {
				port = ":443"
			}

			conn, err := tls.Dial("tcp", host+port, tlsSkip)
			if err != nil {
				respErr(err)
				return
			}

			rd := bufio.NewReader(conn)
			conn.Write(reqbuf)
			resp, err := http.ReadResponse(rd, r)
			if err != nil {
				respErr(err)
				return
			}

			copyHeaders(w.Header(), resp.Header, proxy.Cipher, true, &cr.iv)
			w.WriteHeader(resp.StatusCode)

			if nr, err := proxy.Cipher.IO.Copy(w, resp.Body, &cr.iv, proxy.getIOConfig(cr.Auth)); err != nil {
				logg.E("copy ", nr, " bytes: ", err)
			}

			tryClose(resp.Body)

			proxy.wsMapping.Lock()
			proxy.wsMapping.m[cr.iv] = &wsCallback{conn: conn}
			proxy.wsMapping.Unlock()

			go func() {
				for {
					frame, err := wsReadFrame(conn)
					if err != nil {
						if !isClosedConnErr(err) {
							logg.E(err)
						}
						break
					}

					proxy.wsMapping.RLock()
					proxy.wsMapping.m[cr.iv].Write(frame)
					proxy.wsMapping.RUnlock()
				}
			}()
		} else {
			resp, err := proxy.tp.RoundTrip(r)
			if err != nil {
				logg.E("HTTP forward: ", r.URL, ", ", err)
				proxy.Write(w, &cr.iv, []byte(err.Error()), http.StatusInternalServerError)
				return
			}

			if resp.StatusCode >= 400 {
				logg.D("[", resp.Status, "] - ", r.URL)
			}

			copyHeaders(w.Header(), resp.Header, proxy.Cipher, true, &cr.iv)
			w.WriteHeader(resp.StatusCode)

			if nr, err := proxy.Cipher.IO.Copy(w, resp.Body, &cr.iv, proxy.getIOConfig(cr.Auth)); err != nil {
				logg.E("copy ", nr, " bytes: ", err)
			}

			tryClose(resp.Body)
		}
	} else {
		proxy.blacklist.Add(addr, nil)
		replySomething()
	}
}

func (proxy *ProxyUpstream) Start() (err error) {
	proxy.Listener, err = tcpmux.Listen(proxy.Localaddr, true)
	if err != nil {
		return
	}

	proxy.Cipher.IO.Ob = proxy.Listener.(*tcpmux.ListenPool)

	go func() {
		for tick := range time.Tick(time.Second) {
			proxy.wsMapping.Lock()
			ts := tick.UnixNano()
			for k, ws := range proxy.wsMapping.m {
				if ws.last != 0 && (ts-ws.last)/1e9 > proxy.WSCBTimeout {
					ws.conn.Close()
					delete(proxy.wsMapping.m, k)
				}
			}
			proxy.wsMapping.Unlock()
		}
	}()

	return http.Serve(proxy.Listener, proxy)
}

func NewServer(addr string, config *ServerConfig) *ProxyUpstream {
	proxy := &ProxyUpstream{
		tp: &http.Transport{TLSClientConfig: tlsSkip},

		ServerConfig: config,
		blacklist:    lru.NewCache(128),
	}

	proxy.wsMapping.m = make(map[[ivLen]byte]*wsCallback)

	tcpmux.Version = byte(msg64.Crc16b(0, []byte(config.Cipher.Alias))) | 0x80

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

type wsCallback struct {
	sync.Mutex
	last int64
	conn net.Conn
	rBuf []byte
}

func (w *wsCallback) Write(buf []byte) (n int, err error) {
	w.last = time.Now().UnixNano()
	w.Lock()
	w.rBuf = append(w.rBuf, buf...)
	w.Unlock()
	return len(buf), nil
}
