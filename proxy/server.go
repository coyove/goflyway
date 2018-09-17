package proxy

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/coyove/common/logg"
	"github.com/coyove/common/lru"
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
	LBindTimeout  int64
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

type localRPCtrlSrvReq struct {
	dst      string
	conn     net.Conn
	callback chan localRPCtrlSrvResp
	rawReq   []byte
}

type localRPCtrlSrvResp struct {
	err      error
	localrpr string
	req      localRPCtrlSrvReq
}

// ProxyUpstream is the main struct for upstream server
type ProxyUpstream struct {
	tp        *http.Transport
	rp        http.Handler
	blacklist *lru.Cache

	localRP struct {
		sync.Mutex
		downstream net.Conn
		requests   chan localRPCtrlSrvReq
		waiting    map[string]localRPCtrlSrvResp
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
		logg.E("Webserver doesn't support hijacking")
		return nil
	}

	conn, _, err := hij.Hijack()
	if err != nil {
		logg.E("Hijacking: ", err.Error())
		return nil
	}

	return conn
}

func (proxy *ProxyUpstream) replyGood(downstreamConn net.Conn, cr *clientRequest, ioc *IOConfig, r *http.Request) {
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
		logg.W("Unknown address: ", r.RemoteAddr)
		replySomething()
		return
	}

	var rawReq []byte
	if proxy.localRP.waiting != nil {
		rawReq, _ = httputil.DumpRequest(r, true)
	}

	dst, cr := proxy.decryptHost(stripURI(r.RequestURI))

	if dst == "" || cr == nil {
		if proxy.localRP.waiting != nil {
			userConn := proxy.hijack(w)
			cb := make(chan localRPCtrlSrvResp, 1)

			proxy.localRP.requests <- localRPCtrlSrvReq{
				dst:      dst,
				conn:     userConn,
				callback: cb,
				rawReq:   rawReq,
			}

			logg.D("LocalRP: wait client to response")
			select {
			case resp := <-cb:
				if resp.err != nil {
					userConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n" + resp.err.Error()))
					return
				}
			case <-time.After(time.Duration(proxy.LBindTimeout) * time.Second):
				logg.E("LocalRP: client didn't response")
				userConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\nError: localrp timed out"))
			}
			proxy.localRP.Lock()
			for k, resp := range proxy.localRP.waiting {
				if resp.req.conn == userConn {
					delete(proxy.localRP.waiting, k)
					break
				}
			}
			proxy.localRP.Unlock()
			return
		}
		logg.D("Invalid request from: ", addr, ", ", stripURI(r.RequestURI))
		proxy.blacklist.Add(addr, nil)
		replySomething()
		return
	}

	if proxy.Users != nil {
		if !proxy.auth(cr.Auth) {
			logg.W("User auth failed, from: ", addr)
			return
		}
	}

	if h, _, _ := proxy.blacklist.GetEx(addr); h > invalidRequestRetry {
		logg.D("Repeated access using invalid key from: ", addr)
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

	} else if cr.Opt.IsSet(doLocalRP) {
		ioc := proxy.getIOConfig(cr.Auth)
		ioc.Partial = cr.Opt.IsSet(doPartial)

		if dst == "a" {
			proxy.startLocalRPControlServer(proxy.hijack(w), cr, ioc)
		} else if proxy.localRP.waiting != nil {
			resp, ok := proxy.localRP.waiting[dst]
			if !ok {
				return
			}

			downstreamConn := proxy.hijack(w)
			proxy.replyGood(downstreamConn, cr, &ioc, r)
			go proxy.Cipher.IO.Bridge(downstreamConn, resp.req.conn, &cr.iv, ioc)
			resp.req.callback <- resp
			return
		}
	} else if cr.Opt.IsSet(doConnect) {
		host := dst
		if host == "" {
			logg.W("We had a valid rkey, but invalid host, from: ", addr)
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
				logg.W("Client is trying to send UDP data but we disabled it")
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

		proxy.replyGood(downstreamConn, cr, &ioc, r)

		if cr.Opt.IsSet(doMuxWS) {
			proxy.Listener.(*tcpmux.ListenPool).Upgrade(downstreamConn)
			logg.D("Downstream connection has been upgraded to multiplexer stream")
		} else {
			go proxy.Cipher.IO.Bridge(downstreamConn, targetSiteConn, &cr.iv, ioc)
		}
	} else if cr.Opt.IsSet(doForward) {
		var err error

		r.URL, err = url.Parse(dst)
		if err != nil {
			replySomething()
			return
		}

		r.Host = r.URL.Host
		proxy.decryptRequest(r, cr)

		logg.D(r.Method, " ", r.URL.String())

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
			logg.E("Copy ", nr, " bytes: ", err)
		}

		tryClose(resp.Body)
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

	return http.Serve(proxy.Listener, proxy)
}

func NewServer(addr string, config *ServerConfig) *ProxyUpstream {
	proxy := &ProxyUpstream{
		tp: &http.Transport{TLSClientConfig: tlsSkip},

		ServerConfig: config,
		blacklist:    lru.NewCache(128),
	}

	// tcpmux.HashSeed = config.Cipher.keyBuf

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

func (proxy *ProxyUpstream) startLocalRPControlServer(downstream net.Conn, cr *clientRequest, ioc IOConfig) {
	if _, err := downstream.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		logg.E(err)
		downstream.Close()
		return
	}

	proxy.localRP.Lock()
	if proxy.localRP.downstream != nil {
		proxy.localRP.Unlock()
		return
	}
	proxy.localRP.downstream = downstream
	proxy.localRP.requests = make(chan localRPCtrlSrvReq, 100)
	proxy.localRP.waiting = make(map[string]localRPCtrlSrvResp)
	proxy.localRP.Unlock()

	conn := &DummyConn{}
	conn.Init()
	connw := DummyConnWrapper{conn}

	go func() {
		go proxy.Cipher.IO.Bridge(downstream, conn, &cr.iv, ioc)
		go func() {
			for {
				select {
				case req := <-proxy.localRP.requests:
					if len(req.dst) >= 65535 {
						req.callback <- localRPCtrlSrvResp{
							err: fmt.Errorf("request too long"),
						}
						continue
					}

					buf := make([]byte, 16+4+len(req.rawReq))
					proxy.Cipher.Rand.Read(buf[:16])

					localrpr := fmt.Sprintf("%x", buf[:16])
					binary.BigEndian.PutUint32(buf[16:20], uint32(len(req.rawReq)))
					copy(buf[20:], req.rawReq)

					proxy.localRP.waiting[localrpr] = localRPCtrlSrvResp{
						localrpr: localrpr,
						req:      req,
					}

					go connw.Write(buf)
				}
			}
		}()

		for {
			buf := make([]byte, 16)
			if _, err := connw.Write(buf); err != nil {
				break
			}
			if _, err := connw.Read(buf); err != nil {
				break
			}
			// logg.D("LocalRP: pong")
			time.Sleep(localRPPingInterval)
		}

		proxy.localRP.Lock()
		if proxy.localRP.downstream == downstream {
			proxy.localRP.downstream = nil
			proxy.localRP.waiting = nil
		}
		proxy.localRP.Unlock()
		downstream.Close()
	}()
}
