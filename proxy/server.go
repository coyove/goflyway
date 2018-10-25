package proxy

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coyove/common/logg"
	"github.com/coyove/common/lru"
	acr "github.com/coyove/goflyway/pkg/aclrouter"
	"github.com/coyove/tcpmux"
	"github.com/xtaci/kcp-go"
)

type ServerConfig struct {
	Throttling    int64
	ThrottlingMax int64
	LBindTimeout  int64
	LBindCap      int64
	Policy        Options
	ProxyPassAddr string
	Logger        *logg.Logger
	ACL           *acr.ACL
	ACLCache      *lru.Cache
	HTTPS         *tls.Config
	Users         map[string]UserConfig

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
	end      bool
	conn     net.Conn
	callback chan localRPCtrlSrvResp
	rawReq   []byte
}

type localRPCtrlSrvResp struct {
	err      error
	localrpr string
	req      localRPCtrlSrvReq
}

// ProxyServer is the main struct for upstream server
type ProxyServer struct {
	tp        *http.Transport
	rp        http.Handler
	blacklist *lru.Cache

	localRP struct {
		sync.Mutex
		downstreams []net.Conn
		downConns   []dummyConnWrapper
		requests    chan localRPCtrlSrvReq
		waiting     map[string]localRPCtrlSrvResp
	}

	Localaddr string
	Listener  net.Listener

	*ServerConfig
}

func (proxy *ProxyServer) auth(auth string) bool {
	if _, existed := proxy.Users[auth]; existed {
		// we don't have multi-user mode currently
		return true
	}

	return false
}

func (proxy *ProxyServer) getIOConfig(cr *clientRequest) IOConfig {
	var ioc IOConfig
	if proxy.Throttling > 0 {
		ioc.Bucket = NewTokenBucket(proxy.Throttling, proxy.ThrottlingMax)
	}
	if cr.Opt.IsSet(doPartialCipher) {
		ioc.Mode = PartialCipher
	}
	if cr.Opt.IsSet(doDisableCipher) {
		ioc.Mode = NoneCipher
		proxy.Logger.Dbgf("We have a none cipher request: %v", cr)
	}
	return ioc
}

func (proxy *ProxyServer) Write(w http.ResponseWriter, key [ivLen]byte, p []byte, code int) (n int, err error) {
	if ctr := proxy.Cipher.getCipherStream(key); ctr != nil {
		ctr.XORKeyStream(p, p)
	}

	w.WriteHeader(code)
	return w.Write(p)
}

func (proxy *ProxyServer) hijack(w http.ResponseWriter) net.Conn {
	hij, ok := w.(http.Hijacker)
	if !ok {
		proxy.Logger.Errorf("Hijack failed: not supported")
		return nil
	}

	conn, _, err := hij.Hijack()
	if err != nil {
		proxy.Logger.Errorf("Hijack failed: %v", err)
		return nil
	}

	return conn
}

func (proxy *ProxyServer) replyGood(downstreamConn net.Conn, cr *clientRequest, ioc *IOConfig, r *http.Request) {
	var p buffer
	if cr.Opt.IsSet(doWebSocket) {
		ioc.WSCtrl = wsServer

		var accept buffer
		accept.Writes(r.Header.Get("Sec-WebSocket-Key"), "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
		ans := sha1.Sum(accept.Bytes())

		p.Writes("HTTP/1.1 101 Switching Protocols\r\n")
		p.Writes("Upgrade: websocket\r\n")
		p.Writes("Connection: upgrade\r\n")
		p.Writes("Sec-WebSocket-Accept: ", base64.StdEncoding.EncodeToString(ans[:]), "\r\n\r\n")
	} else {
		p.Writes("HTTP/1.1 200 OK\r\n")
		p.Writes("Content-Type: application/octet-stream\r\n")
		p.Writes("Date: ", time.Now().UTC().Format(time.RFC1123), "\r\n\r\n")
	}

	downstreamConn.Write(p.Bytes())
}

// ServeHTTPImpl returns true if it successfully handled the goflyway request, false if any error occurred.
// When succeed, ServeHTTPImpl will take over all controls of w and r, caller shall not alter them ever after.
func (proxy *ProxyServer) ServeHTTPImpl(w http.ResponseWriter, r *http.Request) bool {
	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		proxy.Logger.Warnf("Unknown address: %s", r.RemoteAddr)
		return false
	}

	var rawReq []byte
	if proxy.localRP.waiting != nil {
		rawReq, _ = httputil.DumpRequest(r, true)
	}

DE_AGAIN:
	dst := ""
	cr := proxy.decryptClientRequest(proxy.stripURI(r.RequestURI))
	if cr != nil {
		dst = cr.Real
	}

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

			proxy.Logger.Dbgf("RP ctrl server waits client to response")
			select {
			case resp := <-cb:
				if resp.err != nil {
					userConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\nError: " + resp.err.Error()))
					return true
				}
			case <-time.After(time.Duration(proxy.LBindTimeout) * time.Second):
				proxy.Logger.Errorf("RP client didn't response")
				userConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\nError: localrp timed out"))
			}
			proxy.Logger.Dbgf("RP client OK")

			proxy.localRP.Lock()
			for k, resp := range proxy.localRP.waiting {
				if resp.req.conn == userConn {
					delete(proxy.localRP.waiting, k)
					break
				}
			}
			proxy.localRP.Unlock()
			return true
		}

		if fu := r.Header.Get(fwdURLHeader); fu != "" {
			r.RequestURI = fu
			r.Header.Del(fwdURLHeader)
			goto DE_AGAIN
		}

		proxy.Logger.Dbgf("Invalid request from %s: %s", addr, proxy.stripURI(r.RequestURI))
		proxy.blacklist.Add(addr, nil)
		return false
	}

	if proxy.Users != nil {
		if !proxy.auth(cr.Auth) {
			proxy.Logger.Warnf("User auth failed from %s", addr)
			return true
		}
	}

	if h, _, _ := proxy.blacklist.GetEx(addr); h > invalidRequestRetry {
		proxy.Logger.Dbgf("Repeated access using invalid key from %s", addr)
		// replySomething()
		// return
	}

	if cr.Opt.IsSet(doDNS) {
		host := cr.Query
		ip, err := net.ResolveIPAddr("ip4", host)
		if err != nil {
			proxy.Logger.Warnf("DNS query failed: %v", err)
			ip = &net.IPAddr{IP: net.IP{127, 0, 0, 1}}
		}

		proxy.Logger.Dbgf("DNS answer of %s: %s", host, ip.String())
		w.Header().Add(dnsRespHeader, base64.StdEncoding.EncodeToString([]byte(ip.IP.To4())))
		w.WriteHeader(200)
		return true
	}

	if cr.Opt.IsSet(doLocalRP) {
		ioc := proxy.getIOConfig(cr)

		if dst == "localrp" {
			proxy.startLocalRPControlServer(proxy.hijack(w), cr, ioc)
		} else if proxy.localRP.waiting != nil {
			proxy.localRP.Lock()
			resp, ok := proxy.localRP.waiting[dst]
			if !ok {
				proxy.localRP.Unlock()
				return true
			}
			proxy.localRP.Unlock()

			downstreamConn := proxy.hijack(w)
			proxy.replyGood(downstreamConn, cr, &ioc, r)
			go proxy.Cipher.IO.Bridge(downstreamConn, resp.req.conn, cr.IV, ioc)
			resp.req.callback <- resp
			return true
		}
	}

	if proxy.isBlocked(dst) {
		w.WriteHeader(http.StatusForbidden)
		proxy.Logger.Logf("%s is blocked", dst)
		return true
	}

	if cr.Opt.IsSet(doConnect) {
		host := dst
		if host == "" {
			proxy.Logger.Warnf("Valid rkey invalid host from %s", addr)
			return false
		}

		proxy.Logger.Logf("Dial real host: %s", host)
		downstreamConn := proxy.hijack(w)
		if downstreamConn == nil {
			return false
		}

		ioc := proxy.getIOConfig(cr)

		var targetSiteConn net.Conn
		var err error

		if cr.Opt.IsSet(doUDPRelay) {
			if proxy.Policy.IsSet(PolicyDisableUDP) {
				proxy.Logger.Warnf("Client UDP relay request rejected")
				downstreamConn.Close()
				return false
			}

			uaddr, _ := net.ResolveUDPAddr("udp", host)

			var rconn *net.UDPConn
			rconn, err = net.DialUDP("udp", nil, uaddr)
			targetSiteConn = &udpBridgeConn{
				UDPConn: rconn,
				udpSrc:  uaddr,
				logger:  proxy.Logger,
			}
			// rconn.Write([]byte{6, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0, 0, 1, 0, 1})
		} else {
			targetSiteConn, err = net.Dial("tcp", host)
		}

		if err != nil {
			proxy.Logger.Errorf("Dial real host failed: %v", err)
			downstreamConn.Close()
			return false
		}

		proxy.replyGood(downstreamConn, cr, &ioc, r)

		if cr.Opt.IsSet(doMuxWS) {
			proxy.Listener.(*tcpmux.ListenPool).Upgrade(downstreamConn)
			proxy.Logger.Dbgf("Downstream connection has been upgraded to multiplexer master")
			targetSiteConn.Close()
		} else {
			go proxy.Cipher.IO.Bridge(downstreamConn, targetSiteConn, cr.IV, ioc)
		}
		return true
	} else if cr.Opt.IsSet(doHTTPReq) {
		var err error

		r.URL, err = url.Parse(dst)
		if err != nil {
			return false
		}

		r.Host = r.URL.Host
		proxy.decryptRequest(r, cr)

		proxy.Logger.Dbgf("HTTP forward: %s %s", r.Method, r.URL.String())

		resp, err := proxy.tp.RoundTrip(r)
		if err != nil {
			proxy.Logger.Errorf("Round trip %s: %v", r.URL, err)
			proxy.Write(w, cr.IV, []byte(err.Error()), http.StatusInternalServerError)
			return true
		}

		copyHeaders(w.Header(), resp.Header, proxy.Cipher, true, cr.IV)
		w.WriteHeader(resp.StatusCode)

		ioc := proxy.getIOConfig(cr)
		if ioc.Mode == PartialCipher {
			ioc.Mode = FullCipher
		}

		if nr, err := proxy.Cipher.IO.Copy(w, resp.Body, cr.IV, ioc); err != nil {
			proxy.Logger.Errorf("IO copy %d bytes: %v", nr, err)
		}

		tryClose(resp.Body)
		return true
	} else {
		proxy.blacklist.Add(addr, nil)
		return false
	}
}

func (proxy *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !proxy.ServeHTTPImpl(w, r) {
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
}

func (proxy *ProxyServer) Start() (err error) {
	switch {
	case proxy.Policy.IsSet(PolicyKCP):
		ln, err := kcp.Listen(proxy.Localaddr)
		if err != nil {
			return err
		}
		proxy.Listener = tcpmux.Wrap(ln)
	case proxy.HTTPS != nil && proxy.Policy.IsSet(PolicyHTTPS):
		ln, err := tls.Listen("tcp", proxy.Localaddr, proxy.HTTPS)
		if err != nil {
			return err
		}
		proxy.Listener = tcpmux.Wrap(ln)
	default:
		proxy.Listener, err = tcpmux.Listen(proxy.Localaddr, true)
		if err != nil {
			return
		}
	}
	proxy.Cipher.IO.Ob = proxy.Listener.(*tcpmux.ListenPool)

	proxy.Listener.(*tcpmux.ListenPool).Key = proxy.Cipher.keyBuf

	if proxy.Logger.GetLevel() == logg.LvDebug {
		go func() {
			for range time.Tick(time.Minute) {
				proxy.localRP.Lock()
				if proxy.localRP.waiting != nil {
					proxy.Logger.Dbgf("RP ctrl server queue: %d waiting, %d connected", len(proxy.localRP.waiting), len(proxy.localRP.downConns))
				}
				proxy.localRP.Unlock()
			}
		}()
	}

	return http.Serve(proxy.Listener, proxy)
}

func NewServer(addr string, config *ServerConfig) (*ProxyServer, error) {
	proxy := &ProxyServer{
		tp: &http.Transport{TLSClientConfig: tlsSkip},

		ServerConfig: config,
		blacklist:    lru.NewCache(128),
	}

	// tcpmux.HashSeed = config.Cipher.keyBuf

	if config.ProxyPassAddr != "" {
		if strings.HasPrefix(config.ProxyPassAddr, "http") {
			u, err := url.Parse(config.ProxyPassAddr)
			if err != nil {
				return nil, nil
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
	return proxy, nil
}
