package proxy

import (
	"crypto/tls"
	"os"

	"github.com/coyove/common/logg"
	"github.com/coyove/common/lru"
	acr "github.com/coyove/goflyway/pkg/aclrouter"
	"github.com/coyove/tcpmux"

	"github.com/xtaci/kcp-go"

	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ResponseHook interface {
	SetBody(r io.ReadCloser)
}

type ClientConfig struct {
	Upstream       string
	UserAuth       string
	UDPRelayCoconn int64
	Mux            int64
	Connect2       string
	Connect2Auth   string
	DummyDomain    string
	LocalRPBind    string
	MITMDump       *os.File
	DNSCache       *lru.Cache
	CA             tls.Certificate
	CACache        *lru.Cache
	ACL            *acr.ACL
	Logger         *logg.Logger
	Policy         Options

	*Cipher
}

type ProxyClient struct {
	*ClientConfig

	tp      *http.Transport // to upstream
	tpq     *http.Transport // to upstream used for dns query
	tpd     *http.Transport // to host directly
	dummies *lru.Cache
	pool    *tcpmux.DialPool
	addr    *net.TCPAddr

	Localaddr string
	Listener  *listenerWrapper
}

func (proxy *ProxyClient) dial(dialStyle byte) (conn net.Conn, err error) {
	lat := time.Now().UnixNano()
	if proxy.Connect2 == "" {
		switch dialStyle {
		case 'd':
			switch {
			case proxy.Policy.IsSet(PolicyKCP):
				conn, err = kcp.Dial(proxy.Upstream)
			case proxy.Policy.IsSet(PolicyHTTPS):
				conn, err = tls.Dial("tcp", proxy.Upstream, tlsSkip)
			default:
				conn, err = net.DialTimeout("tcp", proxy.Upstream, timeoutDial)
			}
		case 'v':
			conn, err = vpnDial(proxy.Upstream)
		default:
			conn, err = proxy.pool.DialTimeout(timeoutDial)
		}

		proxy.IO.Tr.Latency(time.Now().UnixNano() - lat)
		return
	}

	connectConn, err := net.DialTimeout("tcp", proxy.Connect2, timeoutDial)
	if err != nil {
		return nil, err
	}

	up, auth := proxy.Upstream, ""
	if proxy.Connect2Auth != "" {
		// if proxy.Connect2Auth == "socks5" || true {
		// 	connectConn.SetWriteDeadline(time.Now().Add(timeoutOp))
		// 	if _, err = connectConn.Write(socksHandshake); err != nil {
		// 		connectConn.Close()
		// 		return nil, err
		// 	}

		// 	buf := make([]byte, 263)
		// 	connectConn.SetReadDeadline(time.Now().Add(timeoutOp))
		// 	if _, err = connectConn.Read(buf); err != nil {
		// 		connectConn.Close()
		// 		return nil, err
		// 	}

		// 	if buf[0] != socksVersion5 || buf[1] != 0 {
		// 		connectConn.Close()
		// 		return nil, errors.New("unsupported SOCKS5 authentication: " + strconv.Itoa(int(buf[1])))
		// 	}

		// 	host, _port, err := net.SplitHostPort(proxy.Upstream)
		// 	port, _ := strconv.Atoi(_port)
		// 	if err != nil {
		// 		connectConn.Close()
		// 		return nil, err
		// 	}

		// 	payload := []byte{socksVersion5, 1, 0, socksAddrDomain, byte(len(host))}
		// 	payload = append(payload, []byte(host+"00")...)
		// 	binary.BigEndian.PutUint16(payload[len(payload)-2:], uint16(port))

		// 	connectConn.SetWriteDeadline(time.Now().Add(timeoutOp))
		// 	if _, err = connectConn.Write(payload); err != nil {
		// 		connectConn.Close()
		// 		return nil, err
		// 	}

		// 	connectConn.SetReadDeadline(time.Now().Add(timeoutOp))
		// 	if n, err := io.ReadAtLeast(connectConn, buf[:5], 5); err != nil || n < 5 {
		// 		connectConn.Close()
		// 		return nil, err
		// 	}

		// 	if buf[1] != 0 {
		// 		connectConn.Close()
		// 		return nil, errors.New("SOCKS5 returned error: " + strconv.Itoa(int(buf[1])))
		// 	}

		// 	ln := 0
		// 	switch buf[3] {
		// 	case socksAddrIPv4:
		// 		ln = net.IPv4len - 1 + 2
		// 	case socksAddrIPv6:
		// 		ln = net.IPv6len - 1 + 2
		// 	case socksAddrDomain:
		// 		ln = int(buf[4]) + 2
		// 	default:
		// 		connectConn.Close()
		// 		return nil, errors.New("unexpected address type: " + strconv.Itoa(int(buf[3])))
		// 	}

		// 	connectConn.SetReadDeadline(time.Now().Add(timeoutOp))
		// 	if n, err := io.ReadAtLeast(connectConn, buf[5:5+ln], ln); err != nil || n < ln {
		// 		connectConn.Close()
		// 		return nil, err
		// 	}

		// 	return connectConn, nil
		// _, addr, err := parseUDPHeader(nil, buf, true)
		// connectConn.Close()
		// if err != nil {
		// 	return nil, err
		// }

		// proxy.Logger.Dbgf("Client","dial ", addr.String())
		// return net.DialTimeout("tcp", addr.String(), timeoutDial)
		// }

		x := base64.StdEncoding.EncodeToString([]byte(proxy.Connect2Auth))
		auth = fmt.Sprintf("Proxy-Authorization: Basic %s\r\nAuthorization: Basic %s\r\n", x, x)
	}

	connect := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", up, up, auth)
	connectConn.SetWriteDeadline(time.Now().Add(timeoutOp))
	if _, err = connectConn.Write([]byte(connect)); err != nil {
		connectConn.Close()
		return nil, err
	}

	respbuf, err := readUntil(connectConn, "\r\n\r\n")
	if err != nil {
		connectConn.Close()
		return nil, err
	}

	if !bytes.Contains(respbuf, []byte(" 200 ")) { //
		x := string(respbuf)
		if x = x[strings.Index(x, " ")+1:]; len(x) > 3 {
			x = x[:3]
		}

		connectConn.Close()
		return nil, errors.New("connect2: cannot connect to the HTTPS proxy (" + x + ")")
	}

	proxy.IO.Tr.Latency(time.Now().UnixNano() - lat)
	return connectConn, nil
}

func (proxy *ProxyClient) DialUpstream(conn net.Conn, host string, resp []byte, extra uint32, dialStyle byte) (net.Conn, error) {
	if proxy.Policy.IsSet(PolicyWebSocket) {
		return proxy.dialUpstreamWS(conn, host, resp, extra, dialStyle)
	}
	return proxy.dialUpstream(conn, host, resp, extra, dialStyle)
}

func (proxy *ProxyClient) dialUpstream(downstreamConn net.Conn, host string, resp []byte, extra uint32, dialStyle byte) (net.Conn, error) {
	upstreamConn, err := proxy.dial(0)
	if err != nil {
		downstreamConn.Close()
		return nil, err
	}

	r := proxy.Cipher.newRequest()
	r.Opt = Options(doConnect | extra)
	r.Real = host
	r.Auth = proxy.UserAuth
	switch proxy.Cipher.Mode {
	case PartialCipher:
		r.Opt.Set(doPartialCipher)
	case NoneCipher:
		r.Opt.Set(doDisableCipher)
	}

	var pl buffer
	pl.Writes("GET /", proxy.encryptClientRequest(r), " HTTP/1.1\r\n")
	pl.Writes("Host: ", proxy.genHost(), "\r\n")
	for _, h := range dummyHeaders {
		if v, ok := proxy.dummies.Get(h); ok && v.(string) != "" {
			pl.Writes(h, ": ", v.(string), "\r\n")
		}
	}

	upstreamConn.Write(pl.Writes("\r\n").Bytes())
	buf, err := readUntil(upstreamConn, "\r\n\r\n")
	if err != nil || !bytes.HasPrefix(buf, http200) {
		if err == nil {
			err = fmt.Errorf("invalid response from %s: %s", host, string(buf))
		}

		if bytes.HasPrefix(buf, http403) {
			err = fmt.Errorf("server rejected the request of %s", host)
		}

		upstreamConn.Close()
		downstreamConn.Close()
		return nil, err
	}

	if resp != nil {
		downstreamConn.Write(resp)
	}

	go proxy.Cipher.IO.Bridge(downstreamConn, upstreamConn, r.IV, IOConfig{
		Mode: proxy.Cipher.Mode,
	})

	return upstreamConn, nil
}

func (proxy *ProxyClient) dialUpstreamWS(downstreamConn net.Conn, host string, resp []byte, extra uint32, dialStyle byte) (net.Conn, error) {
	upstreamConn, err := proxy.dial(dialStyle)
	if err != nil {
		if downstreamConn != nil {
			downstreamConn.Close()
		}
		return nil, err
	}

	r := proxy.Cipher.newRequest()
	r.Opt = Options(doConnect | doWebSocket | extra)
	r.Real = host
	r.Auth = proxy.UserAuth
	switch proxy.Cipher.Mode {
	case PartialCipher:
		r.Opt.Set(doPartialCipher)
	case NoneCipher:
		r.Opt.Set(doDisableCipher)
	}

	var pl buffer
	if !proxy.Policy.IsSet(PolicyForward) {
		pl.Writes("GET /", proxy.encryptClientRequest(r), " HTTP/1.1\r\n")
		pl.Writes("Host: ", proxy.genHost(), "\r\n")
	} else {
		pl.Writes("GET http://", proxy.Upstream, "/ HTTP/1.1\r\n")
		pl.Writes("Host: ", proxy.Upstream, "\r\n")
		pl.Writes(fwdURLHeader, ": http://", proxy.genHost(), "/", proxy.encryptClientRequest(r), "\r\n")
	}

	wsKey := [20]byte{}
	proxy.Cipher.Rand.Read(wsKey[:])
	pl.Writes("Upgrade: websocket\r\n")
	pl.Writes("Connection: Upgrade\r\n")
	pl.Writes("Sec-WebSocket-Key: ", base64.StdEncoding.EncodeToString(wsKey[:]), "\r\n")
	pl.Writes("Sec-WebSocket-Version: 13\r\n\r\n")

	upstreamConn.Write(pl.Bytes())

	buf, err := readUntil(upstreamConn, "\r\n\r\n")
	if err != nil || !bytes.HasPrefix(buf, http101) {
		if err == nil {
			err = fmt.Errorf("invalid websocket response from %s: %s", host, string(buf))
		}

		if bytes.HasPrefix(buf, http403) {
			err = fmt.Errorf("server rejected the request of %s", host)
		}

		upstreamConn.Close()
		if downstreamConn != nil {
			downstreamConn.Close()
		}

		return nil, err
	}

	if extra == doMuxWS {
		// we return here and handle the connection to tcpmux
		return upstreamConn, nil
	}

	if resp != nil {
		downstreamConn.Write(resp)
	}

	go proxy.Cipher.IO.Bridge(downstreamConn, upstreamConn, r.IV, IOConfig{
		Mode:   proxy.Cipher.Mode,
		WSCtrl: wsClient,
	})
	return upstreamConn, nil
}

func (proxy *ProxyClient) dialHost(downstreamConn net.Conn, host string, resp []byte) (net.Conn, error) {
	targetSiteConn, err := net.Dial("tcp", host)
	if err != nil {
		downstreamConn.Close()
		return nil, err
	}

	downstreamConn.Write(resp)
	go proxy.Cipher.IO.Bridge(downstreamConn, targetSiteConn, [ivLen]byte{}, IOConfig{})
	return downstreamConn, nil
}

func (proxy *ProxyClient) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if proxy.UserAuth != "" {
		if proxy.basicAuth(r.Header.Get("Proxy-Authorization")) == "" {
			w.Header().Set("Proxy-Authenticate", "Basic realm=goflyway")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
	}

	if r.RequestURI == "/proxy.pac" {
		proxy.servePACFile(w, r)
		return
	}

	if r.Method == "CONNECT" {
		hij, _ := w.(http.Hijacker) // No HTTP2
		proxyClient, _, err := hij.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// we are inside GFW and should pass data to upstream
		host := r.URL.Host
		if !hasPort.MatchString(host) {
			host += ":80"
		}

		if ans, ext := proxy.canDirectConnect(host); ans == ruleBlock {
			proxy.Logger.Infof("%s - %s", ext, host)
			proxyClient.Close()
		} else if ans == rulePass {
			proxy.Logger.Logf("%s - %s", ext, r.RequestURI)
			_, err = proxy.dialHost(proxyClient, host, okHTTP)
		} else if proxy.Policy.IsSet(PolicyMITM) {
			proxy.manInTheMiddle(proxyClient, host)
		} else {
			proxy.Logger.Logf("%s - %s", ext, r.RequestURI)
			_, err = proxy.DialUpstream(proxyClient, host, okHTTP, 0, 0)
		}

		proxy.Logger.If(err != nil).Errorf("Dial failed: %v", err)
	} else {
		// normal http requests
		if !r.URL.IsAbs() {
			http.Error(w, "Request URI must be absolute", http.StatusInternalServerError)
			return
		}

		// borrow some headers from real browsings
		proxy.addToDummies(r)

		r.URL.Host = r.Host
		rURL := r.URL.String()
		r.Header.Del("Proxy-Authorization")
		r.Header.Del("Proxy-Connection")

		var resp *http.Response
		var err error
		var iv [ivLen]byte

		if ans, ext := proxy.canDirectConnect(r.Host); ans == ruleBlock {
			proxy.Logger.Infof("%s - %s", ext, r.Host)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		} else if ans == rulePass {
			proxy.Logger.Logf("%s - %s %s", ext, r.Method, r.Host)
			resp, err = proxy.tpd.RoundTrip(r)
		} else {
			proxy.Logger.Logf("%s - %s %s", ext, r.Method, r.Host)
			cr := proxy.newRequest()
			cr.Opt.Set(doForward)
			iv = proxy.encryptRequest(r, cr)
			resp, err = proxy.tp.RoundTrip(r)
		}

		if err != nil {
			proxy.Logger.Errorf("Round trip %s: %v", err, rURL)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		copyHeaders(w.Header(), resp.Header, proxy.Cipher, false, iv)
		w.WriteHeader(resp.StatusCode)

		if h, ok := w.(ResponseHook); ok {
			h.SetBody(proxy.Cipher.IO.NewReadCloser(resp.Body, iv))
		} else {
			mode := proxy.Cipher.Mode
			if mode == PartialCipher {
				mode = FullCipher
			}
			if nr, err := proxy.Cipher.IO.Copy(w, resp.Body, iv, IOConfig{
				Mode: mode,
				Role: roleRecv,
			}); err != nil {
				proxy.Logger.Errorf("IO copy %d bytes: %v", nr, err)
			}

			tryClose(resp.Body)
		}
	}
}

func (proxy *ProxyClient) authSOCKS(conn net.Conn) bool {
	buf := make([]byte, 1+1+255+1+255)
	n, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		proxy.Logger.Errorf("SOCKS5 error: %v", err)
		return false
	}

	ulen := int(buf[1])
	if buf[0] != 0x01 || 2+ulen+1 > n {
		return false
	}

	username := string(buf[2 : 2+ulen])
	plen := int(buf[2+ulen])
	if 2+ulen+1+plen > n {
		return false
	}

	password := string(buf[2+ulen+1 : 2+ulen+1+plen])
	return proxy.UserAuth == username+":"+password
}

func (proxy *ProxyClient) handleSOCKS(conn net.Conn) {
	logClose := func(args ...interface{}) {
		proxy.Logger.Errorf(args[0].(string), args[1:]...)
		conn.Close()
	}

	buf := make([]byte, 2)
	if _, err := io.ReadAtLeast(conn, buf, 2); err != nil {
		logClose("SOCKS5 error: %v", err)
		return
	} else if buf[0] != socksVersion5 {
		logClose("SOCKS5 version error: %v", buf[0])
		return
	}

	numMethods := int(buf[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadAtLeast(conn, methods, numMethods); err != nil {
		logClose("SOCKS5 error: %v", err)
		return
	}

	if proxy.UserAuth != "" {
		conn.Write([]byte{socksVersion5, 0x02}) // username & password auth

		if !proxy.authSOCKS(conn) {
			conn.Write([]byte{1, 1})
			logClose("SOCKS5 auth error from %s", conn.RemoteAddr)
			return
		}

		// auth success
		conn.Write([]byte{1, 0})
	} else {
		conn.Write([]byte{socksVersion5, 0})
	}
	// handshake over
	// tunneling start
	method, addr, err := parseUDPHeader(conn, nil, false)
	if err != nil {
		logClose("SOCKS5 error: %v", err)
		return
	}

	host := addr.String()
	switch method {
	case 1:
		if ans, ext := proxy.canDirectConnect(host); ans == ruleBlock {
			proxy.Logger.Infof("%s - %s", ext, host)
			conn.Close()
		} else if ans == rulePass {
			proxy.Logger.Logf("%s - %s", ext, host)
			_, err = proxy.dialHost(conn, host, okSOCKS)
		} else {
			proxy.Logger.Logf("%s - %s", ext, host)
			_, err = proxy.DialUpstream(conn, host, okSOCKS, 0, 0)
		}
		proxy.Logger.If(err != nil).Errorf("Dial failed: %v", err)
	case 3:
		relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
		if err != nil {
			logClose("UDP relay server can't start: %v", err)
			return
		}

		proxy.handleUDPtoTCP(relay, conn)
	}
}

func (proxy *ProxyClient) Bridge(down net.Conn, host string) {
	if proxy.Policy.IsSet(PolicyWebSocket) {
		proxy.DialUpstream(down, host, nil, 0, 0)
	} else {
		proxy.DialUpstream(down, host, nil, 0, 0)
	}
}

func (proxy *ProxyClient) Start() error {
	mux, err := net.ListenTCP("tcp", proxy.addr)
	if err != nil {
		return err
	}

	proxy.Listener = &listenerWrapper{mux, proxy}
	return http.Serve(proxy.Listener, proxy)
}

func NewClient(localaddr string, config *ClientConfig) (*ProxyClient, error) {
	var err error
	var upURL *url.URL

	upURL, err = url.Parse("http://" + config.Upstream)
	if err != nil {
		return nil, err
	}

	// tcpmux.HashSeed = config.Cipher.keyBuf

	proxyURL := http.ProxyURL(upURL)
	proxy := &ProxyClient{
		pool: tcpmux.NewDialer(config.Upstream, int(config.Mux)),

		tp:  &http.Transport{TLSClientConfig: tlsSkip, Proxy: proxyURL, Dial: (&net.Dialer{Timeout: timeoutDial}).Dial},
		tpd: &http.Transport{TLSClientConfig: tlsSkip},
		tpq: &http.Transport{TLSClientConfig: tlsSkip, Proxy: proxyURL, ResponseHeaderTimeout: timeoutOp, Dial: (&net.Dialer{Timeout: timeoutDial}).Dial},

		dummies: lru.NewCache(int64(len(dummyHeaders))),

		ClientConfig: config,
	}

	proxy.pool.Key = config.Cipher.keyBuf

	if proxy.Policy.IsSet(PolicyHTTPS) {
		proxy.pool.OnDial = func(addr string) (net.Conn, error) {
			return tls.Dial("tcp", addr, tlsSkip)
		}
		proxy.tp.Dial = func(network, addr string) (net.Conn, error) {
			return tls.Dial("tcp", addr, tlsSkip)
		}
		proxy.tpq.Dial = proxy.tp.Dial
	}

	if proxy.Policy.IsSet(PolicyKCP) {
		proxy.pool.OnDial = kcp.Dial
		proxy.tpq.Dial = func(network, address string) (net.Conn, error) {
			return kcp.Dial(address)
		}
		proxy.tp.Dial = proxy.tpq.Dial
	}

	if config.Mux > 0 {
		proxy.Cipher.IO.Ob = proxy.pool

		if config.Policy.IsSet(PolicyWebSocket) {
			// dialUpstreamAndBridgeWS will call dialUpstream,
			// and dialUpstream will call OnDial again,
			// so we set dial style to 'd' (direct) to avoid infinite loop
			// If we are in VPN mode, this value will be later set to 'v' (vpn)

			proxy.pool.OnDial = func(address string) (conn net.Conn, err error) {
				if proxy.Policy.IsSet(PolicyForward) {
					// fwds://...
					return proxy.dialUpstreamWS(nil, proxy.DummyDomain, nil, doMuxWS, 'd')
				}
				return proxy.dialUpstreamWS(nil, address, nil, doMuxWS, 'd')
			}
		}
	}

	if proxy.Connect2 != "" || proxy.Mux != 0 {
		proxy.tp.Proxy, proxy.tpq.Proxy = nil, nil
		proxy.tpq.Dial = func(network, address string) (net.Conn, error) { return proxy.dial(0) }
		proxy.tp.Dial = proxy.tpq.Dial
	}

	if config.Policy.IsSet(PolicyMITM) {
		// plus other fds, we should have a number smaller than 100
		proxy.tp.MaxIdleConns = 20
		proxy.tpd.MaxIdleConns = 20
		proxy.tpq.MaxIdleConns = 20
	}

	if proxy.UDPRelayCoconn <= 0 {
		proxy.UDPRelayCoconn = 1
	}

	if port, lerr := strconv.Atoi(localaddr); lerr == nil {
		proxy.addr = &net.TCPAddr{IP: net.IPv6zero, Port: port}
		localaddr = "0.0.0.0:" + localaddr
	} else {
		proxy.addr, err = net.ResolveTCPAddr("tcp", localaddr)
		if err != nil {
			return nil, err
		}

		if localaddr[0] == ':' {
			localaddr = "0.0.0.0" + localaddr
		}
	}

	proxy.Localaddr = localaddr

	if proxy.Policy.IsSet(PolicyVPN) {
		if config.Policy.IsSet(PolicyWebSocket) {
			proxy.pool.OnDial = func(address string) (conn net.Conn, err error) {
				return proxy.dialUpstreamWS(nil, address, nil, doMuxWS, 'v')
			}
		} else {
			proxy.pool.OnDial = vpnDial
		}

		proxy.IO.sendStat = true
		proxy.pool.DialTimeout(time.Second)
	}

	return proxy, nil
}
