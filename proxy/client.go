package proxy

import (
	"crypto/tls"

	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/pkg/lru"
	"github.com/coyove/tcpmux"

	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ClientConfig struct {
	Upstream string
	Policy   Options
	UserAuth string

	Connect2     string
	Connect2Auth string
	DummyDomain  string
	URLHeader    string

	UDPRelayPort   int
	UDPRelayCoconn int

	Mux int

	DNSCache *lru.Cache
	CA       tls.Certificate
	CACache  *lru.Cache

	*Cipher
}

type ProxyClient struct {
	*ClientConfig

	rkeyHeader string
	tp         *http.Transport // to upstream
	tpq        *http.Transport // to upstream used for dns query
	tpd        *http.Transport // to host directly
	dummies    *lru.Cache
	pool       *tcpmux.DialPool

	UDP struct {
		sync.Mutex
		Conns map[string]*udp_tcp_conn_t
		Addrs map[net.Addr]bool
	}

	Localaddr string
	Listener  *listenerWrapper
}

func (proxy *ProxyClient) dialUpstream() (net.Conn, error) {
	if proxy.Connect2 == "" {
		upstreamConn, err := proxy.pool.DialTimeout(timeoutDial)
		if err != nil {
			return nil, err
		}

		return upstreamConn, nil
	}

	connectConn, err := net.DialTimeout("tcp", proxy.Connect2, timeoutDial)
	if err != nil {
		return nil, err
	}

	up, auth := proxy.Upstream, ""
	if proxy.Connect2Auth != "" {
		// if proxy.Connect2Auth == "socks5" {
		// 	connectConn.SetWriteDeadline(time.Now().Add(timeoutOp))
		// 	if _, err = connectConn.Write(SOCKS5_HANDSHAKE); err != nil {
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
		// 	payload = append(payload, []byte(host)...)
		// 	payload = append(payload, 0, 0)
		// 	binary.BigEndian.PutUint16(payload[len(payload)-2:], uint16(port))

		// 	connectConn.SetWriteDeadline(time.Now().Add(timeoutOp))
		// 	if _, err = connectConn.Write(payload); err != nil {
		// 		connectConn.Close()
		// 		return nil, err
		// 	}

		// 	connectConn.SetReadDeadline(time.Now().Add(timeoutOp))
		// 	if n, err := io.ReadAtLeast(connectConn, buf, 5); err != nil || n < 5 {
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
		// 	if n, err := io.ReadAtLeast(connectConn, buf, ln); err != nil || n < ln {
		// 		connectConn.Close()
		// 		return nil, err
		// 	}

		// 	return connectConn, nil
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

	if !bytes.Contains(respbuf, okHTTP[9:14]) { // []byte(" 200 ")
		x := string(respbuf)
		if x = x[strings.Index(x, " ")+1:]; len(x) > 3 {
			x = x[:3]
		}

		connectConn.Close()
		return nil, errors.New("connect2: cannot connect to the HTTPS proxy (" + x + ")")
	}

	return connectConn, nil
}

func (proxy *ProxyClient) dialUpstreamAndBridge(downstreamConn net.Conn, host string, resp []byte) net.Conn {
	upstreamConn, err := proxy.dialUpstream()
	if err != nil {
		logg.E(err)
		downstreamConn.Close()
		return nil
	}

	rkey, rkeybuf := proxy.Cipher.NewIV(doConnect, nil, proxy.UserAuth)
	pl := make([]string, 0, len(dummyHeaders)+3)
	pl = append(pl,
		"GET /"+proxy.Cipher.EncryptCompress(host, rkeybuf...)+" HTTP/1.1\r\n",
		"Host: "+proxy.genHost()+"\r\n")

	for _, i := range proxy.Rand.Perm(len(dummyHeaders)) {
		if h := dummyHeaders[i]; h == "ph" {
			pl = append(pl, proxy.rkeyHeader+": "+rkey+"\r\n")
		} else if v, ok := proxy.dummies.Get(h); ok && v.(string) != "" {
			pl = append(pl, h+": "+v.(string)+"\r\n")
		}
	}

	upstreamConn.Write([]byte(strings.Join(pl, "") + "\r\n"))

	buf, err := readUntil(upstreamConn, "\r\n\r\n")
	// the first 15 bytes MUST be "HTTP/1.1 200 OK"
	if err != nil || len(buf) < 15 || !bytes.Equal(buf[:15], okHTTP[:15]) {
		if err != nil {
			logg.E(err)
		}

		upstreamConn.Close()
		downstreamConn.Close()
		return nil
	}

	downstreamConn.Write(resp)
	go proxy.Cipher.IO.Bridge(downstreamConn, upstreamConn, rkeybuf, IOConfig{Partial: proxy.Partial})

	return upstreamConn
}

func (proxy *ProxyClient) dialUpstreamAndBridgeWS(downstreamConn net.Conn, host string, resp []byte) net.Conn {
	upstreamConn, err := proxy.dialUpstream()
	if err != nil {
		logg.E(err)
		downstreamConn.Close()
		return nil
	}

	rkey, rkeybuf := proxy.Cipher.NewIV(doConnect+doWebSocket, nil, proxy.UserAuth)
	var pl string
	if proxy.URLHeader == "" {
		pl = "GET /" + proxy.Cipher.EncryptCompress(host, rkeybuf...) + " HTTP/1.1\r\n" +
			"Host: " + proxy.genHost() + "\r\n"
	} else {
		pl = "GET http://" + proxy.Upstream + "/ HTTP/1.1\r\n" +
			"Host: " + proxy.Upstream + "\r\n" +
			proxy.URLHeader + ": http://" + proxy.genHost() + "/" + proxy.Cipher.EncryptCompress(host, rkeybuf...) + "\r\n"
	}

	pl += "Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + rkey[:24] + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		proxy.rkeyHeader + ": " + rkey + "\r\n\r\n"

	upstreamConn.Write([]byte(pl))

	buf, err := readUntil(upstreamConn, "\r\n\r\n")
	if err != nil || !strings.HasPrefix(string(buf), "HTTP/1.1 101 Switching Protocols") {
		if err != nil {
			logg.E(err)
		}

		upstreamConn.Close()
		downstreamConn.Close()
		return nil
	}

	downstreamConn.Write(resp)
	go proxy.Cipher.IO.Bridge(downstreamConn, upstreamConn, rkeybuf, IOConfig{
		Partial: proxy.Partial,
		WSCtrl:  wsClient,
	})
	return upstreamConn
}

func (proxy *ProxyClient) dialHostAndBridge(downstreamConn net.Conn, host string, resp []byte) {
	targetSiteConn, err := net.Dial("tcp", host)
	if err != nil {
		logg.E(err)
		downstreamConn.Close()
		return
	}

	downstreamConn.Write(resp)
	go proxy.Cipher.IO.Bridge(downstreamConn, targetSiteConn, nil, IOConfig{})
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
		proxy.PACFile(w, r)
		return
	}

	if r.Method == "CONNECT" {
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

		// we are inside GFW and should pass data to upstream
		host := r.URL.Host
		if !hasPort.MatchString(host) {
			host += ":80"
		}

		if proxy.canDirectConnect(host) {
			logg.D("CONNECT ", r.RequestURI)
			proxy.dialHostAndBridge(proxyClient, host, okHTTP)
		} else if proxy.Policy.IsSet(PolicyManInTheMiddle) {
			proxy.manInTheMiddle(proxyClient, host)
		} else if proxy.Policy.IsSet(PolicyWebSocket) {
			logg.D("WS^ ", r.RequestURI)
			proxy.dialUpstreamAndBridgeWS(proxyClient, host, okHTTP)
		} else {
			logg.D("CONNECT^ ", r.RequestURI)
			proxy.dialUpstreamAndBridge(proxyClient, host, okHTTP)
		}
	} else {
		// normal http requests
		if !r.URL.IsAbs() {
			http.Error(w, "request URI must be absolute", http.StatusInternalServerError)
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
		var rkeybuf []byte

		if proxy.canDirectConnect(r.Host) {
			logg.D(r.Method, " ", rURL)
			resp, err = proxy.tpd.RoundTrip(r)
		} else {
			logg.D(r.Method, "^ ", rURL)
			resp, rkeybuf, err = proxy.encryptAndTransport(r)
		}

		if err != nil {
			logg.E("HTTP forward: ", rURL, ", ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if resp.StatusCode >= 400 {
			logg.D("[", resp.Status, "] - ", rURL)
		}

		copyHeaders(w.Header(), resp.Header, proxy.Cipher, false, rkeybuf)
		w.WriteHeader(resp.StatusCode)

		if nr, err := proxy.Cipher.IO.Copy(w, resp.Body, rkeybuf, IOConfig{Partial: false}); err != nil {
			logg.E("copy ", nr, " bytes: ", err)
		}

		tryClose(resp.Body)
	}
}

func (proxy *ProxyClient) canDirectConnect(host string) bool {
	if proxy.Policy.IsSet(PolicyDisabled) {
		return true
	}

	host, _ = splitHostPort(host)
	isChineseIP := func(ip string) bool {
		if proxy.Policy.IsSet(PolicyGlobal) {
			return false
		}

		return lookup.IsChineseIP(ip)
	}

	if lookup.IsChineseWebsite(host) {
		return !proxy.Policy.IsSet(PolicyGlobal)
	}

	if ip, ok := proxy.DNSCache.Get(host); ok && ip.(string) != "" { // we have cached the host
		return lookup.IsPrivateIP(ip.(string)) || isChineseIP(ip.(string))
	}

	// lookup at local in case host points to a private ip
	ip, err := lookup.LookupIPv4(host)
	if err != nil {
		logg.E(err)
	}

	if lookup.IsPrivateIP(ip) {
		proxy.DNSCache.Add(host, ip)
		return true
	}

	// if it is a foreign ip or we trust local dns repsonse, just return the answer
	// but if it is a chinese ip, we withhold and query the upstream to double check
	maybeChinese := isChineseIP(ip)
	if !maybeChinese || proxy.Policy.IsSet(PolicyTrustClientDNS) {
		proxy.DNSCache.Add(host, ip)
		return maybeChinese
	}

	dnsloc := "http://" + proxy.genHost()
	rkey, _ := proxy.Cipher.NewIV(doDNS, []byte(host), proxy.UserAuth)

	if proxy.URLHeader != "" {
		dnsloc = "http://" + proxy.Upstream
	}

	req, err := http.NewRequest("GET", dnsloc, nil)
	if err != nil {
		logg.E(err)
		return maybeChinese
	}

	req.Header.Add(proxy.rkeyHeader, rkey)
	if proxy.URLHeader != "" {
		req.Header.Add(proxy.URLHeader, "http://"+proxy.genHost())
	}

	resp, err := proxy.tpq.RoundTrip(req)
	if err != nil {
		if e, _ := err.(net.Error); e != nil && e.Timeout() {
			// proxy.tpq.Dial = (&net.Dialer{Timeout: 2 * time.Second}).Dial
		} else {
			logg.E(err)
		}
		return maybeChinese
	}
	tryClose(resp.Body)
	ip2 := net.ParseIP(resp.Header.Get(dnsRespHeader)).To4()
	if ip2 == nil {
		return maybeChinese
	}

	proxy.DNSCache.Add(host, ip2.String())
	return isChineseIP(ip2.String())
}

func (proxy *ProxyClient) authSocks(conn net.Conn) bool {
	buf := make([]byte, 1+1+255+1+255)
	n, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		logg.E(socksReadErr, err)
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

func (proxy *ProxyClient) handleSocks(conn net.Conn) {
	logClose := func(args ...interface{}) {
		logg.E(args...)
		conn.Close()
	}

	buf := make([]byte, 2)
	if _, err := io.ReadAtLeast(conn, buf, 2); err != nil {
		logClose(socksReadErr, err)
		return
	} else if buf[0] != socksVersion5 {
		logClose(socksVersionErr)
		return
	}

	numMethods := int(buf[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadAtLeast(conn, methods, numMethods); err != nil {
		logClose(socksReadErr, err)
		return
	}

	if proxy.UserAuth != "" {
		conn.Write([]byte{socksVersion5, 0x02}) // username & password auth

		if !proxy.authSocks(conn) {
			conn.Write([]byte{1, 1})
			logClose("invalid auth data from: ", conn.RemoteAddr)
			return
		}

		// auth success
		conn.Write([]byte{1, 0})
	} else {
		conn.Write([]byte{socksVersion5, 0})
	}
	// handshake over
	// tunneling start
	method, addr, ok := parseDstFrom(conn, nil, false)
	if !ok {
		conn.Close()
		return
	}

	host := addr.String()
	switch method {
	case 1:
		if proxy.canDirectConnect(host) {
			logg.D("SOCKS ", host)
			proxy.dialHostAndBridge(conn, host, okSOCKS)
		} else if proxy.Policy.IsSet(PolicyWebSocket) {
			logg.D("WS^ ", host)
			proxy.dialUpstreamAndBridgeWS(conn, host, okSOCKS)
		} else {
			logg.D("SOCKS^ ", host)
			proxy.dialUpstreamAndBridge(conn, host, okSOCKS)
		}
	case 3:
		if proxy.UDPRelayPort == 0 {
			logClose("use command -udp to enable UDP relay")
		}

		relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
		if err != nil {
			logClose("cannot create UDP relay server: ", err)
			return
		}

		// prepare the response to answer the client
		response, port := make([]byte, len(okSOCKS)), relay.LocalAddr().(*net.UDPAddr).Port
		copy(response, okSOCKS)
		binary.BigEndian.PutUint16(response[8:], uint16(port))
		conn.Write(response)
		logg.D("UDP relay listening port: ", port)

		for {
			buf := make([]byte, 2048)
			n, src, err := relay.ReadFrom(buf)
			if err != nil {
				break
			}

			go proxy.handleUDPtoTCP(buf[:n], relay, conn, src)
		}
	default:
		logClose("do not support TCP bind")
	}
}

func (proxy *ProxyClient) UpdateKey(newKey string) {
	proxy.Cipher.Init(newKey)
	proxy.rkeyHeader = "X-" + proxy.Cipher.Alias
}

func (proxy *ProxyClient) Start() error {
	return http.Serve(proxy.Listener, proxy)
}

func NewClient(localaddr string, config *ClientConfig) *ProxyClient {
	var mux net.Listener
	var err error

	upURL, err := url.Parse("http://" + config.Upstream)
	if err != nil {
		logg.F(err)
		return nil
	}

	proxyURL := http.ProxyURL(upURL)
	proxy := &ProxyClient{
		pool: tcpmux.NewDialer(config.Upstream, config.Mux),

		tp:  &http.Transport{TLSClientConfig: tlsSkip, Proxy: proxyURL},
		tpd: &http.Transport{TLSClientConfig: tlsSkip},
		tpq: &http.Transport{TLSClientConfig: tlsSkip, Proxy: proxyURL, ResponseHeaderTimeout: timeoutOp, Dial: (&net.Dialer{Timeout: timeoutDial}).Dial},

		dummies:    lru.NewCache(len(dummyHeaders)),
		rkeyHeader: "X-" + config.Cipher.Alias,

		ClientConfig: config,
	}

	tcpmux.Version = config.Cipher.Alias[0] | 0x80

	if proxy.Connect2 != "" || proxy.Mux != 0 {
		proxy.tp.Proxy, proxy.tpq.Proxy = nil, nil
		proxy.tpq.Dial = func(network, address string) (net.Conn, error) {
			return proxy.dialUpstream()
		}
		proxy.tp.Dial = proxy.tpq.Dial
	}

	if config.Policy.IsSet(PolicyAggrClosing) && config.Policy.IsSet(PolicyManInTheMiddle) {
		// plus other fds, we should have a number smaller than 100
		proxy.tp.MaxIdleConns = 30
		proxy.tpd.MaxIdleConns = 30
		proxy.tpq.MaxIdleConns = 30
	}

	if proxy.UDPRelayCoconn <= 0 {
		proxy.UDPRelayCoconn = 1
	}

	if port, lerr := strconv.Atoi(localaddr); lerr == nil {
		mux, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv6zero, Port: port})
		localaddr = "127.0.0.1:" + localaddr
	} else {
		mux, err = net.Listen("tcp", localaddr)
		if localaddr[0] == ':' {
			localaddr = "127.0.0.1" + localaddr
		}
	}

	if err != nil {
		logg.F(err)
		return nil
	}

	proxy.Listener = &listenerWrapper{Listener: mux, proxy: proxy, obpool: NewOneBytePool(1024), retry24: proxy.Policy.IsSet(PolicyAggrClosing)}
	proxy.Localaddr = localaddr

	return proxy
}
