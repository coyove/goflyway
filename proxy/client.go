package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/pkg/lru"

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
	Upstream       string
	GlobalProxy    bool
	NoProxy        bool
	DisableConsole bool
	ManInTheMiddle bool
	Connect2       string
	Connect2Auth   string
	UserAuth       string
	DummyDomain    string
	DummyDomain2   string
	DNSCacheSize   int

	UDPRelayPort   int
	UDPRelayCoconn int

	*Cipher
}

type ProxyClient struct {
	*ClientConfig

	tp      *http.Transport // to upstream
	tpq     *http.Transport // to upstream used for dns query
	tpd     *http.Transport // to host directly
	dummies *lru.Cache
	udp     struct {
		sync.Mutex
		conns map[string]*udp_tcp_conn_t
		addrs map[net.Addr]bool
	}

	rkeyHeader string

	DNSCache  *lru.Cache
	Nickname  string
	Localaddr string
	Listener  *listenerWrapper
}

var HTTP200 = []byte(" 200 ")                      // HTTP/x.x 200 xxxxxxxx
var SOCKS5_HANDSHAKE = []byte{socksVersion5, 1, 0} // we currently support "no auth" only
var DIAL_TIMEOUT = time.Duration(5) * time.Second
var CONNECT_OP_TIMEOUT = time.Duration(20) * time.Second

func (proxy *ProxyClient) dialUpstream() (net.Conn, error) {
	if proxy.Connect2 == "" {
		upstreamConn, err := net.DialTimeout("tcp", proxy.Upstream, DIAL_TIMEOUT)
		if err != nil {
			return nil, err
		}

		return upstreamConn, nil
	}

	connectConn, err := net.DialTimeout("tcp", proxy.Connect2, DIAL_TIMEOUT)
	if err != nil {
		return nil, err
	}

	up, auth := proxy.Upstream, ""
	if proxy.Connect2Auth != "" {
		// if proxy.Connect2Auth == "socks5" {
		// 	connectConn.SetWriteDeadline(time.Now().Add(CONNECT_OP_TIMEOUT))
		// 	if _, err = connectConn.Write(SOCKS5_HANDSHAKE); err != nil {
		// 		connectConn.Close()
		// 		return nil, err
		// 	}

		// 	buf := make([]byte, 263)
		// 	connectConn.SetReadDeadline(time.Now().Add(CONNECT_OP_TIMEOUT))
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

		// 	connectConn.SetWriteDeadline(time.Now().Add(CONNECT_OP_TIMEOUT))
		// 	if _, err = connectConn.Write(payload); err != nil {
		// 		connectConn.Close()
		// 		return nil, err
		// 	}

		// 	connectConn.SetReadDeadline(time.Now().Add(CONNECT_OP_TIMEOUT))
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

		// 	connectConn.SetReadDeadline(time.Now().Add(CONNECT_OP_TIMEOUT))
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
	connectConn.SetWriteDeadline(time.Now().Add(CONNECT_OP_TIMEOUT))
	_, err = connectConn.Write([]byte(connect))
	if err != nil {
		connectConn.Close()
		return nil, err
	}

	buf, respbuf := make([]byte, 1), &bytes.Buffer{}
	eoh, eidx, found := "\r\n\r\n", 0, false

	for {
		n, err := connectConn.Read(buf)
		if n == 1 {
			respbuf.WriteByte(buf[0])
		}

		if buf[0] == eoh[eidx] {
			if eidx++; eidx == 4 {
				// we are meeting \r\n\r\n, the end
				found = true
				break
			}
		}

		if err != nil {
			break
		}
	}

	if !found {
		connectConn.Close()
		return nil, errors.New("connect2: malformed repsonse")
	}

	if !bytes.Contains(respbuf.Bytes(), HTTP200) {
		x := respbuf.String()
		if x = x[strings.Index(x, " ")+1:]; len(x) > 3 {
			x = x[:3]
		}

		connectConn.Close()
		return nil, errors.New("connect2: cannot connect to the HTTPS proxy (" + x + ")")
	}

	return connectConn, nil
}

func (proxy *ProxyClient) dialUpstreamAndBridge(downstreamConn net.Conn, host, auth string, resp []byte) net.Conn {
	upstreamConn, err := proxy.dialUpstream()
	if err != nil {
		logg.E(err)
		return nil
	}

	rkey, rkeybuf := proxy.Cipher.NewIV(doConnect, nil, auth)
	payload := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\n", proxy.Cipher.EncryptCompress(host, rkeybuf...), proxy.genHost())

	payloads := make([]string, 0, len(dummyHeaders))
	proxy.dummies.Info(func(k lru.Key, v interface{}, h int64) {
		if v != nil && v.(string) != "" && proxy.Cipher.Rand.Intn(5) > 1 {
			payloads = append(payloads, k.(string)+": "+v.(string)+"\r\n")
		}
	})

	payloads = append(payloads, fmt.Sprintf("%s: %s\r\n", proxy.rkeyHeader, rkey))

	for _, i := range proxy.Rand.Perm(len(payloads)) {
		payload += payloads[i]
	}

	upstreamConn.Write([]byte(payload + "\r\n"))
	buf := make([]byte, 96)
	if nr, er := io.ReadAtLeast(upstreamConn, buf, len(buf)); er != nil || nr != len(buf) || !bytes.Equal(buf[:15], okHTTP[:15]) {
		logg.E("failed to read response: ", err, " ", nr, " bytes: ", buf)
		upstreamConn.Close()
		downstreamConn.Close()
		return nil
	}

	downstreamConn.Write(resp)
	proxy.Cipher.IO.Bridge(downstreamConn, upstreamConn, rkeybuf, IOConfig{Partial: proxy.Partial})

	return upstreamConn
}

func (proxy *ProxyClient) dialHostAndBridge(downstreamConn net.Conn, host string, resp []byte) {
	targetSiteConn, err := net.Dial("tcp", host)
	if err != nil {
		logg.E(err)
		return
	}

	downstreamConn.Write(resp)
	proxy.Cipher.IO.Bridge(downstreamConn, targetSiteConn, nil, IOConfig{})
}

func (proxy *ProxyClient) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.RequestURI, "/?goflyway-console") && !proxy.DisableConsole {
		proxy.handleWebConsole(w, r)
		return
	}

	var auth string
	if proxy.UserAuth != "" {
		if auth = proxy.basicAuth(r.Header.Get("Proxy-Authorization")); auth == "" {
			w.Header().Set("Proxy-Authenticate", "Basic realm=goflyway")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
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

		if proxy.canDirectConnect(auth, host) {
			logg.D("CONNECT ", r.RequestURI)
			proxy.dialHostAndBridge(proxyClient, host, okHTTP)
		} else if proxy.ManInTheMiddle {
			proxy.manInTheMiddle(proxyClient, host, auth)
		} else {
			logg.D("CONNECT^ ", r.RequestURI)
			proxy.dialUpstreamAndBridge(proxyClient, host, auth, okHTTP)
		}
	} else {
		// normal http requests
		if !r.URL.IsAbs() {
			http.Error(w, "request uri must be absolute", http.StatusInternalServerError)
			return
		}

		// borrow some headers from real browsings
		proxy.addToDummies(r)

		r.URL.Host = r.Host
		rUrl := r.URL.String()
		r.Header.Del("Proxy-Authorization")
		r.Header.Del("Proxy-Connection")

		var resp *http.Response
		var err error
		var rkeybuf []byte

		if proxy.canDirectConnect(auth, r.Host) {
			logg.D(r.Method, " ", rUrl)
			resp, err = proxy.tpd.RoundTrip(r)
		} else {
			logg.D(r.Method, "^ ", rUrl)
			resp, rkeybuf, err = proxy.encryptAndTransport(r, auth)
		}

		if err != nil {
			logg.E("proxy pass: ", rUrl, ", ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if resp.StatusCode >= 400 {
			logg.D("[", resp.Status, "] - ", rUrl)
		}

		copyHeaders(w.Header(), resp.Header, proxy.Cipher, false, rkeybuf)
		w.WriteHeader(resp.StatusCode)

		if nr, err := proxy.Cipher.IO.Copy(w, resp.Body, rkeybuf, IOConfig{Partial: false}); err != nil {
			logg.E("copy ", nr, " bytes: ", err)
		}

		tryClose(resp.Body)
	}
}

func (proxy *ProxyClient) canDirectConnect(auth, host string) bool {
	if proxy.NoProxy {
		return true
	}

	host, _ = splitHostPort(host)

	isChineseIP := func(ip string) bool {
		if proxy.GlobalProxy {
			return false
		}

		return lookup.IsChineseIP(ip)
	}

	if lookup.IsChineseWebsite(host) {
		return !proxy.GlobalProxy
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

	// if it is a foreign ip, just return false
	// but if it is a chinese ip, we withhold and query the upstream to double check
	maybeChinese := isChineseIP(ip)
	if !maybeChinese {
		proxy.DNSCache.Add(host, ip)
		return false
	}

	req, err := http.NewRequest("GET", "http://"+proxy.genHost(), nil)
	if err != nil {
		logg.E(err)
		return maybeChinese
	}
	rkey, _ := proxy.Cipher.NewIV(doDNS, []byte(host), auth)
	req.Header.Add(proxy.rkeyHeader, rkey)

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
	ip2 := net.ParseIP(resp.Header.Get("ETag")).To4()
	if ip2 == nil {
		return maybeChinese
	}

	proxy.DNSCache.Add(host, ip2.String())
	return isChineseIP(ip2.String())
}

func (proxy *ProxyClient) authSocks(conn net.Conn) (string, bool) {
	buf := make([]byte, 1+1+255+1+255)
	var n int
	var err error

	if n, err = io.ReadAtLeast(conn, buf, 2); err != nil {
		logg.E(socksReadErr, err)
		return "", false
	}

	if buf[0] != 0x01 {
		return "", false
	}

	username_len := int(buf[1])
	if 2+username_len+1 > n {
		return "", false
	}

	username := string(buf[2 : 2+username_len])
	password_len := int(buf[2+username_len])

	if 2+username_len+1+password_len > n {
		return "", false
	}

	password := string(buf[2+username_len+1 : 2+username_len+1+password_len])
	pu := username + ":" + password
	return pu, proxy.UserAuth == pu
}

func (proxy *ProxyClient) handleSocks(conn net.Conn) {
	var err error
	log_close := func(args ...interface{}) {
		logg.E(args...)
		conn.Close()
	}

	buf := make([]byte, 2)
	if _, err = io.ReadAtLeast(conn, buf, 2); err != nil {
		log_close(socksReadErr, err)
		return
	}

	if buf[0] != socksVersion5 {
		log_close(socksVersionErr)
		return
	}

	numMethods := int(buf[1])
	methods := make([]byte, numMethods)
	if _, err = io.ReadAtLeast(conn, methods, numMethods); err != nil {
		log_close(socksReadErr, err)
		return
	}

	var (
		auth string
		ok   bool
	)

	if proxy.UserAuth != "" {
		conn.Write([]byte{socksVersion5, 0x02}) // username & password auth

		if auth, ok = proxy.authSocks(conn); !ok {
			conn.Write([]byte{0x01, 0x01})
			conn.Close()
			return
		}

		// auth success
		conn.Write([]byte{0x1, 0})
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

	if method == 0x01 {
		if proxy.canDirectConnect(auth, host) {
			logg.D("SOCKS ", host)
			proxy.dialHostAndBridge(conn, host, okSOCKS)
		} else {
			logg.D("SOCKS^ ", host)
			proxy.dialUpstreamAndBridge(conn, host, auth, okSOCKS)
		}
	} else if method == 0x03 {
		if proxy.UDPRelayPort != 0 {
			relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
			if err != nil {
				log_close("udp relay server: ", err)
				return
			}

			response, port := make([]byte, len(okSOCKS)), relay.LocalAddr().(*net.UDPAddr).Port
			copy(response, okSOCKS)
			binary.BigEndian.PutUint16(response[8:], uint16(port))

			conn.Write(response)
			logg.D("udp relay listening port: ", port)

			for {
				buf := make([]byte, 2048)
				n, src, err := relay.ReadFrom(buf)
				if err != nil {
					break
				}

				go proxy.handleUDPtoTCP(buf[:n], relay, conn, auth, src)
			}
		} else {
			log_close("use command -udp to enable udp relay")
		}
	}
}

func (proxy *ProxyClient) UpdateKey(newKey string) {
	proxy.Cipher.KeyString = newKey
	proxy.Cipher.New()
	proxy.Nickname = genWord(proxy.Cipher, false)
	proxy.rkeyHeader = "X-" + proxy.Nickname
}

func (proxy *ProxyClient) Start() error {
	return http.Serve(proxy.Listener, proxy)
}

func NewClient(localaddr string, config *ClientConfig) *ProxyClient {
	var mux net.Listener
	var err error

	upstreamUrl, err := url.Parse("http://" + config.Upstream)
	if err != nil {
		logg.F(err)
		return nil
	}

	word := genWord(config.Cipher, false)
	proxy := &ProxyClient{
		tp: &http.Transport{
			TLSClientConfig: tlsSkip,
			Proxy:           http.ProxyURL(upstreamUrl),
		},

		tpq: &http.Transport{
			TLSClientConfig:       tlsSkip,
			Proxy:                 http.ProxyURL(upstreamUrl),
			TLSHandshakeTimeout:   2 * time.Second,
			ResponseHeaderTimeout: 2 * time.Second,
			Dial: (&net.Dialer{Timeout: time.Duration(DIAL_TIMEOUT) * time.Second}).Dial,
		},

		tpd: &http.Transport{
			TLSClientConfig: tlsSkip,
		},

		dummies:    lru.NewCache(len(dummyHeaders)),
		DNSCache:   lru.NewCache(config.DNSCacheSize),
		rkeyHeader: "X-" + word,
		Nickname:   word,

		ClientConfig: config,
	}

	if proxy.Connect2 != "" {
		proxy.tp.Proxy, proxy.tpq.Proxy = nil, nil
		proxy.tpq.Dial = func(network, address string) (net.Conn, error) {
			return proxy.dialUpstream()
		}
		proxy.tp.Dial = proxy.tpq.Dial
	}

	if proxy.UDPRelayCoconn <= 0 {
		proxy.UDPRelayCoconn = 1
	}

	if port, lerr := strconv.Atoi(localaddr); lerr == nil {
		mux, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv6zero, Port: port})
		localaddr = "localhost:" + localaddr
	} else {
		mux, err = net.Listen("tcp", localaddr)
	}

	if err != nil {
		logg.F(err)
		return nil
	}

	proxy.Listener = &listenerWrapper{Listener: mux, proxy: proxy, obpool: NewOneBytePool(1024)}
	proxy.Localaddr = localaddr

	return proxy
}
