package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/pkg/lru"

	"encoding/binary"
	"encoding/base64"
	"bytes"
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

var HTTP200 = []byte(" 200 ") // HTTP/x.x 200 xxxxxxxx
var DIAL_TIMEOUT = 5

func (proxy *ProxyClient) dialUpstream() (net.Conn, error) {
	o := time.Duration(DIAL_TIMEOUT) * time.Second

	if proxy.Connect2 == "" {
		upstreamConn, err := net.DialTimeout("tcp", proxy.Upstream, o)
		if err != nil {
			return nil, err
		}

		return upstreamConn, nil
	}

	connectConn, err := net.DialTimeout("tcp", proxy.Connect2, o)
	if err != nil {
		return nil, err
	}

	up, auth := proxy.Upstream, ""
	if proxy.Connect2Auth != "" {
		x := base64.StdEncoding.EncodeToString([]byte(proxy.Connect2Auth))
		auth = fmt.Sprintf("Proxy-Authorization: Basic %s\r\nAuthorization: Basic %s\r\n", x, x)
	}

	connect := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", up, up, auth)
	connectConn.SetWriteDeadline(time.Now().Add(o))
	_, err = connectConn.Write([]byte(connect))
	if err != nil {
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
		return nil, errors.New("connect2: malformed repsonse")
	}

	if !bytes.Contains(respbuf.Bytes(), HTTP200) {
		x := respbuf.String()
		if x = x[strings.Index(x, " ")+1:]; len(x) > 3 {
			x = x[:3]
		}
		
		return nil, errors.New("connect2: cannot connect to the https proxy (" + x + ")")
	}

	return connectConn, nil
}

func (proxy *ProxyClient) dialUpstreamAndBridge(downstreamConn net.Conn, host, auth string, options byte) net.Conn {
	upstreamConn, err := proxy.dialUpstream()
	if err != nil {
		logg.E(err)
		return nil
	}

	rkey, rkeybuf := proxy.Cipher.NewIV(options, nil, auth)
	payload := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\n", proxy.Cipher.EncryptCompress(host, rkeybuf...), proxy.genHost())

	payloads := make([]string, 0, len(DUMMY_FIELDS))
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
	proxy.Cipher.IO.Bridge(downstreamConn, upstreamConn, rkeybuf, IOConfig{Partial: proxy.Partial})

	return upstreamConn
}

func (proxy *ProxyClient) dialHostAndBridge(downstreamConn net.Conn, host string, options int) {
	targetSiteConn, err := net.Dial("tcp", host)
	if err != nil {
		logg.E(err)
		return
	}

	if (options & DO_SOCKS5) != 0 {
		downstreamConn.Write(OK_SOCKS)
	} else {
		downstreamConn.Write(OK_HTTP)
	}

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
			proxy.dialHostAndBridge(proxyClient, host, DO_CONNECT)
		} else if proxy.ManInTheMiddle {
			proxy.manInTheMiddle(proxyClient, host, auth)
		} else {
			logg.D("CONNECT^ ", r.RequestURI)
			proxy.dialUpstreamAndBridge(proxyClient, host, auth, DO_CONNECT)
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
			logg.E("copy ", nr, "bytes: ", err)
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
	rkey, _ := proxy.Cipher.NewIV(DO_DNS, []byte(host), auth)
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
		logg.E(CANNOT_READ_BUF, err)
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
		log_close(CANNOT_READ_BUF, err)
		return
	}

	if buf[0] != SOCKS5_VERSION {
		log_close(NOT_SOCKS5)
		return
	}

	numMethods := int(buf[1])
	methods := make([]byte, numMethods)
	if _, err = io.ReadAtLeast(conn, methods, numMethods); err != nil {
		log_close(CANNOT_READ_BUF, err)
		return
	}

	var (
		auth string
		ok   bool
	)

	if proxy.UserAuth != "" {
		conn.Write([]byte{SOCKS5_VERSION, 0x02}) // username & password auth

		if auth, ok = proxy.authSocks(conn); !ok {
			conn.Write([]byte{0x01, 0x01})
			conn.Close()
			return
		}

		// auth success
		conn.Write([]byte{0x1, 0})
	} else {
		conn.Write([]byte{SOCKS5_VERSION, 0})
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
			proxy.dialHostAndBridge(conn, host, DO_SOCKS5)
		} else {
			logg.D("SOCKS^ ", host)
			proxy.dialUpstreamAndBridge(conn, host, auth, DO_SOCKS5)
		}
	} else if method == 0x03 {
		if proxy.UDPRelayPort != 0 {
			relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
			if err != nil {
				log_close("udp relay server: ", err)
				return
			}

			response := []byte{SOCKS5_VERSION, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			port := relay.LocalAddr().(*net.UDPAddr).Port
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

		dummies:    lru.NewCache(len(DUMMY_FIELDS)),
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
