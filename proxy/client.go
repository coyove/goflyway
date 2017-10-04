package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/pkg/lru"

	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
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
	DisableConsole bool
	UserAuth       string
	DNSCacheSize   int

	UDPRelayPort   int
	UDPRelayCoconn int

	*GCipher
}

type ProxyClient struct {
	*ClientConfig

	tp      *http.Transport
	tpd     *http.Transport
	dummies *lru.Cache
	udp     struct {
		upstream struct {
			sync.Mutex
			conns map[string]net.Conn
		}
	}

	rkeyHeader string

	DNSCache  *lru.Cache
	Nickname  string
	Localaddr string
	Listener  *listenerWrapper
}

func (proxy *ProxyClient) dialUpstream() net.Conn {
	upstreamConn, err := net.Dial("tcp", proxy.Upstream)
	if err != nil {
		logg.E(err)
		return nil
	}

	return upstreamConn
}

func (proxy *ProxyClient) dialUpstreamAndBridge(downstreamConn net.Conn, host, auth string, options int) {
	upstreamConn := proxy.dialUpstream()
	if upstreamConn == nil {
		return
	}

	rkey, rkeybuf := proxy.GCipher.RandomIV()

	if (options & DO_SOCKS5) != 0 {
		host = EncryptHost(proxy.GCipher, host, HOST_SOCKS_CONNECT)
	} else {
		host = EncryptHost(proxy.GCipher, host, HOST_HTTP_CONNECT)
	}

	payload := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n", host)

	proxy.dummies.Info(func(k lru.Key, v interface{}, h int64) {
		if v.(string) != "" && proxy.GCipher.Rand.Intn(5) > 1 {
			payload += k.(string) + ": " + v.(string) + "\r\n"
		}
	})

	payload += fmt.Sprintf("%s: %s\r\n", proxy.rkeyHeader, rkey)

	if auth != "" {
		payload += fmt.Sprintf("%s: %s\r\n", AUTH_HEADER, proxy.GCipher.EncryptString(auth))
	}

	upstreamConn.Write([]byte(payload + "\r\n"))
	proxy.GCipher.Bridge(downstreamConn, upstreamConn, rkeybuf, nil)
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
		// response HTTP 200 OK to downstream, and it will not be xored in IOCopyCipher
		downstreamConn.Write(OK_HTTP)
	}

	proxy.GCipher.Bridge(downstreamConn, targetSiteConn, nil, nil)
}

func (proxy *ProxyClient) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logg.D(r.Method, " ", r.RequestURI)

	if strings.HasPrefix(r.RequestURI, "/?goflyway-console") && !proxy.DisableConsole {
		proxy.handleWebConsole(w, r)
		return
	}

	var auth string
	if proxy.UserAuth != "" {
		if auth = proxy.basicAuth(getAuth(r)); auth == "" {
			w.Header().Set("Proxy-Authenticate", "Basic realm=goflyway")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
	}

	if r.Method == "CONNECT" {
		// dig tunnel
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
			proxy.dialHostAndBridge(proxyClient, host, DO_HTTP)
		} else {
			proxy.dialUpstreamAndBridge(proxyClient, host, auth, DO_HTTP)
		}
	} else {
		// normal http requests
		if !r.URL.IsAbs() {
			http.Error(w, "request uri must be absolute", http.StatusInternalServerError)
			return
		}

		// borrow some headers from real browsings
		proxy.addToDummies(r)

		rUrl := r.URL.String()
		r.Header.Del("Proxy-Authorization")
		r.Header.Del("Proxy-Connection")

		var resp *http.Response
		var err error
		var rkeybuf []byte

		if proxy.canDirectConnect(auth, r.Host) {
			resp, err = proxy.tpd.RoundTrip(r)
		} else {
			// encrypt req to pass GFW
			rkeybuf = proxy.encryptRequest(r)

			if auth != "" {
				SafeAddHeader(r, AUTH_HEADER, auth)
			}

			resp, err = proxy.tp.RoundTrip(r)
		}

		if err != nil {
			logg.E("proxy pass: ", rUrl, ", ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if resp.StatusCode >= 400 {
			logg.D("[", resp.Status, "] - ", rUrl)
		}

		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)

		iocc := proxy.GCipher.WrapIO(w, resp.Body, rkeybuf, nil)
		iocc.Partial = false

		nr, err := iocc.DoCopy()
		tryClose(resp.Body)

		if err != nil {
			logg.E("io.wrap ", nr, "bytes: ", err)
		}
	}
}

func (proxy *ProxyClient) canDirectConnect(auth, host string) bool {
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

	// lookup at upstream
	upstreamConn := proxy.dialUpstream()
	if upstreamConn == nil {
		return maybeChinese
	}

	// only http 1.0 allows request without Host
	payload := fmt.Sprintf("GET /%s HTTP/1.0\r\n\r\n", proxy.GCipher.EncryptString(auth+"-"+host))

	upstreamConn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err = upstreamConn.Write([]byte(payload)); err != nil {
		if !err.(net.Error).Timeout() {
			logg.W("remote lookup: ", err)
		}
		return maybeChinese
	}

	upstreamConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	ipbuf, err := ioutil.ReadAll(upstreamConn)
	tryClose(upstreamConn)

	if err != nil {
		return maybeChinese
	}

	ip2 := net.IP(ipbuf).To4()
	if ip2 == nil {
		return maybeChinese
	}

	proxy.DNSCache.Add(host, ip2.String())
	return isChineseIP(ip2.String())
}

func (proxy *ProxyClient) authConnection(conn net.Conn) (string, bool) {
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

		if auth, ok = proxy.authConnection(conn); !ok {
			conn.Write([]byte{0x01, 0x01})
			conn.Close()
			return
		} else {
			// auth success
			conn.Write([]byte{0x1, 0})
		}
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
		logg.D("SOCKS ", host)
		if proxy.canDirectConnect(auth, host) {
			proxy.dialHostAndBridge(conn, host, DO_SOCKS5)
		} else {
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
			logg.D("udp relay listening port: ", port, ", sync conn: ", conn)

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

func (proxy *ProxyClient) PleaseUnlockMe() {
	upConn := proxy.dialUpstream()
	if upConn != nil {
		token := base64.StdEncoding.EncodeToString(proxy.Encrypt(genTrustedToken("unlock", proxy.GCipher)))

		payload := fmt.Sprintf("GET / HTTP/1.1\r\nHost: www.baidu.com\r\n%s: %s\r\n", proxy.rkeyHeader, token)
		if proxy.UserAuth != "" {
			payload += AUTH_HEADER + ": " + proxy.UserAuth + "\r\n"
		}

		upConn.SetWriteDeadline(time.Now().Add(time.Second))
		upConn.Write([]byte(payload + "\r\n"))
		upConn.Close()
	}
}

func (proxy *ProxyClient) UpdateKey(newKey string) {
	proxy.GCipher.KeyString = newKey
	proxy.GCipher.New()
	proxy.Nickname = genWord(proxy.GCipher)
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
	}

	word := genWord(config.GCipher)
	proxy := &ProxyClient{
		tp: &http.Transport{
			TLSClientConfig: tlsSkip,
			Proxy:           http.ProxyURL(upstreamUrl),
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
	}

	proxy.Listener = &listenerWrapper{Listener: mux, proxy: proxy, obpool: NewOneBytePool(1024)}
	proxy.Localaddr = localaddr
	return proxy
}
