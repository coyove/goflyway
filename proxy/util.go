package proxy

import (
	"github.com/coyove/goflyway/pkg/bitsop"
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/pkg/tlds"

	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	socks5Version = byte(0x05)
	socksTypeIPv4 = 1
	socksTypeDm   = 3
	socksTypeIPv6 = 4

	DO_NOTHING    = 0
	DO_THROTTLING = 1
	DO_SOCKS5     = 1 << 16

	HOST_HTTP_CONNECT  = byte(0x00)
	HOST_HTTP_FORWARD  = byte(0x01)
	HOST_SOCKS_CONNECT = byte(0x02)
	HOST_DOMAIN_LOOKUP = byte(0x03)
	HOST_IPV6          = byte(0x04)

	DNS_HEADER      = "X-Host-Lookup"
	AUTH_HEADER     = "X-Authorization"
	CANNOT_READ_BUF = "[SOCKS] cannot read buffer - "
	NOT_SOCKS5      = "[SOCKS] invalid socks version (socks5 only)"

	UDP_TIMEOUT = 30
	TCP_TIMEOUT = 60
)

var (
	OK_HTTP = []byte("HTTP/1.0 200 OK\r\n\r\n")
	// version, granted = 0, 0, ipv4, 0, 0, 0, 0, (port) 0, 0
	OK_SOCKS = []byte{socks5Version, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01}
	//                                 RSV | FRAG | ATYP |       DST.ADDR      | DST.PORT |
	UDP_REQUEST_HEADER  = []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	UDP_REQUEST_HEADER6 = []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	DUMMY_FIELDS = []string{"Accept-Language", "User-Agent", "Referer", "Cache-Control", "Accept-Encoding", "Connection"}

	tlsSkip = &tls.Config{InsecureSkipVerify: true}

	hostHeadExtract = regexp.MustCompile(`(\S+)\.com`)
	urlExtract      = regexp.MustCompile(`\?q=(\S+)$`)
	hasPort         = regexp.MustCompile(`:\d+$`)

	base32Encoding = base32.NewEncoding("0123456789abcdefghiklmnoprstuwxy")
)

func SafeAddHeader(req *http.Request, k, v string) {
	if orig := req.Header.Get(k); orig != "" {
		req.Header.Set(k, v+" "+orig)
	} else {
		req.Header.Add(k, v)
	}
}

func SafeGetHeader(req *http.Request, k string) string {
	v := req.Header.Get(k)
	if s := strings.Index(v, " "); s > 0 {
		req.Header.Set(k, v[s+1:])
		v = v[:s]
	}

	return v
}

func (proxy *ProxyClient) addToDummies(req *http.Request) {
	for _, field := range DUMMY_FIELDS {
		if x := req.Header.Get(field); x != "" {
			proxy.dummies.Add(field, x)
		}
	}
}

func (proxy *ProxyClient) encryptRequest(req *http.Request) []byte {
	req.Host = EncryptHost(proxy.GCipher, req.Host, HOST_HTTP_FORWARD)
	req.URL, _ = url.Parse("http://" + req.Host + "/?q=" + proxy.GCipher.EncryptString(req.URL.String()))

	rkey, rkeybuf := proxy.GCipher.RandomIV()
	SafeAddHeader(req, proxy.rkeyHeader, rkey)

	proxy.addToDummies(req)

	for _, c := range req.Cookies() {
		c.Value = proxy.GCipher.EncryptString(c.Value)
	}

	req.Body = ioutil.NopCloser((&IOReaderCipher{
		Src:    req.Body,
		Key:    rkeybuf,
		Cipher: proxy.GCipher,
	}).Init())

	return rkeybuf
}

func (proxy *ProxyUpstream) decryptRequest(req *http.Request, rkeybuf []byte) {
	req.Host = DecryptHost(proxy.GCipher, req.Host, HOST_HTTP_FORWARD)

	if p := urlExtract.FindStringSubmatch(req.URL.String()); len(p) > 1 {
		req.URL, _ = url.Parse(proxy.GCipher.DecryptString(p[1]))
		req.RequestURI = req.URL.String()
	}

	for _, c := range req.Cookies() {
		c.Value = proxy.GCipher.DecryptString(c.Value)
	}

	req.Body = ioutil.NopCloser((&IOReaderCipher{
		Src:    req.Body,
		Key:    rkeybuf,
		Cipher: proxy.GCipher,
	}).Init())
}

func copyHeaders(dst, src http.Header) {
	for k := range dst {
		dst.Del(k)
	}
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func (proxy *ProxyClient) basicAuth(token string) string {
	parts := strings.Split(token, " ")
	if len(parts) != 2 {
		return ""
	}

	pa, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return ""
	}

	if s := string(pa); s == proxy.UserAuth {
		return s
	} else {
		return ""
	}
}

func getAuth(r *http.Request) string {
	pa := r.Header.Get("Proxy-Authorization")
	if pa == "" {
		pa = r.Header.Get(AUTH_HEADER)
	}

	return pa
}

func tryClose(b io.ReadCloser) {
	if err := b.Close(); err != nil {
		logg.W("can't close response body - ", err)
	}
}

func splitHostPort(host string) (string, string) {
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		idx2 := strings.LastIndex(host, "]")
		if idx2 < idx {
			return strings.ToLower(host[:idx]), host[idx:]
		}

		// ipv6 without port
	}

	return strings.ToLower(host), ""
}

func EncryptHost(c *GCipher, text string, mark byte) string {
	host, port := splitHostPort(text)

	enc := func(in string) string {
		return Base32Encode(c.Encrypt(bitsop.Compress(mark, in)))
	}

	if lookup.IPAddressToInteger(host) != 0 {
		return enc(host) + port
	}

	if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
		ip := net.ParseIP(host[1 : len(host)-1])
		if ip != nil {
			buf := append([]byte{(mark | HOST_IPV6) << 5}, ip...)
			return Base32Encode(c.Encrypt(buf)) + port
		}
	}

	parts := strings.Split(host, ".")
	flag := false
	for i := len(parts) - 1; i >= 0; i-- {
		if !tlds.TLDs[parts[i]] {
			parts[i] = enc(parts[i])
			flag = true
			break
		}
	}

	if flag {
		return strings.Join(parts, ".") + port
	}

	return enc(host) + port
}

func DecryptHost(c *GCipher, text string, mark byte) string {
	host, m := TryDecryptHost(c, text)
	if m != mark {
		return ""
	} else {
		return host
	}
}

func TryDecryptHost(c *GCipher, text string) (h string, m byte) {
	host, port := splitHostPort(text)
	parts := strings.Split(host, ".")

	for i := len(parts) - 1; i >= 0; i-- {
		if !tlds.TLDs[parts[i]] {
			buf := c.Decrypt(Base32Decode(parts[i]))
			if len(buf) == 0 {
				return text, 0
			}

			mark := buf[0] >> 5
			if (mark & HOST_IPV6) != 0 {
				if ipv6 := net.IP(buf[1:]).To16(); ipv6 != nil {
					return "[" + ipv6.String() + "]" + port, mark - HOST_IPV6
				} else {
					return "", 0
				}
			}

			m, parts[i] = bitsop.Decompress(buf)
			if len(parts[i]) == 0 {
				return text, 0
			}

			break
		}
	}

	return strings.Join(parts, ".") + port, m
}

func Base32Encode(buf []byte) string {
	str := base32Encoding.EncodeToString(buf)
	idx := strings.Index(str, "=")

	if idx == -1 {
		return str
	}

	return str[:idx] //+ base32Replace[len(str)-idx-1]
}

func Base32Decode(text string) []byte {
	const paddings = "======"

	if m := len(text) % 8; m > 1 {
		text = text + paddings[:8-m]
	}

	buf, err := base32Encoding.DecodeString(text)
	if err != nil {
		return []byte{}
	}

	return buf
}

func genWord(gc *GCipher) string {
	const (
		vowels = "aeiou"
		cons   = "bcdfghlmnprst"
	)

	ret := make([]byte, 16)
	gc.Block.Encrypt(ret, gc.Key)
	ret[0] = (vowels + cons)[ret[0]/15]
	i, ln := 1, int(ret[15]/85)+6

	link := func(prev string, this string, thisidx byte) {
		if strings.ContainsRune(prev, rune(ret[i-1])) {
			ret[i] = this[ret[i]/thisidx]
			i++
		}
	}

	for i < ln {
		link(vowels, cons, 20)
		link(cons, vowels, 52)
		link(vowels, cons, 20)
		link(cons, vowels+"tr", 37)
	}

	ret[0] -= 32
	return string(ret[:ln])
}

type addr_t struct {
	ip   net.IP
	host string
	port int
	size int
}

func (a *addr_t) String() string {
	return a.HostString() + ":" + strconv.Itoa(a.port)
}

func (a *addr_t) HostString() string {
	if a.ip != nil {
		return a.ip.String()
	} else {
		return a.host
	}
}

func (a *addr_t) IP() net.IP {
	if a.ip != nil {
		return a.ip
	}

	ip, err := net.ResolveIPAddr("ip", a.host)
	if err != nil {
		logg.E("[ADT] ", err)
		return nil
	}

	return ip.IP
}

func (a *addr_t) IsAllZeros() bool {
	if a.ip != nil {
		return a.ip.IsUnspecified() && a.port == 0
	}

	return false
}

func ParseDstFrom(conn net.Conn, typeBuf []byte, omitCheck bool) (byte, *addr_t, bool) {
	var err error
	var n int

	if typeBuf == nil {
		typeBuf, n = make([]byte, 256+3+1+1+2), 0
		// conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		if n, err = io.ReadAtLeast(conn, typeBuf, 3+1+net.IPv4len+2); err != nil {
			logg.E(CANNOT_READ_BUF, err)
			return 0x0, nil, false
		}
	}

	if typeBuf[0] != socks5Version && !omitCheck {
		logg.E(NOT_SOCKS5)
		return 0x0, nil, false
	}

	if typeBuf[1] != 0x01 && typeBuf[1] != 0x03 && !omitCheck { // 0x01: establish a TCP/IP stream connection
		logg.E("[SOCKS] invalid command: ", typeBuf[1])
		return 0x0, nil, false
	}

	addr := &addr_t{}
	switch typeBuf[3] {
	case socksTypeIPv4:
		addr.size = 3 + 1 + net.IPv4len + 2
	case socksTypeIPv6:
		addr.size = 3 + 1 + net.IPv6len + 2
	case socksTypeDm:
		addr.size = 3 + 1 + 1 + int(typeBuf[4]) + 2
	default:
		logg.E("[SOCKS] invalid type")
		return 0x0, nil, false
	}

	if conn != nil {
		if _, err = io.ReadFull(conn, typeBuf[n:addr.size]); err != nil {
			logg.E(CANNOT_READ_BUF, err)
			return 0x0, nil, false
		}
	} else {
		if len(typeBuf) < addr.size {
			logg.E(CANNOT_READ_BUF, err)
			return 0x0, nil, false
		}
	}

	rawaddr := typeBuf[3 : addr.size-2]
	addr.port = int(binary.BigEndian.Uint16(typeBuf[addr.size-2 : addr.size]))

	switch typeBuf[3] {
	case socksTypeIPv4:
		addr.ip = net.IP(rawaddr[1:])
	case socksTypeIPv6:
		addr.ip = net.IP(rawaddr[1:])
	default:
		addr.host = string(rawaddr[2:])
	}

	return typeBuf[1], addr, true
}
