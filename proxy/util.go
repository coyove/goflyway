package proxy

import (
	"github.com/coyove/goflyway/pkg/bitsop"
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/pkg/tlds"

	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/httputil"
	"net/url"
	"regexp"
	"strings"
)

const (
	SOCKS5_VERSION  = byte(0x05)
	SOCKS_TYPE_IPv4 = 1
	SOCKS_TYPE_Dm   = 3
	SOCKS_TYPE_IPv6 = 4

	DO_HTTP   = 0
	DO_SOCKS5 = 1

	HOST_HTTP_CONNECT  = byte(0x00)
	HOST_HTTP_FORWARD  = byte(0x01)
	HOST_SOCKS_CONNECT = byte(0x02)
	HOST_IPV6          = byte(0x04)

	AUTH_HEADER     = "X-Authorization"
	CANNOT_READ_BUF = "socks server: cannot read buffer: "
	NOT_SOCKS5      = "invalid socks version (socks5 only)"

	UDP_TIMEOUT = 30
	TCP_TIMEOUT = 60
)

var (
	OK_HTTP = []byte("HTTP/1.0 200 OK\r\n\r\n")
	//                       version, granted = 0, 0, ipv4, 0, 0, 0, 0, (port) 0, 0
	OK_SOCKS = []byte{SOCKS5_VERSION, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01}
	//                                 RSV | FRAG | ATYP |       DST.ADDR      | DST.PORT |
	UDP_REQUEST_HEADER  = []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	UDP_REQUEST_HEADER6 = []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	DUMMY_FIELDS = []string{"Accept-Language", "User-Agent", "Referer", "Cache-Control", "Accept-Encoding", "Connection"}

	tlsSkip = &tls.Config{InsecureSkipVerify: true}

	hostHeadExtract = regexp.MustCompile(`(\S+)\.com`)
	urlExtract      = regexp.MustCompile(`\?q=(\S+)$`)
	hasPort         = regexp.MustCompile(`:\d+$`)
	isHttpsSchema   = regexp.MustCompile(`^https:\/\/`)

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
	if proxy.DummyDomain == "" {
		req.Host = EncryptHost(proxy.GCipher, req.Host, HOST_HTTP_FORWARD)
	} else {
		req.Host = proxy.DummyDomain
	}

	req.URL, _ = url.Parse("http://" + req.Host + "/?q=" + proxy.GCipher.EncryptString(req.URL.String()))

	rkey, rkeybuf := proxy.GCipher.RandomIV()
	SafeAddHeader(req, proxy.rkeyHeader, rkey)

	cookies := []string{}
	for _, c := range req.Cookies() {
		c.Value = proxy.GCipher.EncryptString(c.Value)
		cookies = append(cookies, c.String())
	}

	req.Header.Set("Cookie", strings.Join(cookies, ";"))
	req.Header.Set("Origin", proxy.EncryptString(req.Header.Get("Origin"))+".com")
	req.Header.Set("Referer", proxy.EncryptString(req.Header.Get("Referer")))

	req.Body = ioutil.NopCloser((&IOReaderCipher{
		Src:    req.Body,
		Key:    rkeybuf,
		Cipher: proxy.GCipher,
	}).Init())

	return rkeybuf
}

func (proxy *ProxyUpstream) decryptRequest(req *http.Request, rkeybuf []byte) {
	if p := urlExtract.FindStringSubmatch(req.URL.String()); len(p) > 1 {
		req.URL, _ = url.Parse(proxy.GCipher.DecryptString(p[1]))
		req.RequestURI = req.URL.String()
	}

	if proxy.DummyDomain == "" {
		req.Host = proxy.decryptHost(proxy.GCipher, req.Host, HOST_HTTP_FORWARD)
	} else {
		req.Host = req.URL.Host
	}

	cookies := []string{}
	for _, c := range req.Cookies() {
		c.Value = proxy.GCipher.DecryptString(c.Value)
		cookies = append(cookies, c.String())
	}

	req.Header.Set("Cookie", strings.Join(cookies, ";"))
	req.Header.Set("Origin", proxy.DecryptString(strings.Replace(req.Header.Get("Origin"), ".com", "", -1)))
	req.Header.Set("Referer", proxy.DecryptString(req.Header.Get("Referer")))

	req.Body = ioutil.NopCloser((&IOReaderCipher{
		Src:    req.Body,
		Key:    rkeybuf,
		Cipher: proxy.GCipher,
	}).Init())
}

func copyHeaders(dst, src http.Header, gc *GCipher, enc bool) {
	for k := range dst {
		dst.Del(k)
	}

	for k, vs := range src {

		for _, v := range vs {
			cip := func(ei, di int) {
				if enc {
					v = v[:ei] + "=" + gc.EncryptString(v[ei+1:di]) + ";" + v[di+1:]
				} else {
					v = v[:ei] + "=" + gc.DecryptString(v[ei+1:di]) + ";" + v[di+1:]
				}
			}

			if k == "Set-Cookie" {
				ei, di := strings.Index(v, "="), strings.Index(v, ";")

				if ei > -1 && di > ei {
					cip(ei, di)
				}

				ei = strings.Index(v, "main=") // [Dd]omain
				if ei > -1 {
					for di = ei + 5; di < len(v); di++ {
						if v[di] == ';' {
							cip(ei+4, di)
							break
						}
					}
				}
			}

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
		logg.W("can't close: ", err)
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

func (proxy *ProxyUpstream) decryptHost(c *GCipher, text string, mark byte) string {
	host, m := proxy.tryDecryptHost(c, text)
	if m != mark {
		return ""
	} else {
		return host
	}
}

func (proxy *ProxyUpstream) tryDecryptHost(c *GCipher, text string) (h string, m byte) {
	host, port := splitHostPort(text)
	if host != "" && host == proxy.DummyDomain {
		return host, HOST_HTTP_FORWARD
	}

	parts := strings.Split(host, ".")

	for i := len(parts) - 1; i >= 0; i-- {
		if !tlds.TLDs[parts[i]] {
			bbuf, err := Base32Decode(parts[i])
			if err != nil {
				return text, 0xff
			}

			buf := c.Decrypt(bbuf)
			if len(buf) == 0 {
				return text, 0xff
			}

			mark := buf[0] >> 5
			if (mark & HOST_IPV6) != 0 {
				if ipv6 := net.IP(buf[1:]).To16(); ipv6 != nil {
					return "[" + ipv6.String() + "]" + port, mark - HOST_IPV6
				} else {
					return "", 0xff
				}
			}

			m, parts[i] = bitsop.Decompress(buf)
			if len(parts[i]) == 0 {
				return text, 0xff
			}

			break
		}
	}

	return strings.Join(parts, ".") + port, m
}

func isTrustedToken(mark string, rkeybuf []byte) bool {
	if string(rkeybuf[:len(mark)]) != mark {
		return false
	}

	b := rkeybuf[len(mark)]

	for i := len(mark) + 1; i < IV_LENGTH; i++ {
		if rkeybuf[i] >= b {
			return false
		}
	}

	return true
}

func genTrustedToken(mark string, gc *GCipher) []byte {
	ret := make([]byte, IV_LENGTH)
	copy(ret, []byte(mark))

	n := gc.Rand.Intn(128)
	ret[len(mark)] = byte(n)
	for i := len(mark) + 1; i < IV_LENGTH; i++ {
		ret[i] = byte(gc.Rand.Intn(n))
	}

	return ret
}

func Base32Encode(buf []byte) string {
	str := base32Encoding.EncodeToString(buf)
	idx := strings.Index(str, "=")

	if idx == -1 {
		return str
	}

	return str[:idx] //+ base32Replace[len(str)-idx-1]
}

func Base32Decode(text string) ([]byte, error) {
	const paddings = "======"

	if m := len(text) % 8; m > 1 {
		text = text + paddings[:8-m]
	}

	return base32Encoding.DecodeString(text)
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
