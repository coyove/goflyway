package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"

	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	SOCKS5_VERSION  = byte(0x05)
	SOCKS_TYPE_IPv4 = 1
	SOCKS_TYPE_Dm   = 3
	SOCKS_TYPE_IPv6 = 4

	DO_CONNECT  = 1
	DO_FORWARD  = 1 << 1
	DO_SOCKS5   = 1 << 2
	DO_OMIT_HDR = 1 << 3
	DO_RSV1     = 1 << 4
	DO_RSV2     = 1 << 5
	DO_RSV3     = 1 << 6
	DO_RSV4     = 1 << 7

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
	DUMMY_TLDS   = []string{".com", ".net", ".org"}

	tlsSkip = &tls.Config{InsecureSkipVerify: true}

	hostHeadExtract = regexp.MustCompile(`(\S+)\.com`)
	urlExtract      = regexp.MustCompile(`\?q=(\S+)$`)
	hasPort         = regexp.MustCompile(`:\d+$`)
	isHttpsSchema   = regexp.MustCompile(`^https:\/\/`)

	base32Encoding  = base32.NewEncoding("0123456789abcdefghiklmnoprstuwxy")
	base32Encoding2 = base32.NewEncoding("abcd&fghijklmnopqrstuvwxyz+-_./e")
)

func (proxy *ProxyClient) addToDummies(req *http.Request) {
	for _, field := range DUMMY_FIELDS {
		if x := req.Header.Get(field); x != "" {
			proxy.dummies.Add(field, x)
		}
	}
}

func (proxy *ProxyClient) genHost() string {
	if proxy.DummyDomain == "" {
		return genWord(proxy.GCipher, true) + DUMMY_TLDS[proxy.Rand.Intn(len(DUMMY_TLDS))]
	}

	return proxy.DummyDomain
}

func (proxy *ProxyClient) encryptAndTransport(req *http.Request, auth string) (*http.Response, []byte, error) {
	rkey, rkeybuf := proxy.GCipher.NewIV(DO_FORWARD, nil, auth)
	req.Header.Add(proxy.rkeyHeader, rkey)

	proxy.addToDummies(req)
	req.Host = proxy.genHost()
	req.URL, _ = url.Parse("http://" + req.Host + "/" + proxy.GCipher.EncryptCompress(req.URL.String(), rkeybuf...))

	cookies := []string{}
	for _, c := range req.Cookies() {
		c.Value = proxy.GCipher.EncryptString(c.Value, rkeybuf...)
		cookies = append(cookies, c.String())
	}

	req.Header.Set("Cookie", strings.Join(cookies, ";"))
	if origin := req.Header.Get("Origin"); origin != "" {
		req.Header.Set("Origin", proxy.EncryptString(origin, rkeybuf...)+".com")
	}

	if referer := req.Header.Get("Referer"); referer != "" {
		req.Header.Set("Referer", proxy.EncryptString(referer, rkeybuf...))
	}

	req.Body = ioutil.NopCloser((&IOReaderCipher{
		Src:    req.Body,
		Key:    rkeybuf,
		Cipher: proxy.GCipher,
	}).Init())

	resp, err := proxy.tp.RoundTrip(req)
	return resp, rkeybuf, err
}

func stripURI(uri string) string {
	if len(uri) < 1 {
		return uri
	}

	if uri[0] != '/' {
		idx := strings.Index(uri[8:], "/")
		if idx > -1 {
			uri = uri[idx+1+8:]
		} else {
			logg.W("unexpected uri: ", uri)
		}
	} else {
		uri = uri[1:]
	}

	return uri
}

func (proxy *ProxyUpstream) decryptRequest(req *http.Request, options byte, rkeybuf []byte) bool {
	var err error
	req.URL, err = url.Parse(proxy.GCipher.DecryptDecompress(stripURI(req.RequestURI), rkeybuf...))
	if err != nil {
		logg.E(err)
		return false
	}

	req.Host = req.URL.Host

	cookies := []string{}
	for _, c := range req.Cookies() {
		c.Value = proxy.GCipher.DecryptString(c.Value, rkeybuf...)
		cookies = append(cookies, c.String())
	}
	req.Header.Set("Cookie", strings.Join(cookies, ";"))

	if origin := req.Header.Get("Origin"); origin != "" {
		req.Header.Set("Origin", proxy.DecryptString(origin[:len(origin)-4], rkeybuf...))
	}

	if referer := req.Header.Get("Referer"); referer != "" {
		req.Header.Set("Referer", proxy.DecryptString(referer, rkeybuf...))
	}

	req.Body = ioutil.NopCloser((&IOReaderCipher{
		Src:    req.Body,
		Key:    rkeybuf,
		Cipher: proxy.GCipher,
	}).Init())

	return true
}

func copyHeaders(dst, src http.Header, gc *GCipher, enc bool, rkeybuf []byte) {
	for k := range dst {
		dst.Del(k)
	}

	for k, vs := range src {
	READ:
		for _, v := range vs {
			cip := func(ei, di int) {
				if enc {
					v = v[:ei] + "=" + gc.EncryptString(v[ei+1:di]) + ";" + v[di+1:]
				} else if rkeybuf != nil {
					v = v[:ei] + "=" + gc.DecryptString(v[ei+1:di]) + ";" + v[di+1:]
				}
			}

			switch strings.ToLower(k) {
			case "set-cookie":
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
			case "content-encoding":
				if enc {
					dst.Add("X-Content-Encoding", v)
					continue READ
				}
			case "x-content-encoding":
				if !enc {
					dst.Add("Content-Encoding", v)
					continue READ
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
	}

	return ""
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

func checksum1b(buf []byte) byte {
	s := int16(1)
	for _, b := range buf {
		s *= primes[b]
	}
	return byte(s>>12) + byte(s&0x00f0)
}

func isTrustedToken(mark string, rkeybuf []byte) int {
	logg.D("test token: ", rkeybuf)

	if string(rkeybuf[:len(mark)]) != mark {
		return 0
	}

	sent := int64(binary.BigEndian.Uint32(rkeybuf[12:]))
	if time.Now().Unix()-sent >= 10 {
		// token becomes invalid after 10 seconds
		return -1
	}

	return 1
}

func genTrustedToken(mark, auth string, gc *GCipher) string {
	buf := make([]byte, IV_LENGTH)

	copy(buf, []byte(mark))
	binary.BigEndian.PutUint32(buf[IV_LENGTH-4:], uint32(time.Now().Unix()))

	k, _ := gc.NewIV(0, buf, "")
	return k
}

func Base32Encode(buf []byte, alpha bool) string {
	var str string
	if alpha {
		str = base32Encoding.EncodeToString(buf)
	} else {
		str = base32Encoding2.EncodeToString(buf)
	}
	idx := strings.Index(str, "=")

	if idx == -1 {
		return str
	}

	return str[:idx]
}

func Base32Decode(text string, alpha bool) ([]byte, error) {
	const paddings = "======"

	if m := len(text) % 8; m > 1 {
		text = text + paddings[:8-m]
	}

	if alpha {
		return base32Encoding.DecodeString(text)
	}

	return base32Encoding2.DecodeString(text)
}

func genWord(gc *GCipher, random bool) string {
	const (
		vowels = "aeiou"
		cons   = "bcdfghlmnprst"
	)

	ret := make([]byte, 16)
	i, ln := 0, 0

	if random {
		ret[0] = (vowels + cons)[gc.Rand.Intn(18)]
		i, ln = 1, gc.Rand.Intn(6)+3
	} else {
		gc.Block.Encrypt(ret, gc.Key)
		ret[0] = (vowels + cons)[ret[0]/15]
		i, ln = 1, int(ret[15]/85)+6
	}

	link := func(prev string, this string, thisidx byte) {
		if strings.ContainsRune(prev, rune(ret[i-1])) {
			if random {
				ret[i] = this[gc.Rand.Intn(len(this))]
			} else {
				ret[i] = this[ret[i]/thisidx]
			}

			i++
		}
	}

	for i < ln {
		link(vowels, cons, 20)
		link(cons, vowels, 52)
		link(vowels, cons, 20)
		link(cons, vowels+"tr", 37)
	}

	if !random {
		ret[0] -= 32
	}

	return string(ret[:ln])
}
