package proxy

import (
	"github.com/coyove/goflyway/pkg/bitsop"
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
	DUMMY_TLDS   = []string{".com", ".net", ".org"}

	tlsSkip = &tls.Config{InsecureSkipVerify: true}

	hostHeadExtract = regexp.MustCompile(`(\S+)\.com`)
	urlExtract      = regexp.MustCompile(`\?q=(\S+)$`)
	hasPort         = regexp.MustCompile(`:\d+$`)
	isHttpsSchema   = regexp.MustCompile(`^https:\/\/`)

	base32Encoding  = base32.NewEncoding("0123456789abcdefghiklmnoprstuwxy")
	base32Encoding2 = base32.NewEncoding("abcd&fghijklmnopqrstuvwxyz+-_./e")
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

func (proxy *ProxyClient) genHost() string {
	if proxy.DummyDomain == "" {
		return genWord(proxy.GCipher, true) + DUMMY_TLDS[proxy.Rand.Intn(len(DUMMY_TLDS))]
	}

	return proxy.DummyDomain
}

func (proxy *ProxyClient) encryptRequest(req *http.Request) []byte {
	opt := byte(DO_FORWARD)
	rkey, rkeybuf := proxy.GCipher.RandomIV(opt)
	SafeAddHeader(req, proxy.rkeyHeader, rkey)

	proxy.addToDummies(req)
	req.Host = proxy.genHost()
	req.URL, _ = url.Parse("http://" + req.Host + "/" + compressAndEncrypt(req.URL.String(), proxy.GCipher, rkeybuf))

	cookies := []string{}
	for _, c := range req.Cookies() {
		c.Value = proxy.GCipher.EncryptString(c.Value)
		cookies = append(cookies, c.String())
	}

	req.Header.Set("Cookie", strings.Join(cookies, ";"))
	if req.Header.Get("Origin") != "" {
		req.Header.Set("Origin", proxy.EncryptString(req.Header.Get("Origin"))+".com")
	}

	if req.Header.Get("Referer") != "" {
		req.Header.Set("Referer", proxy.EncryptString(req.Header.Get("Referer")))
	}

	req.Body = ioutil.NopCloser((&IOReaderCipher{
		Src:    req.Body,
		Key:    rkeybuf,
		Cipher: proxy.GCipher,
	}).Init())

	return rkeybuf
}

func (proxy *ProxyUpstream) decryptRequest(req *http.Request, options byte, rkeybuf []byte) bool {
	var err error
	req.URL, err = url.Parse(decryptURIAndDecompress(req.RequestURI, proxy.GCipher, rkeybuf))
	if err != nil {
		logg.E(err)
		return false
	}

	req.Host = req.URL.Host

	cookies := []string{}
	for _, c := range req.Cookies() {
		c.Value = proxy.GCipher.DecryptString(c.Value)
		cookies = append(cookies, c.String())
	}

	req.Header.Set("Cookie", strings.Join(cookies, ";"))
	if req.Header.Get("Origin") != "" {
		req.Header.Set("Origin", proxy.DecryptString(strings.Replace(req.Header.Get("Origin"), ".com", "", -1)))
	}

	if req.Header.Get("Referer") != "" {
		req.Header.Set("Referer", proxy.DecryptString(req.Header.Get("Referer")))
	}

	req.Body = ioutil.NopCloser((&IOReaderCipher{
		Src:    req.Body,
		Key:    rkeybuf,
		Cipher: proxy.GCipher,
	}).Init())

	return true
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

func checksum1b(buf []byte) byte {
	s := int16(1)
	for _, b := range buf {
		s *= primes[b]
	}
	return byte(s>>12) + byte(s&0x00f0)
}

func isTrustedToken(mark string, rkeybuf []byte) int {
	logg.D("test token: ", rkeybuf)

	mbuf := rkeybuf[1 : len(mark)+1]
	if string(mbuf) != mark || checksum1b(mbuf) != rkeybuf[0] {
		return 0
	}

	sent := int64(binary.BigEndian.Uint32(rkeybuf[12:]))
	if time.Now().Unix()-sent >= 10 || checksum1b(rkeybuf[12:]) != rkeybuf[11] {
		// token becomes invalid after 10 seconds
		return -1
	}

	return 1
}

func genTrustedToken(mark string, gc *GCipher) string {
	_rand := gc.NewRand()
	pad := _rand.Intn(4)
	ret := make([]byte, 1+pad+12+4)
	buf := []byte(mark)

	if len(buf) > 10 {
		buf = buf[:10]
	}

	// +----+-------+------------------+----------+----------------+--------------+
	// | 1b | pad b | mark checksum 1b | mark 10b | ts checksum 1b | timestamp 4b |
	// +----+-------+------------------+----------+----------------+--------------+

	copy(ret[1+pad+1:], buf)
	ret[1+pad] = checksum1b(buf)
	binary.BigEndian.PutUint32(ret[1+pad+12:], uint32(time.Now().Unix()))
	ret[1+pad+11] = checksum1b(ret[1+pad+12:])

	ss := []byte{byte(_rand.Intn(256)), byte(_rand.Intn(256)), byte(_rand.Intn(256)), byte(_rand.Intn(256))}
	return base64.StdEncoding.EncodeToString(append(_xor(gc.Block, gc.GenerateIV(ss...), ret), ss...))
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

func compressAndEncrypt(str string, gc *GCipher, iv []byte) string {
	buf := bitsop.Compress(str)
	return Base32Encode(gc.Encrypt(buf, iv...), false)
}

func decryptURIAndDecompress(str string, gc *GCipher, iv []byte) string {
	if len(str) < 1 {
		return ""
	}

	if str[0] != '/' {
		idx := strings.Index(str[8:], "/")
		if idx == -1 {
			return ""
		}
		str = str[idx+1+8:]
	} else {
		str = str[1:]
	}

	buf, err := Base32Decode(str, false)
	if err != nil {
		return ""
	}

	return bitsop.Decompress(gc.Decrypt(buf, iv...))
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
		i, ln = 1, gc.Rand.Intn(5)+2
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
