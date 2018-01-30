package proxy

import (
	"bytes"
	"fmt"
	"net"

	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/msg64"

	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unsafe"
)

const (
	socksVersion5   = byte(0x05)
	socksAddrIPv4   = 1
	socksAddrDomain = 3
	socksAddrIPv6   = 4
	socksVersionErr = "invalid SOCKS version: %d"
	socksMethodErr  = "invalid SOCKS method: %d"
	socksAddressErr = "invalid SOCKS address type: %d"
)

const (
	doConnect   = 1 << iota // Establish TCP tunnel
	doForward               // Forward plain HTTP request
	doWebSocket             // Use WebSocket protocol
	doDNS                   // DNS query request
	doPartial               // Partial encryption
	doUDPRelay              // UDP relay request
	doRSV1                  // Reserved
	doRSV2                  // Reserved
)

const (
	PolicyManInTheMiddle = 1 << iota
	PolicyGlobal
	PolicyVPN
	PolicyWebSocket
)

const (
	timeoutUDP          = 30 * time.Second
	timeoutTCP          = 60 * time.Second
	timeoutDial         = 5 * time.Second
	timeoutOp           = 20 * time.Second
	invalidRequestRetry = 10
	dnsRespHeader       = "ETag"
	errConnClosedMsg    = "use of closed network connection"
)

var (
	okHTTP          = []byte{'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', ' ', 'O', 'K', '\r', '\n', '\r', '\n'}
	okSOCKS         = []byte{socksVersion5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	udpHeaderIPv4   = []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	udpHeaderIPv6   = []byte{0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	socksHandshake  = []byte{socksVersion5, 1, 0}
	dummyHeaders    = []string{"Accept-Language", "Accept-Encoding", "Cache-Control", "Connection", "Referer", "User-Agent"}
	tlsSkip         = &tls.Config{InsecureSkipVerify: true}
	hasPort         = regexp.MustCompile(`:\d+$`)
	isHTTPSSchema   = regexp.MustCompile(`^https:\/\/`)
	base32Encoding  = base32.NewEncoding("0123456789abcdefghiklmnoprstuwxy")
	base32Encoding2 = base32.NewEncoding("abcd&fghijklmnopqrstuvwxyz+-_./e")
)

type Options byte

func (o *Options) IsSet(option byte) bool { return (byte(*o) & option) != 0 }

func (o *Options) Set(option byte) { *o = Options(byte(*o) | option) }

func (o *Options) UnSet(option byte) { *o = Options((byte(*o) | option) - option) }

func (o *Options) Val() byte { return byte(*o) }

type builder string

func (b *builder) Append(texts ...string) { *b = builder(string(*b) + strings.Join(texts, "")) }

func (b *builder) String() string { return string(*b) }

func (b *builder) UnsafeBytes() *[]byte { return (*[]byte)(unsafe.Pointer(b)) }

func (proxy *ProxyClient) addToDummies(req *http.Request) {
	for _, field := range dummyHeaders {
		if x := req.Header.Get(field); x != "" {
			proxy.dummies.Add(field, x)
		}
	}
}

func (proxy *ProxyClient) genHost() string {
	const tlds = ".com.net.org"
	if proxy.DummyDomain == "" {
		i := proxy.Rand.Intn(3) * 4
		return proxy.Cipher.genWord(true) + tlds[i:i+4]
	}

	return proxy.DummyDomain
}

func (proxy *ProxyClient) encryptAndTransport(req *http.Request) (*http.Response, []byte, error) {
	r := proxy.Cipher.newRequest()
	r.Opt.Set(doForward)
	r.Auth = proxy.UserAuth

	proxy.addToDummies(req)

	if proxy.URLHeader != "" {
		req.Header.Add(proxy.URLHeader, "http://"+proxy.genHost()+"/"+proxy.encryptHost(req.URL.String(), r))
		req.Host = proxy.Upstream
		req.URL, _ = url.Parse("http://" + proxy.Upstream)
	} else {
		req.Host = proxy.genHost()
		req.URL, _ = url.Parse("http://" + req.Host + "/" + proxy.encryptHost(req.URL.String(), r))
	}

	if proxy.Policy.IsSet(PolicyManInTheMiddle) && proxy.Connect2Auth != "" {
		x := "Basic " + base64.StdEncoding.EncodeToString([]byte(proxy.Connect2Auth))
		req.Header.Add("Proxy-Authorization", x)
		req.Header.Add("Authorization", x)
	}

	cookies := make([]string, 0, len(req.Cookies()))
	rkeybuf := r.iv[:]

	for _, c := range req.Cookies() {
		c.Value = proxy.Cipher.EncryptString(c.Value, rkeybuf...)
		cookies = append(cookies, c.String())
	}

	req.Header.Set("Cookie", strings.Join(cookies, ";"))
	if origin := req.Header.Get("Origin"); origin != "" {
		req.Header.Set("Origin", proxy.EncryptString(origin, rkeybuf...)+".com")
	}

	if referer := req.Header.Get("Referer"); referer != "" {
		req.Header.Set("Referer", proxy.EncryptString(referer, rkeybuf...))
	}

	req.Body = proxy.Cipher.IO.NewReadCloser(req.Body, rkeybuf)
	// logg.D(req.Header)
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
			logg.W("unexpected URI: ", uri)
		}
	} else {
		uri = uri[1:]
	}

	return uri
}

func (proxy *ProxyUpstream) decryptRequest(req *http.Request, rkeybuf []byte) bool {

	cookies := make([]string, 0, len(req.Cookies()))
	for _, c := range req.Cookies() {
		c.Value = proxy.Cipher.DecryptString(c.Value, rkeybuf...)
		cookies = append(cookies, c.String())
	}
	req.Header.Set("Cookie", strings.Join(cookies, ";"))

	if origin := req.Header.Get("Origin"); len(origin) > 4 {
		req.Header.Set("Origin", proxy.DecryptString(origin[:len(origin)-4], rkeybuf...))
	}

	if referer := req.Header.Get("Referer"); referer != "" {
		req.Header.Set("Referer", proxy.DecryptString(referer, rkeybuf...))
	}

	for k := range req.Header {
		if k[:3] == "Cf-" || (len(k) > 12 && strings.ToLower(k[:12]) == "x-forwarded-") {
			// ignore all cloudflare headers
			// this is needed when you use cf as the frontend:
			// gofw client -> cloudflare -> gofw server -> target host using cloudflare

			// delete all x-forwarded-... headers
			// some websites won't allow them
			req.Header.Del(k)
		}
	}

	req.Body = proxy.Cipher.IO.NewReadCloser(req.Body, rkeybuf)
	return true
}

func copyHeaders(dst, src http.Header, gc *Cipher, enc bool, rkeybuf []byte) {
	for k := range dst {
		dst.Del(k)
	}

	setcookies := []string{}
	for k, vs := range src {
	READ:
		for _, v := range vs {
			switch strings.ToLower(k) {
			case "set-cookie":
				if rkeybuf != nil {
					if enc {
						setcookies = append(setcookies, v)
						continue READ
					} else {
						ei, di := strings.Index(v, "="), strings.Index(v, ";")
						if di == -1 {
							di = len(v)
						}

						v = gc.DecryptString(v[ei+1:di], rkeybuf...)
					}
				}
			case "content-encoding", "content-type":
				if enc {
					dst.Add("X-"+k, v)
					continue READ
				} else if rkeybuf != nil {
					continue READ
				}

				// rkeybuf is nil and we are in decrypt mode
				// aka plain copy mode, so fall to the bottom
			case "x-content-encoding", "x-content-type":
				if !enc {
					dst.Add(k[2:], v)
					continue READ
				}
			}

			for _, vn := range strings.Split(v, "\n") {
				dst.Add(k, vn)
			}
		}
	}

	if len(setcookies) > 0 && rkeybuf != nil {
		// some http proxies or middlewares will combine multiple Set-Cookie headers into one
		// but some browsers do not support this behavior
		// here we just do the combination in advance and split them when decrypting
		dst.Add("Set-Cookie", gc.genWord(true)+"="+
			gc.EncryptString(strings.Join(setcookies, "\n"), rkeybuf...)+"; Domain="+gc.genWord(true)+".com; HttpOnly")
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
		logg.W("cannot close: ", err)
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

func readUntil(r io.Reader, eoh string) ([]byte, error) {
	buf, respbuf := make([]byte, 1), &bytes.Buffer{}
	eidx, found := 0, false

	for {
		n, err := r.Read(buf)
		if n == 1 {
			respbuf.WriteByte(buf[0])
		}

		if buf[0] == eoh[eidx] {
			if eidx++; eidx == len(eoh) {
				found = true
				break
			}
		} else {
			eidx = 0
		}

		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("readUntil cannot find the pattern: %v", []byte(eoh))
	}

	return respbuf.Bytes(), nil
}

func isClosedConnErr(err error) bool {
	return strings.Contains(err.Error(), errConnClosedMsg)
}

func isTimeoutErr(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}

	return false
}

func unsafeStringBytes(in *string) *[]byte {
	return (*[]byte)(unsafe.Pointer(in))
}

func (proxy *ProxyClient) encryptHost(host string, r *clientRequest) string {
	rd := proxy.Cipher.Rand
	s1, s2, s3, s4 := byte(rd.Intn(256)), byte(rd.Intn(256)), byte(rd.Intn(256)), byte(rd.Intn(256))
	enc := proxy.Cipher.Encrypt(msg64.Encode(host, r), s1, s2, s3, s4)
	enc = append(enc, s1, s2, s3, s4)

	return msg64.Base41Encode(enc)
}

func (proxy *ProxyUpstream) decryptHost(url string) (host string, r *clientRequest) {
	buf, ok := msg64.Base41Decode(url)
	if !ok || len(buf) < 4 {
		return
	}

	ln := len(buf)
	s1, s2, s3, s4 := buf[ln-4], buf[ln-3], buf[ln-2], buf[ln-1]
	buf = proxy.Cipher.Decrypt(buf[:ln-4], s1, s2, s3, s4)

	r = new(clientRequest)
	host = msg64.Decode(buf, r)

	return
}
