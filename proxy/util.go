package proxy

import (
	. "../config"
	"../counter"
	"../logg"
	"../lookup"
	"../shoco"

	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	socks5Version = byte(0x05)
	socksTypeIPv4 = 1
	socksTypeDm   = 3
	socksTypeIPv6 = 4

	DO_NOTHING    = 0
	DO_THROTTLING = 1
	DO_SOCKS5     = 1 << 16

	HOST_HTTP_CONNECT  = '*'
	HOST_HTTP_FORWARD  = '#'
	HOST_SOCKS_CONNECT = '$'

	RKEY_HEADER     = "X-Request-ID"
	RKEY_HEADER2    = "X-Request-HTTP-ID"
	DNS_HEADER      = "X-Host-Lookup"
	CANNOT_READ_BUF = "[SOCKS] cannot read buffer - "
	NOT_SOCKS5      = "[SOCKS] invalid socks version (socks5 only)"
)

var (
	OK_HTTP = []byte("HTTP/1.0 200 OK\r\n\r\n")
	// version, granted = 0, 0, ipv4, 0, 0, 0, 0, (port) 0, 0
	OK_SOCKS = []byte{socks5Version, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01}

	tlsSkip = &tls.Config{InsecureSkipVerify: true}

	hostHeadExtract = regexp.MustCompile(`(\S+)\.com`)
	urlExtract      = regexp.MustCompile(`\?q=(\S+)$`)
	hasPort         = regexp.MustCompile(`:\d+$`)

	base32Encoding = base32.NewEncoding("0123456789abcdfgijklmnopqsuvwxyz")
	base32Replace  = []string{"th", "er", "t", "h", "e", "r"}
)

func NewRand() *rand.Rand {
	var k int64 = int64(binary.BigEndian.Uint64(G_KeyBytes[:8]))
	var k2 int64

	if *G_HRCounter {
		k2 = counter.Get()
	} else {
		k2 = time.Now().UnixNano()
	}

	return rand.New(rand.NewSource(k2 ^ k))
}

func RandomKey() string {
	_rand := NewRand()
	retB := make([]byte, 16)

	for i := 0; i < 16; i++ {
		retB[i] = byte(_rand.Intn(255) + 1)
	}

	return base64.StdEncoding.EncodeToString(AEncrypt(retB))
}

func ReverseRandomKey(key string) []byte {
	if key == "" {
		return nil
	}

	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil
	}

	return ADecrypt(k)
}

func processBody(req *http.Request, enc bool) {
	var rkey string
	if enc {
		add := func(field string) {
			if x := req.Header.Get(field); x != "" {
				G_RequestDummies.Add(field, x)
			}
		}

		add("Accept-Language")
		add("User-Agent")
		add("Referer")
		add("Cache-Control")
		add("Accept-Encoding")
		add("Connection")

		rkey = RandomKey()
		SafeAddHeader(req, RKEY_HEADER2, rkey)
	} else {
		rkey = SafeGetHeader(req, RKEY_HEADER2)
	}

	for _, c := range req.Cookies() {
		if enc {
			c.Value = AEncryptString(c.Value)
		} else {
			c.Value = ADecryptString(c.Value)
		}
	}

	req.Body = ioutil.NopCloser((&IOReaderCipher{Src: req.Body, Key: ReverseRandomKey(rkey)}).Init())
}

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

func EncryptRequest(req *http.Request) string {
	req.Host = EncryptHost(req.Host, HOST_HTTP_FORWARD)
	req.URL, _ = url.Parse("http://" + req.Host + "/?q=" + AEncryptString(req.URL.String()))

	rkey := RandomKey()
	SafeAddHeader(req, RKEY_HEADER, rkey)
	processBody(req, true)
	return rkey
}

func DecryptRequest(req *http.Request) string {
	req.Host = DecryptHost(req.Host, HOST_HTTP_FORWARD)
	if p := urlExtract.FindStringSubmatch(req.URL.String()); len(p) > 1 {
		req.URL, _ = url.Parse(ADecryptString(p[1]))
	}

	rkey := SafeGetHeader(req, RKEY_HEADER)
	processBody(req, false)
	return rkey
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

func getAuth(r *http.Request) string {
	pa := r.Header.Get("Proxy-Authorization")
	if pa == "" {
		pa = r.Header.Get("X-Authorization")
	}

	return pa
}

func basicAuth(token string) bool {
	parts := strings.Split(token, " ")
	if len(parts) != 2 {
		return false
	}

	pa, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return false
	}

	return string(pa) == *G_Auth
}

func tryClose(b io.ReadCloser) {
	if err := b.Close(); err != nil {
		logg.W("can't close response body - ", err)
	}
}

func SplitHostPort(host string) (string, string) {
	if idx := strings.Index(host, ":"); idx > 0 {
		return strings.ToLower(host[:idx]), host[idx:] // Port has a colon ':'
	} else {
		return strings.ToLower(host), ""
	}
}

func EncryptHost(text string, mark byte) string {
	host, port := SplitHostPort(text)

	enc := func(in string) string {
		if *G_DisableShoco {
			return Base32Encode(AEncrypt([]byte(in)))
		} else {
			return Base32Encode(AEncrypt(shoco.Compress(in)))
		}
	}

	if lookup.IPAddressToInteger(host) != 0 {
		return enc(string(mark)+host) + port
	}

	parts := strings.Split(host, ".")
	flag := false
	for i := len(parts) - 1; i >= 0; i-- {
		if !tlds[parts[i]] {
			parts[i] = enc(string(mark) + parts[i])
			flag = true
			break
		}
	}

	if flag {
		return strings.Join(parts, ".") + port
	}

	return enc(string(mark)+host) + port
}

func DecryptHost(text string, mark byte) string {
	host, m := TryDecryptHost(text)
	if m != mark {
		return ""
	} else {
		return host
	}
}

func TryDecryptHost(text string) (h string, m byte) {
	host, port := SplitHostPort(text)
	parts := strings.Split(host, ".")

	for i := len(parts) - 1; i >= 0; i-- {
		if !tlds[parts[i]] {
			buf := Base32Decode(parts[i])

			if *G_DisableShoco {
				parts[i] = string(ADecrypt(buf))
			} else {
				parts[i] = shoco.Decompress(ADecrypt(buf))
			}

			if len(parts[i]) == 0 {
				return text, 0
			} else {
				m = parts[i][0]
			}
			parts[i] = parts[i][1:]
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

	return str[:idx] + base32Replace[len(str)-idx-1]
}

func Base32Decode(text string) []byte {
	const paddings = "======"

	for i := 0; i < len(base32Replace); i++ {
		if strings.HasSuffix(text, base32Replace[i]) {
			text = text[:len(text)-len(base32Replace[i])] + paddings[:i+1]
			break
		}
	}

	buf, err := base32Encoding.DecodeString(text)
	if err != nil {
		return []byte{}
	}

	return buf
}
