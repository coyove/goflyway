package proxy

import (
	. "../config"
	"../counter"
	"../logg"

	"crypto/tls"
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

var (
	OK200   = []byte("HTTP/1.0 200 OK\r\n\r\n")
	tlsSkip = &tls.Config{InsecureSkipVerify: true}

	rkeyHeader  = "X-Request-ID"
	rkeyHeader2 = "X-Request-HTTP-ID"
	dnsHeader   = "X-Host-Lookup"

	hostHeadExtract = regexp.MustCompile(`(\S+)\.com`)
	urlExtract      = regexp.MustCompile(`\?q=(\S+)$`)
	hasPort         = regexp.MustCompile(`:\d+$`)

	base32Paddings = []string{".com", ".org", ".net", ".co", ".me", ".cc", ".edu", ".cn"}
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
		SafeAddHeader(req, rkeyHeader2, rkey)
	} else {
		rkey = SafeGetHeader(req, rkeyHeader2)
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
	req.Host = EncryptHost(req.Host, "#")
	req.URL, _ = url.Parse("http://" + req.Host + "/?q=" + AEncryptString(req.URL.String()))

	rkey := RandomKey()
	SafeAddHeader(req, rkeyHeader, rkey)

	if !*G_UnsafeHttp {
		processBody(req, true)
	}

	return rkey
}

func DecryptRequest(req *http.Request) string {
	req.Host = DecryptHost(req.Host, "#")
	if p := urlExtract.FindStringSubmatch(req.URL.String()); len(p) > 1 {
		req.URL, _ = url.Parse(ADecryptString(p[1]))
	}

	rkey := SafeGetHeader(req, rkeyHeader)

	if !*G_UnsafeHttp {
		processBody(req, false)
	}

	return rkey
}

// func EncryptHost(host, mark string) string {
// 	var buf []byte
// 	if *G_NoShoco {
// 		buf = AEncrypt([]byte(mark + host))
// 	} else {
// 		buf = AEncrypt(shoco.Compress(mark + host))
// 	}

// 	t := base32.StdEncoding.EncodeToString(buf)
// 	for i := 7; i >= 1; i-- {
// 		if strings.HasSuffix(t, "======="[:i]) {
// 			return t[:len(t)-i] + base32Paddings[i]
// 		}
// 	}

// 	return t + base32Paddings[0]
// }

// func DecryptHost(host, mark string) string {

// 	for i := 7; i >= 0; i-- {
// 		if strings.HasSuffix(host, base32Paddings[i]) {
// 			host = host[:len(host)-len(base32Paddings[i])] + "======="[:i]
// 			goto next
// 		}
// 	}

// 	return ""

// next:
// 	buf, err := base32.StdEncoding.DecodeString(host)
// 	if err != nil || len(buf) == 0 {
// 		return ""
// 	}

// 	h := ADecrypt(buf)
// 	if !*G_NoShoco {
// 		h = []byte(shoco.Decompress(h))
// 	}

// 	if len(h) == 0 || h[0] != mark[0] {
// 		return ""
// 	}

// 	return string(h[1:])
// }

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

	return string(pa) == *G_Username+":"+*G_Password
}

func tryClose(b io.ReadCloser) {
	if err := b.Close(); err != nil {
		logg.W("can't close response body - ", err)
	}
}

func bytesStartWith(buf []byte, prefix []byte) bool {
	if len(prefix) > len(buf) {
		return false
	}

	for i := 0; i < len(prefix); i++ {
		if prefix[i] != buf[i] {
			return false
		}
	}

	return true
}
