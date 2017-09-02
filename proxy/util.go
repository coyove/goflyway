package proxy

import (
	. "../config"
	"../logg"

	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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
	dnsHeaderID = "X-Host-Lookup-ID"
	dnsHeader   = "X-Host-Lookup"

	hostHeadHolder  = "%s.%s.com"
	hostHeadExtract = regexp.MustCompile(`(\S+)\.com`)
	urlExtract      = regexp.MustCompile(`\?q=(\S+)$`)
	hasPort         = regexp.MustCompile(`:\d+$`)

	primes = []byte{
		11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
		47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
	}
)

func NewRand() *rand.Rand {
	k := int64(binary.BigEndian.Uint64(G_KeyBytes[:8]))
	return rand.New(rand.NewSource(time.Now().UnixNano() ^ k))
}

func RandomKey() string {
	_rand := NewRand()
	retB := make([]byte, 16)

	for i := 0; i < 16; i++ {
		retB[i] = byte(_rand.Intn(255) + 1)
	}

	return base64.StdEncoding.EncodeToString(Skip32Encode(G_KeyBytes, retB))
}

func ReverseRandomKey(key string) []byte {
	if key == "" {
		return nil
	}

	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil
	}

	return Skip32Decode(G_KeyBytes, k)
}

func processBody(req *http.Request, enc bool) {
	var rkey string
	if enc {
		G_RequestDummies.Add("Accept-Language", req.Header.Get("Accept-Language"))
		G_RequestDummies.Add("User-Agent", req.Header.Get("User-Agent"))

		rkey = RandomKey()
		SafeAddHeader(req, rkeyHeader2, rkey)
	} else {
		rkey = SafeGetHeader(req, rkeyHeader2)
	}

	for _, c := range req.Cookies() {
		if enc {
			c.Value = Skip32EncodeString(G_KeyBytes, c.Value)
		} else {
			c.Value = Skip32DecodeString(G_KeyBytes, c.Value)
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
	req.URL, _ = url.Parse("http://" + req.Host + "/?q=" + Skip32EncodeString(G_KeyBytes, req.URL.String()))

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
		req.URL, _ = url.Parse(Skip32DecodeString(G_KeyBytes, p[1]))
	}

	rkey := SafeGetHeader(req, rkeyHeader)

	if !*G_UnsafeHttp {
		processBody(req, false)
	}

	return rkey
}

func EncryptHost(host, mark string) string {
	return fmt.Sprintf("%x", Skip32Encode(G_KeyBytes, []byte(mark+host))) + ".com"
}

func DecryptHost(host, mark string) string {
	m := hostHeadExtract.FindStringSubmatch(host)
	if len(m) < 2 {
		return ""
	}

	buf, err := hex.DecodeString(m[1])
	if err != nil || len(buf) == 0 {
		return ""
	}

	h := Skip32Decode(G_KeyBytes, buf)
	if len(h) == 0 || h[0] != mark[0] {
		return ""
	}

	return string(h[1:])
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
