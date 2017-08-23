package proxy

import (
	. "../config"
	"../logg"
	"../lru"

	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var hostHead = "%s.baidu.com:433"
var hostHeadExtract = regexp.MustCompile(`(\S+)\.baidu\.com`)
var urlExtract = regexp.MustCompile(`\?q=(\S+)$`)

func RandomKeyBase36() string {
	_rand := rand.New(rand.NewSource(time.Now().UnixNano()))
	retB := make([]byte, 64)

	for i := 0; i < 64; i++ {
		retB[i] = byte(_rand.Intn(256))
	}

	return Base36Encode(Skip32Encode(G_KeyBytes, retB, true))
}

func processBody(req *http.Request, enc bool) {
	buf, err := ioutil.ReadAll(req.Body)
	req.Body.Close()

	if err != nil {
		return
	}

	for _, c := range req.Cookies() {
		if enc {
			c.Value = Skip32EncodeString(G_KeyBytes, c.Value)
		} else {
			c.Value = Skip32DecodeString(G_KeyBytes, c.Value)
		}
	}

	if enc {
		req.Body = ioutil.NopCloser(bytes.NewReader(Skip32Encode(G_KeyBytes, buf, false)))
	} else {
		req.Body = ioutil.NopCloser(bytes.NewReader(Skip32Decode(G_KeyBytes, buf, false)))
	}
}

func EncryptRequest(req *http.Request) {
	req.Host = EncryptHost(req.Host)
	req.URL, _ = url.Parse("http://" + req.Host + "/?q=" + Skip32EncodeString(G_KeyBytes, req.URL.String()))

	if !*G_UnsafeHttp {
		processBody(req, true)
	}
}

func DecryptRequest(req *http.Request) {
	req.Host = DecryptHost(req.Host)
	if p := urlExtract.FindStringSubmatch(req.URL.String()); len(p) > 1 {
		req.URL, _ = url.Parse(Skip32DecodeString(G_KeyBytes, p[1]))
	}

	if !*G_UnsafeHttp {
		processBody(req, false)
	}
}

func EncryptHost(host string) string {
	return fmt.Sprintf(hostHead, Skip32EncodeString(G_KeyBytes, host))
}

func DecryptHost(host string) string {
	if p := hostHeadExtract.FindStringSubmatch(host); len(p) > 1 {
		return Skip32DecodeString(G_KeyBytes, p[1])
	}

	return ""
}

func copyAndClose(dst, src *net.TCPConn, key string) {
	ts := time.Now()

	var rkey []byte
	if key != "" {
		rkey = Skip32Decode(G_KeyBytes, Base36Decode(key), true)
	}

	if _, err := (&IOCopyCipher{
		Dst: dst,
		Src: src,
		Key: rkey,
	}).DoCopy(); err != nil && !*G_SuppressSocketReadWriteError {
		logg.E("[COPY] ~", time.Now().Sub(ts).Seconds(), " - ", err)
	}

	dst.CloseWrite()
	src.CloseRead()
}

func copyOrWarn(dst io.Writer, src io.Reader, key string, wg *sync.WaitGroup) {
	ts := time.Now()

	var rkey []byte
	if key != "" {
		rkey = Skip32Decode(G_KeyBytes, Base36Decode(key), true)
	}

	if _, err := (&IOCopyCipher{
		Dst: dst,
		Src: src,
		Key: rkey,
	}).DoCopy(); err != nil && !*G_SuppressSocketReadWriteError {
		logg.E("[COPYW] ~", time.Now().Sub(ts).Seconds(), " - ", err)
	}

	wg.Done()
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

func PrintCache(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Write([]byte(`<html><title>goflyway dns lookup cache</title>
		<form method='POST'><button>clear cache</button></form>
		<table>
		<tr><th>host</th><th>ip</th><th>hits</th></tr>`))

		flag := false
		G_Cache.Info(func(k lru.Key, v interface{}, h int64) {
			flag = true
			w.Write([]byte(fmt.Sprintf("<tr><td>%v</td><td>%v</td><td align=right>%d</td></tr>", k, v, h)))
		})

		if !flag {
			w.Write([]byte("<tr><td>n/a</td><td>n/a</td><td align=right>n/a</td></tr>"))
		}

		w.Write([]byte("</table></html>"))
	} else if r.Method == "POST" {
		G_Cache.Clear()
		http.Redirect(w, r, "/dns-lookup-cache", 301)
	}
}

type IOCopyCipher struct {
	Dst io.Writer
	Src io.Reader
	Key []byte

	read int64
}

func (cc *IOCopyCipher) DoCopy() (written int64, err error) {
	buf := make([]byte, 32*1024)
	cc.read = 0

	for {
		ts := time.Now()
		nr, er := cc.Src.Read(buf)
		if nr > 0 {
			xbuf := buf[0:nr]

			if cc.Key != nil && len(cc.Key) > 0 {
				// if key is not null, do the en/decryption
				xs := 0

				if bytesStartWith(xbuf, OK200) {
					xs = len(OK200)
				}

				for i := xs; i < nr; i++ {
					xbuf[i] ^= cc.Key[(int(cc.read)+i-xs)%len(cc.Key)]
				}

				cc.read += int64(nr - xs)
			}

			nw, ew := cc.Dst.Write(xbuf)

			if nw > 0 {
				written += int64(nw)
			}

			if ew != nil {
				err = ew
				logg.W("[IO TIMING 0] ", time.Now().Sub(ts).Seconds())
				break
			}

			if nr != nw {
				err = io.ErrShortWrite
				logg.W("[IO TIMING 1] ", time.Now().Sub(ts).Seconds())
				break
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}
