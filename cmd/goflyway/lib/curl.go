package lib

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	_url "net/url"
	"os"
	"strconv"
	"strings"
)

func ParseHeadersAndPostBody(headers, post string, multipartPOST bool, req *http.Request) (err error) {
	buf := &bytes.Buffer{}
	parse := func(in string, form bool) ([][2]string, error) {
		if strings.HasPrefix(in, "@") {
			buf, err := ioutil.ReadFile(in[1:])
			if err != nil {
				return nil, err
			}
			in = string(buf)
		} else {
			in, _ = strconv.Unquote(`"` + in + `"`)
		}

		if form {
			values, err := url.ParseQuery(in)
			if err != nil {
				return nil, err
			}

			ret := make([][2]string, 0, len(values))
			for k, v := range values {
				if strings.HasPrefix(v[0], "@") {
					multipartPOST = true
				}
				ret = append(ret, [2]string{k, v[0]})
			}
			return ret, nil
		}
		lines := strings.Split(in, "\n")
		pairs := make([][2]string, 0, len(lines))

		for _, line := range lines {
			if len(line) < 3 {
				continue
			}

			if line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}

			buf.Reset()
			for i, r := range line {
				lc := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
					r == '!' || r == '#' || r == '$' || r == '%' || r == '&' || r == '\'' || r == '+' || r == '-' ||
					r == '.' || r == '^' || r == '_' || r == '`' || r == '|' || r == '~' || r == '*'

				if lc {
					buf.WriteRune(r)
				} else {
					line = strings.TrimSpace(line[i+1:])
					break
				}
			}

			if buf.Len() == 0 {
				continue
			}

			if strings.HasPrefix(line, "@") {
				multipartPOST = true
			}

			pairs = append(pairs, [2]string{buf.String(), line})
		}

		return pairs, nil
	}

	if strings.HasPrefix(post, "@@") {
		f, err := os.Open(post[2:])
		if err != nil {
			return err
		}

		buf := bufio.NewReader(f)

		if multipartPOST {
			line, _ := buf.Peek(256)
			if idx := bytes.IndexByte(line, '\n'); idx > -1 {
				ct := strings.Replace(string(line[:idx]), "\r", "", -1)
				req.Header.Set("Content-Type", ct)
			}
			req.Header.Set("Content-Length", "0")
		} else if req.Method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Content-Length", "0")
		}

		req.Body = ioutil.NopCloser(buf)
		return nil
	}

	ppost, err := parse(post, true)
	if err != nil {
		return err
	}

	if multipartPOST {
		buf.Reset()
		mw := multipart.NewWriter(buf)

		for _, kv := range ppost {
			if strings.HasPrefix(kv[1], "@") {
				f, err := os.Open(kv[1][1:])
				if err != nil {
					return err
				}

				w, _ := mw.CreateFormFile(kv[0], kv[1][1:])
				_, err = io.Copy(w, f)
				f.Close()
			} else {
				w, _ := mw.CreateFormField(kv[0])
				_, err = io.Copy(w, strings.NewReader(kv[1]))
			}

			if err != nil {
				return err
			}
		}

		mw.Close()
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Content-Length", "0")
		req.Body = ioutil.NopCloser(buf)
	} else {
		if req.Method == "POST" {
			form := _url.Values{}
			for _, kv := range ppost {
				form.Add(kv[0], kv[1])
			}

			x := form.Encode()
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Content-Length", strconv.Itoa(len(x)))
			req.Body = ioutil.NopCloser(strings.NewReader(x))
		} else {
			form := req.URL.Query()
			for _, kv := range ppost {
				form.Add(kv[0], kv[1])
			}
			req.URL.RawQuery = form.Encode()
			req.RequestURI = req.URL.String()
		}
	}

	pheader, err := parse(headers, false)
	if err != nil {
		return err
	}

	for _, kv := range pheader {
		req.Header.Add(kv[0], kv[1])
	}

	return nil
}

func ParseSetCookies(headers http.Header) []*http.Cookie {
	var dummy http.Response
	dummy.Header = headers
	return dummy.Cookies()
}

func IOCopy(w io.Writer, r *ResponseRecorder, reformatJSON bool) {
	if r.HeaderMap.Get("Content-Type") == "application/json" || reformatJSON {
		buf, bufsrc := &bytes.Buffer{}, &bytes.Buffer{}
		io.Copy(bufsrc, r.Body)
		json.Indent(buf, bufsrc.Bytes(), "", "  ")
		w.Write(buf.Bytes())
	} else {
		io.Copy(w, r.Body)
	}
}

type NullReader struct{}

func (r *NullReader) Read(p []byte) (int, error) { return 0, io.EOF }

func (r *NullReader) Close() error { return nil }

type readerProgress struct {
	r        io.ReadCloser
	callback func(bytes int64)
}

func (r *readerProgress) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.callback(int64(n))
	return n, err
}

func (r *readerProgress) Close() error {
	r.r.Close()
	return nil
}

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// ResponseRecorder is an implementation of http.ResponseWriter that
// records its mutations for later inspection in tests.
type ResponseRecorder struct {
	Code      int
	HeaderMap http.Header
	Flushed   bool
	Body      io.ReadCloser

	result      *http.Response // cache of Result's return value
	snapHeader  http.Header    // snapshot of HeaderMap at first Write
	wroteHeader bool
	callback    func(bytes int64)
}

// NewRecorder returns an initialized ResponseRecorder.
func NewRecorder(callback func(bytes int64)) *ResponseRecorder {
	return &ResponseRecorder{
		HeaderMap: make(http.Header),
		Code:      200,
		callback:  callback,
	}
}

// DefaultRemoteAddr is the default remote address to return in RemoteAddr if
// an explicit DefaultRemoteAddr isn't set on ResponseRecorder.
const DefaultRemoteAddr = "1.2.3.4"

// Header returns the response headers.
func (rw *ResponseRecorder) Header() http.Header {
	m := rw.HeaderMap
	if m == nil {
		m = make(http.Header)
		rw.HeaderMap = m
	}
	return m
}

func (rw *ResponseRecorder) writeHeader(b []byte, str string) {
	if rw.wroteHeader {
		return
	}
	if len(str) > 512 {
		str = str[:512]
	}

	m := rw.Header()

	_, hasType := m["Content-Type"]
	hasTE := m.Get("Transfer-Encoding") != ""
	if !hasType && !hasTE {
		if b == nil {
			b = []byte(str)
		}
		m.Set("Content-Type", http.DetectContentType(b))
	}

	rw.WriteHeader(200)
}

func (rw *ResponseRecorder) IsRedir() bool {
	return rw.Code == 301 || rw.Code == 302 || rw.Code == 307
}

func (rw *ResponseRecorder) SetBody(r io.ReadCloser) {
	rw.Body = &readerProgress{r: r, callback: rw.callback}
}

func PrettySize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d bytes", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%d KB", bytes/1024)
	} else if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(bytes)/1024/1024)
	}
	return fmt.Sprintf("%.2f GB", float64(bytes)/1024/1024/1024)
}

func (rw *ResponseRecorder) Write(buf []byte) (int, error) {
	// if rw.IsRedir() && rw.ignoreRedirBody {
	// 	return len(buf), nil
	// }

	// header := func(k string) string {
	// 	s := rw.HeaderMap[k]
	// 	if len(s) == 0 {
	// 		return ""
	// 	}
	// 	return s[0]
	// }

	// enc := header("Content-Encoding")

	// if enc == "gzip" && rw.reader == nil {
	// 	PrintInErr("* decoding gzip content\n")
	// }

	// rw.totalSize += int64(len(buf))
	// PrintInErr("\r* copy body: ", prettySize(rw.totalSize), " / ",
	// 	prettySize(parseContentLength(header("Content-Length"))))

	// rw.writeHeader(buf, "")

	// if rw.reader == nil {
	// 	rw.rwPipe = &pipe{in: make(chan []byte, 128), ex: buf}

	// 	if enc == "gzip" {
	// 		// Here we assumes that buf is big enough to hold gzip header
	// 		rw.reader, _ = gzip.NewReader(rw.rwPipe)
	// 	} else {
	// 		rw.reader = rw.rwPipe
	// 	}

	// 	go io.Copy(rw.body, rw.reader)
	// }

	// return rw.rwPipe.Write(buf)
	return len(buf), nil
}

// WriteHeader sets rw.Code. After it is called, changing rw.Header
// will not affect rw.HeaderMap.
func (rw *ResponseRecorder) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.Code = code
	rw.wroteHeader = true
	if rw.HeaderMap == nil {
		rw.HeaderMap = make(http.Header)
	}
	rw.snapHeader = cloneHeader(rw.HeaderMap)
}

func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// Result returns the response generated by the handler.
//
// The returned Response will have at least its StatusCode,
// Header, Body, and optionally Trailer populated.
// More fields may be populated in the future, so callers should
// not DeepEqual the result in tests.
//
// The Response.Header is a snapshot of the headers at the time of the
// first write call, or at the time of this call, if the handler never
// did a write.
//
// The Response.Body is guaranteed to be non-nil and Body.Read call is
// guaranteed to not return any error other than io.EOF.
//
// Result must only be called after the handler has finished running.
//
// Coyove: note this method will not dump body
func (rw *ResponseRecorder) Result() *http.Response {
	if rw.result != nil {
		return rw.result
	}
	if rw.snapHeader == nil {
		rw.snapHeader = cloneHeader(rw.HeaderMap)
	}
	res := &http.Response{
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: rw.Code,
		Header:     rw.snapHeader,
	}
	rw.result = res
	if res.StatusCode == 0 {
		res.StatusCode = 200
	}
	res.Status = fmt.Sprintf("%03d %s", res.StatusCode, http.StatusText(res.StatusCode))
	res.ContentLength = parseContentLength(res.Header.Get("Content-Length"))

	if trailers, ok := rw.snapHeader["Trailer"]; ok {
		res.Trailer = make(http.Header, len(trailers))
		for _, k := range trailers {
			// TODO: use http2.ValidTrailerHeader, but we can't
			// get at it easily because it's bundled into net/http
			// unexported. This is good enough for now:
			switch k {
			case "Transfer-Encoding", "Content-Length", "Trailer":
				// Ignore since forbidden by RFC 2616 14.40.
				continue
			}
			k = http.CanonicalHeaderKey(k)
			vv, ok := rw.HeaderMap[k]
			if !ok {
				continue
			}
			vv2 := make([]string, len(vv))
			copy(vv2, vv)
			res.Trailer[k] = vv2
		}
	}
	for k, vv := range rw.HeaderMap {
		if !strings.HasPrefix(k, http.TrailerPrefix) {
			continue
		}
		if res.Trailer == nil {
			res.Trailer = make(http.Header)
		}
		for _, v := range vv {
			res.Trailer.Add(strings.TrimPrefix(k, http.TrailerPrefix), v)
		}
	}
	return res
}

// parseContentLength trims whitespace from s and returns -1 if no value
// is set, or the value if it's >= 0.
//
// This a modified version of same function found in net/http/transfer.go. This
// one just ignores an invalid header.
func parseContentLength(cl string) int64 {
	cl = strings.TrimSpace(cl)
	if cl == "" {
		return -1
	}
	n, err := strconv.ParseInt(cl, 10, 64)
	if err != nil {
		return -1
	}
	return n
}
