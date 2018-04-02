package lib

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func ParseExtendedOSArgs() (method string, url string) {
	if len(os.Args) <= 1 {
		return
	}

	if strings.HasPrefix(os.Args[1], "-") {
		return
	}

	method = strings.ToUpper(os.Args[1])
	url = os.Args[len(os.Args)-1]
	os.Args = append(os.Args[:1], os.Args[2:len(os.Args)-1]...)

	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}

	return
}

func ParseHeadersAndPost(headers, post string, multipartPOST bool, req *http.Request) (err error) {
	buf := &bytes.Buffer{}
	parse := func(in string) ([][2]string, error) {
		if strings.HasPrefix(in, "@") {
			buf, err := ioutil.ReadFile(in[1:])
			if err != nil {
				return nil, err
			}
			in = string(buf)
		} else {
			in, _ = strconv.Unquote(`"` + in + `"`)
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

	ppost, err := parse(post)
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
		req.Body = ioutil.NopCloser(buf)
	} else {
		for _, kv := range ppost {
			req.Header.Add(kv[0], kv[1])
		}
	}

	return nil
}

func ParseSetCookies(headers http.Header) []*http.Cookie {
	var dummy http.Response
	dummy.Header = headers
	return dummy.Cookies()
}

type waitingReader struct {
	in chan []byte
	ex []byte
}

func (r *waitingReader) Read(p []byte) (int, error) {
REPEAT:
	if len(r.ex) > 0 {
		copy(p, r.ex)
		if len(r.ex) <= len(p) {
			n := len(r.ex)
			r.ex = nil
			return n, nil
		}

		r.ex = r.ex[len(p):]
		return len(p), nil
	}

	var ok bool
	select {
	case r.ex, ok = <-r.in:
		if !ok {
			return 0, io.EOF
		}
	}

	goto REPEAT
}

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// ResponseRecorder is an implementation of http.ResponseWriter that
// records its mutations for later inspection in tests.
type ResponseRecorder struct {
	// Code is the HTTP response code set by WriteHeader.
	//
	// Note that if a Handler never calls WriteHeader or Write,
	// this might end up being 0, rather than the implicit
	// http.StatusOK. To get the implicit value, use the Result
	// method.
	Code int

	// HeaderMap contains the headers explicitly set by the Handler.
	//
	// To get the implicit headers set by the server (such as
	// automatic Content-Type), use the Result method.
	HeaderMap http.Header

	// Body is the buffer to which the Handler's Write calls are sent.
	// If nil, the Writes are silently discarded.
	Body io.Writer

	// Flushed is whether the Handler called Flush.
	Flushed bool

	result      *http.Response // cache of Result's return value
	snapHeader  http.Header    // snapshot of HeaderMap at first Write
	wroteHeader bool
	gzip        *gzip.Reader
	waitReader  *waitingReader
}

// NewRecorder returns an initialized ResponseRecorder.
func NewRecorder(body io.Writer) *ResponseRecorder {
	return &ResponseRecorder{
		HeaderMap: make(http.Header),
		Body:      body,
		Code:      200,
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

// writeHeader writes a header if it was not written yet and
// detects Content-Type if needed.
//
// bytes or str are the beginning of the response body.
// We pass both to avoid unnecessarily generate garbage
// in rw.WriteString which was created for performance reasons.
// Non-nil bytes win.
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

// Write always succeeds and writes to rw.Body, if not nil.
func (rw *ResponseRecorder) Write(buf []byte) (int, error) {
	rw.writeHeader(buf, "")
	if rw.gzip == nil && rw.HeaderMap.Get("Content-Encoding") == "gzip" {
		rw.waitReader = &waitingReader{in: make(chan []byte, 1024), ex: buf}
		rw.gzip, _ = gzip.NewReader(rw.waitReader)
		return len(buf), nil
	}

	if rw.gzip != nil {
		rw.waitReader.in <- buf
		n, err := rw.gzip.Read(buf)
		if err != nil {
			return 0, err
		}

		buf = buf[:n]
	}

	rw.Body.Write(buf)
	return len(buf), nil
}

func (rw *ResponseRecorder) Close() error {
	if rw.gzip != nil {
		close(rw.waitReader.in)
		io.Copy(rw.Body, rw.gzip)
		rw.gzip.Close()
	}
	return nil
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
