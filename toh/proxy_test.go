package toh

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
)

func iocopy(dst io.Writer, src io.Reader) (written int64, err error) {
	size := 32 * 1024
	buf := make([]byte, size)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
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

func bridge(a, b io.ReadWriteCloser) {
	go func() { iocopy(a, b); a.Close(); b.Close() }()
	go func() { iocopy(b, a); a.Close(); b.Close() }()
}

type client int

type server int

var dd *Dialer

func (s *client) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	up, err := dd.Dial()
	if err != nil {
		log.Println(err)
		return
	}
	up.Write([]byte(r.Method[:1] + host + "\n"))

	down, _, _ := w.(http.Hijacker).Hijack()
	if r.Method != "CONNECT" {
		header, _ := httputil.DumpRequestOut(r, false)
		x := string(header)
		up.Write([]byte(x))
		io.Copy(up, r.Body)
	}

	bridge(down, up)
}

func foo(conn net.Conn) {
	down := NewBufConn(conn)
	buf, err := down.ReadBytes('\n')
	if err != nil || len(buf) < 2 {
		conn.Close()
		return
	}

	host := string(buf)
	connect := host[0] == 'C'
	host = host[1 : len(host)-1]
	// vprint(host, connect)

	up, _ := net.Dial("tcp", host)

	if up == nil || down == nil {
		down.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
		return
	}

	if connect {
		down.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	bridge(down, up)
}

func TestProxy(t *testing.T) {
	go func() {
		for {
			time.Sleep(2 * time.Second)
			f, _ := os.Create("heap.txt")
			pprof.Lookup("goroutine").WriteTo(f, 1)
			f.Close()
		}
	}()

	//p, _ := url.Parse("68.183.156.72:8080")
	//DefaultTransport.Proxy = http.ProxyURL(p)

	go func() {
		log.Println("hello")
		up, ws := os.Getenv("UP"), os.Getenv("WS") == "1"

		if up == "" {
			up = ":10001"
		}

		tr := *http.DefaultTransport.(*http.Transport)
		tr.MaxConnsPerHost = 100

		u, _ := url.Parse("http://example.com")

		dd = NewDialer("tcp", up,
			WithTransport(&tr),
			WithInactiveTimeout(time.Second*10),
			WithWebSocket(ws),
			WithPath("/aaa"))

		go http.ListenAndServe(":10000", new(client))

		ln, _ := Listen("tcp", ":10001",
			WithInactiveTimeout(time.Second*10),
			WithPath("/aaa"),
			WithBadRequest(httputil.NewSingleHostReverseProxy(u).ServeHTTP))
		for {
			conn, _ := ln.Accept()
			go foo(conn)
		}
	}()

	//	Verbose = false
	select {}
}
