package goflyway

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/coyove/goflyway/toh"
	. "github.com/coyove/goflyway/v"
)

type commonConfig struct {
	WriteBuffer int64
	Key         string
	Timeout     time.Duration
	Stat        *Traffic
}

func (config *commonConfig) check() {
	if config.Timeout == 0 {
		config.Timeout = time.Second * 15
	}
	if config.WriteBuffer == 0 {
		config.WriteBuffer = 1024 * 1024 // 1M
	}
}

type ServerConfig struct {
	commonConfig
	ProxyPassAddr string
	SpeedThrot    *TokenBucket
}

func NewServer(listen string, config *ServerConfig) error {
	config.check()

	rp := append([]toh.Option{}, toh.WithMaxWriteBuffer(int(config.WriteBuffer)))

	if config.ProxyPassAddr != "" {
		if strings.HasPrefix(config.ProxyPassAddr, "http") {
			u, err := url.Parse(config.ProxyPassAddr)
			if err != nil {
				return err
			}
			rp = append(rp, toh.WithBadRequest(httputil.NewSingleHostReverseProxy(u).ServeHTTP))
		} else {
			rp = append(rp, toh.WithBadRequest(http.FileServer(http.Dir(config.ProxyPassAddr)).ServeHTTP))
		}
	}

	listener, err := toh.Listen(config.Key, listen, rp...)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go func(conn net.Conn) {
			down := toh.NewBufConn(conn)
			defer down.Close()

			buf, err := down.ReadBytes('\n')
			if err != nil || len(buf) < 2 {
				Vprint(err)
				return
			}

			host := string(bytes.TrimRight(buf, "\n"))

			dialstart := time.Now()
			up, err := net.DialTimeout("tcp", host, config.Timeout)
			if err != nil {
				Vprint(host, err)
				down.Write([]byte(err.Error() + "\n"))
				return
			}

			Vprint("dial ", host, " in ", time.Since(dialstart).Nanoseconds()/1e6, "ms")
			defer up.Close()

			down.Write([]byte("OK\n"))
			Bridge(up, down, config.SpeedThrot, config.Stat)
		}(conn)
	}
}
