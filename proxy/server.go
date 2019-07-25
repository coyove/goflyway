package proxy

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	. "github.com/coyove/goflyway/v"
	"github.com/coyove/tcpmux/toh"
	"github.com/xtaci/kcp-go"
)

type commonConfig struct {
	KCP     bool
	Key     string
	Timeout time.Duration
}

func (config *commonConfig) check() {
	if config.Timeout == 0 {
		config.Timeout = time.Second * 15
	}
}

type ServerConfig struct {
	commonConfig
	ProxyPassAddr string
	SpeedThrot    *TokenBucket
}

func NewServer(listen string, config *ServerConfig) error {
	var (
		err      error
		listener net.Listener
		rp       []toh.Option
	)

	config.check()

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

	if config.KCP {
		listener, err = kcp.Listen(listen)
	} else {
		listener, err = toh.Listen(config.Key, listen, rp...)
	}
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
			Vprint(Stacktrace, host)

			up, err := net.Dial("tcp", host)
			if err != nil {
				down.Write([]byte(err.Error() + "\n"))
				return
			}
			defer up.Close()

			down.Write([]byte("OK\n"))
			Bridge(down, up, config.SpeedThrot)
		}(conn)
	}
}
