package proxy

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coyove/tcpmux/toh"
	"github.com/xtaci/kcp-go"
)

type ServerConfig struct {
	Policy        Options
	ProxyPassAddr string
	Key           string
	Timeout       time.Duration
}

// ProxyServer is the main struct for upstream server
type ProxyServer struct {
	listener net.Listener
	listen   string
	rp       http.Handler

	*ServerConfig
}

func (proxy *ProxyServer) handle(conn net.Conn) {
	down := toh.NewBufConn(conn)
	defer down.Close()

	buf, err := down.ReadBytes('\n')
	if err != nil || len(buf) < 2 {
		return
	}

	host := string(bytes.TrimRight(buf, "\n"))
	up, err := net.Dial("tcp", host)
	if err != nil {
		down.Write([]byte(err.Error() + "\n"))
		return
	}
	defer up.Close()

	down.Write([]byte("OK\n"))
	Bridge(down, up)
}

func (proxy *ProxyServer) Start() (err error) {
	if proxy.Policy.IsSet(PolicyKCP) {
		proxy.listener, err = kcp.Listen(proxy.listen)
	} else {
		proxy.listener, err = toh.Listen(proxy.Key, proxy.listen)
	}

	if err != nil {
		return err
	}

	for {
		conn, err := proxy.listener.Accept()
		if err != nil {
			return err
		}
		go proxy.handle(conn)
	}
}

func NewServer(addr string, config *ServerConfig) (*ProxyServer, error) {
	if config.Timeout == 0 {
		config.Timeout = time.Second * 10
	}

	proxy := &ProxyServer{
		ServerConfig: config,
	}

	// tcpmux.HashSeed = config.Cipher.keyBuf

	if config.ProxyPassAddr != "" {
		if strings.HasPrefix(config.ProxyPassAddr, "http") {
			u, err := url.Parse(config.ProxyPassAddr)
			if err != nil {
				return nil, nil
			}

			proxy.rp = httputil.NewSingleHostReverseProxy(u)
		} else {
			proxy.rp = http.FileServer(http.Dir(config.ProxyPassAddr))
		}
	}

	if port, lerr := strconv.Atoi(addr); lerr == nil {
		addr = (&net.TCPAddr{IP: net.IPv4zero, Port: port}).String()
	}

	proxy.listen = addr
	return proxy, nil
}
