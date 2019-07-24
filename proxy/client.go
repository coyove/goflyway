package proxy

import (
	"log"
	"time"

	"github.com/coyove/tcpmux/toh"

	kcp "github.com/xtaci/kcp-go"

	"io"
	"net"
	"net/http"
	"strconv"
)

type ResponseHook interface {
	SetBody(r io.ReadCloser)
}

type ClientConfig struct {
	Upstream string
	Bind     string
	Key      string
	Timeout  time.Duration
	Policy   Options
}

type ProxyClient struct {
	*ClientConfig

	addr   *net.TCPAddr
	dialer *toh.Dialer
}

func (proxy *ProxyClient) Start() error {
	mux, err := net.ListenTCP("tcp", proxy.addr)
	if err != nil {
		return err
	}

	for {
		conn, err := mux.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			downconn := toh.NewBufConn(conn)
			defer conn.Close()

			up, err := proxy.dialer.Dial()
			if err != nil {
				log.Println(err)
				return
			}
			defer up.Close()

			upconn := toh.NewBufConn(up)
			if _, err := upconn.Write([]byte(proxy.Bind + "\n")); err != nil {
				log.Println(err)
				return
			}

			resp, err := upconn.ReadBytes('\n')
			if err != nil || string(resp) != "OK\n" {
				log.Println(err, string(resp))
				return
			}

			Bridge(downconn, upconn)
		}(conn)
	}
}

func NewClient(localaddr string, config *ClientConfig) (*ProxyClient, error) {
	var err error

	if config.Timeout == 0 {
		config.Timeout = time.Second * 10
	}

	proxy := &ProxyClient{
		ClientConfig: config,
	}

	tr := *http.DefaultTransport.(*http.Transport)
	tr.MaxConnsPerHost = 100
	tr.Dial = func(network string, address string) (net.Conn, error) {
		switch {
		case config.Policy.IsSet(PolicyKCP):
			return kcp.Dial(address)
		case config.Policy.IsSet(PolicyVPN):
			return vpnDial(address)
		default:
			return net.Dial(network, address)
		}
	}

	proxy.dialer = toh.NewDialer(config.Key, config.Upstream,
		toh.WithWebSocket(config.Policy.IsSet(PolicyWebSocket)),
		toh.WithInactiveTimeout(config.Timeout),
		toh.WithTransport(&tr))

	if port, lerr := strconv.Atoi(localaddr); lerr == nil {
		proxy.addr = &net.TCPAddr{IP: net.IPv6zero, Port: port}
	} else {
		proxy.addr, err = net.ResolveTCPAddr("tcp", localaddr)
		if err != nil {
			return nil, err
		}
	}

	if proxy.Policy.IsSet(PolicyVPN) {
	}

	return proxy, nil
}
