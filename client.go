package goflyway

import (
	"github.com/coyove/goflyway/toh"
	. "github.com/coyove/goflyway/v"
	kcp "github.com/xtaci/kcp-go"

	"net"
)

type ClientConfig struct {
	commonConfig
	Upstream    string
	Bind        string
	URLHeader   string
	PathPattern string
	WebSocket   bool
	VPN         bool
}

func NewClient(localaddr string, config *ClientConfig) error {
	config.check()

	//tr := *http.DefaultTransport.(*http.Transport)
	//tr.MaxConnsPerHost = 100
	//http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
	//	switch {
	//	case config.KCP:
	//		return kcp.Dial(address)
	//	case config.VPN:
	//		return vpnDial(address)
	//	default:
	//		conn, err := net.Dial(network, address)
	//		Vprint(conn.Write([]byte("POST /1.txt HTTP/1.1\r\nHost: toh22.test.upcdn.net:80\r\nContent-Length: 2\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: curl/7.54.0\r\n\r\n\x01\x02")))
	//		Vprint(conn)
	//		return conn, err
	//	}
	//}

	dialer := toh.NewDialer(config.Key, config.Upstream,
		toh.WithWebSocket(config.WebSocket),
		toh.WithInactiveTimeout(config.Timeout),
		// toh.WithTransport(&tr),
		toh.WithMaxWriteBuffer(int(config.WriteBuffer)),
		toh.WithHeader(config.URLHeader))

	mux, err := net.Listen("tcp", localaddr)
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

			var up net.Conn
			var err error

			if config.KCP {
				up, err = kcp.Dial(config.Upstream)
			} else {
				up, err = dialer.Dial()
			}

			if err != nil {
				Vprint("dial server: ", err)
				return
			}
			defer up.Close()

			upconn := toh.NewBufConn(up)
			if _, err := upconn.Write([]byte(config.Bind + "\n")); err != nil {
				Vprint("failed to req: ", err)
				return
			}

			resp, err := upconn.ReadBytes('\n')
			if err != nil || string(resp) != "OK\n" {
				Vprint("server failed to ack: ", err, ", resp: ", string(resp))
				return
			}

			Bridge(upconn, downconn, nil, config.Stat)
		}(conn)
	}
}
