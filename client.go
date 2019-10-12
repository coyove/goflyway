package goflyway

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/coyove/goflyway/toh"
	"github.com/coyove/goflyway/v"

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
	Dynamic     bool
}

func NewClient(localaddr string, config *ClientConfig) error {
	config.check()

	tr := *http.DefaultTransport.(*http.Transport)
	if config.VPN {
		tr.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
			return vpnDial(address)
		}
	}

	dialer := toh.NewDialer(config.Key, config.Upstream,
		toh.WithWebSocket(config.WebSocket),
		toh.WithInactiveTimeout(config.Timeout),
		toh.WithTransport(&tr),
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

			var bind = config.Bind

			if config.Dynamic {
				dst, err := handleSOCKS5(downconn)
				if err != nil {
					v.Eprint("SOCKS5 server error: ", err)
					return
				}
				bind = dst
				v.Vprint("SOCKS5 destination: ", dst)
			}

			up, err := dialer.Dial()

			if err != nil {
				v.Eprint("dial server: ", err)
				return
			}
			defer up.Close()

			upconn := toh.NewBufConn(up)
			if _, err := upconn.Write([]byte(bind + "\n")); err != nil {
				v.Eprint("failed to req: ", err)
				return
			}

			resp, err := upconn.ReadBytes('\n')
			if err != nil || string(resp) != "OK\n" {
				v.Eprint("server failed to ack: ", err, ", resp: ", string(resp))
				return
			}

			if config.Dynamic {
				// SOCKS5 OK response
				downconn.Write([]byte{0x05, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			}

			Bridge(upconn, downconn, nil, config.Stat)
		}(conn)
	}
}

func handleSOCKS5(conn net.Conn) (string, error) {
	buf := make([]byte, 256)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", fmt.Errorf("failed to read header: %v", err)
	}

	if buf[0] != 0x05 {
		return "", fmt.Errorf("unsupported SOCKS version: %v", buf[0])
	}

	numMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:numMethods]); err != nil {
		return "", fmt.Errorf("failed to read methods: %v", err)
	}

	if numMethods > 1 {
		v.VVVprint("client supported methods: ", buf[:numMethods])
	}

	// TODO: auth
	if _, err := conn.Write([]byte{0x05, 0}); err != nil {
		return "", fmt.Errorf("failed to handshake: %v", err)
	}

	// read destination
	_, err := io.ReadFull(conn, buf[:3+1])
	if err != nil {
		return "", fmt.Errorf("failed to read destination: %v", err)
	}

	var addrsize int
	var method = buf[3]

	switch method {
	case 0x01:
		addrsize = net.IPv4len + 2
	case 0x04:
		addrsize = net.IPv6len + 2
	case 0x03:
		// read one extra byte that indicates the length of the domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", fmt.Errorf("failed to read domain destination: %v", err)
		}
		addrsize = int(buf[0]) + 2
	default:
		return "", fmt.Errorf("invalid address type: %v", buf[3])
	}

	if _, err = io.ReadFull(conn, buf[:addrsize]); err != nil {
		return "", fmt.Errorf("failed to read destination: %v", err)
	}

	var host string
	var port = strconv.Itoa(int(binary.BigEndian.Uint16(buf[addrsize-2 : addrsize])))

	switch method {
	case 0x01, 0x04:
		host = net.IP(buf[:addrsize-2]).String()
	default:
		host = string(buf[:addrsize-2])
	}

	if strings.Contains(host, ":") {
		// IPv6?
		host = "[" + host + "]"
	}

	return host + ":" + port, nil
}
