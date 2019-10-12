package toh

import (
	"crypto/cipher"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
)

type WSConn struct {
	net.Conn
	mu   sync.Mutex
	blk  cipher.Block
	mask bool
	buf  []byte
}

func (c *WSConn) Write(p []byte) (int, error) {
	L := len(p)

	// TODO
	key := make([]byte, 12)
	rand.Read(key)

	gcm, _ := cipher.NewGCM(c.blk)

	p = gcm.Seal(p[:0], key, p, nil)
	p = append(p, key...)

	if _, err := wsWrite(c.Conn, p, c.mask); err != nil {
		return 0, err
	}
	return L, nil
}

func (c *WSConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

READ:
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	payload, _, err := wsRead(c.Conn)
	if err != nil {
		return 0, err
	}
	if len(payload) < 12 {
		return 0, fmt.Errorf("invalid websocket payload")
	}

	key := payload[len(payload)-12:]
	payload = payload[:len(payload)-12]

	gcm, _ := cipher.NewGCM(c.blk)

	payload, err = gcm.Open(payload[:0], key, payload, nil)
	if err != nil {
		return 0, err
	}

	c.buf = payload
	goto READ
}

func (d *Dialer) wsHandshake() (net.Conn, error) {
	var (
		host  = d.endpoint
		conn  net.Conn
		err   error
		https bool
	)

REDIR:
	if https {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: d.Timeout}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.DialTimeout("tcp", host, d.Timeout)
	}

	if err != nil {
		return nil, err
	}

	wsKey := [20]byte{}
	rand.Read(wsKey[:])

	header := "GET " + d.Path() + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(wsKey[:]) + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"

	if _, err := conn.Write([]byte(header)); err != nil {
		conn.Close()
		return nil, err
	}

	c := &WSConn{
		Conn: NewBufConn(conn),
		mask: true,
		blk:  d.blk,
	}

	resp, err := http.ReadResponse(c.Conn.(*BufConn).Reader, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		if host == d.endpoint {
			switch resp.StatusCode {
			case http.StatusMovedPermanently, http.StatusFound, http.StatusPermanentRedirect, http.StatusTemporaryRedirect:
				// TODO
				u, _ := url.Parse(resp.Header.Get("Location"))
				host, https = u.Host, u.Scheme == "https"

				if _, _, err := net.SplitHostPort(host); err != nil {
					if https {
						host += ":443"
					} else {
						host += ":80"
					}
				}
				goto REDIR
			}
		}
		return nil, fmt.Errorf("invalid websocket response: %v", resp.Status)
	}

	return c, nil
}

func (ln *Listener) wsHandShake(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	ans := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(ans[:]) + "\r\n\r\n")); err != nil {
		conn.Close()
		return nil, err
	}

	return &WSConn{Conn: conn, blk: ln.blk}, nil
}

// WSWrite and WSRead are simple implementations of RFC6455
// we assume that all payloads are 65535 bytes at max
// we don't care control frames and everything is binary
// we don't close it explicitly, it closes when the TCP connection closes
// we don't ping or pong
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-------+-+-------------+-------------------------------+
//   |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//   |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//   |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//   | |1|2|3|       |K|             |                               |
//   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//   |     Extended payload length continued, if payload len == 127  |
//   + - - - - - - - - - - - - - - - +-------------------------------+
//   |                               |Masking-key, if MASK set to 1  |
//   +-------------------------------+-------------------------------+
//   | Masking-key (continued)       |          Payload Data         |
//   +-------------------------------- - - - - - - - - - - - - - - - +
//   :                     Payload Data continued ...                :
//   + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//   |                     Payload Data continued ...                |
//   +---------------------------------------------------------------+
func wsWrite(dst io.Writer, payload []byte, mask bool) (n int, err error) {
	if len(payload) > 65535 {
		return 0, fmt.Errorf("don't support payload larger than 65535 yet")
	}

	buf := make([]byte, 4)
	buf[0] = 2 // binary
	buf[1] = 126
	binary.BigEndian.PutUint16(buf[2:], uint16(len(payload)))

	if mask {
		buf[1] |= 0x80
		buf = append(buf, 0, 0, 0, 0)
		key := rand.Uint32()
		binary.BigEndian.PutUint32(buf[4:8], key)

		for i, b := 0, buf[4:8]; i < len(payload); i++ {
			payload[i] ^= b[i%4]
		}
	}

	if n, err = dst.Write(buf); err != nil {
		return
	}

	return dst.Write(payload)
}

func wsRead(src io.Reader) (payload []byte, n int, err error) {
	buf := make([]byte, 4)
	if n, err = io.ReadAtLeast(src, buf[:2], 2); err != nil {
		return
	}

	if buf[0] != 2 {
		err = fmt.Errorf("invalid websocket opcode: %v", buf[0])
		return
	}

	mask := (buf[1] & 0x80) > 0
	ln := int(buf[1] & 0x7f)

	switch ln {
	case 126:
		if n, err = io.ReadAtLeast(src, buf[2:4], 2); err != nil {
			return
		}
		ln = int(binary.BigEndian.Uint16(buf[2:4]))
	case 127:
		err = fmt.Errorf("payload too large")
		return
	default:
	}

	if mask {
		if n, err = io.ReadAtLeast(src, buf[:4], 4); err != nil {
			return
		}
		// now buf contains mask key
	}

	payload = make([]byte, ln)
	if n, err = io.ReadAtLeast(src, payload, ln); err != nil {
		return
	}

	if mask {
		for i, b := 0, buf[:4]; i < len(payload); i++ {
			payload[i] ^= b[i%4]
		}
	}

	// n == ln, err == nil,
	return
}
