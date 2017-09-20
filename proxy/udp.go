package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"

	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	UOT_HEADER = byte(0x07)
)

func derr(err error) bool {
	if ne, ok := err.(net.Error); ok {
		if ne.Timeout() {
			return false
		}
	}

	return true
}

func (proxy *ProxyUpstream) HandleTCPtoUDP(c net.Conn) {
	defer c.Close()

	readFromTCP := func() (string, []byte) {
		xbuf := make([]byte, 2)

		c.SetReadDeadline(time.Now().Add(time.Duration(TCP_TIMEOUT) * time.Second))
		if _, err := io.ReadAtLeast(c, xbuf, 2); err != nil {
			if derr(err) {
				logg.E(CANNOT_READ_BUF, err)
			}
			return "", nil
		}

		hostlen := int(xbuf[1])
		hostbuf := make([]byte, hostlen)

		if _, err := io.ReadAtLeast(c, hostbuf, hostlen); err != nil {
			if derr(err) {
				logg.E(CANNOT_READ_BUF, err)
			}
			return "", nil
		}

		if hostlen < 4 {
			logg.E("[TtU] invalid hostlen")
			return "", nil
		}

		host := string(proxy.GCipher.Decrypt(hostbuf[:hostlen-4]))
		port := int(binary.BigEndian.Uint16(hostbuf[hostlen-4 : hostlen-2]))
		host = host + ":" + strconv.Itoa(port)

		payloadlen := int(binary.BigEndian.Uint16(hostbuf[hostlen-2:]))
		payload := make([]byte, payloadlen)

		if _, err := io.ReadAtLeast(c, payload, payloadlen); err != nil {
			if derr(err) {
				logg.E(CANNOT_READ_BUF, err)
			}
			return "", nil
		}

		payload = proxy.GCipher.Decrypt(payload)
		return host, payload
	}

	host, payload := readFromTCP()

	uaddr, _ := net.ResolveUDPAddr("udp", host)
	rconn, err := net.DialUDP("udp", nil, uaddr)
	if err != nil {
		logg.E("[UDP] dial - ", err)
		return
	}

	rconn.SetWriteDeadline(time.Now().Add(time.Duration(UDP_TIMEOUT) * time.Second))
	if _, err := rconn.Write(payload); err != nil {
		if derr(err) {
			logg.E("[TtU] write to target - ", err)
		}
		return
	}

	quit := make(chan bool)
	go func() { // goroutine: read from downstream tcp, write to target host udp
	READ:
		for {
			select {
			case <-quit:
				break READ
			default:
				if _, buf := readFromTCP(); buf != nil {
					rconn.SetWriteDeadline(time.Now().Add(time.Duration(UDP_TIMEOUT) * time.Second))
					if _, err := rconn.Write(buf); err != nil {
						if derr(err) {
							logg.E("[TtU] write to target - ", err)
						}
						break READ
					}
				} else {
					break READ
				}
			}
		}

		c.Close()     // may double-close, but fine
		rconn.Close() // may double-close, but fine
	}()

	buf := make([]byte, 2048)
	for { // read from target host udp, write to downstream tcp
		rconn.SetReadDeadline(time.Now().Add(time.Duration(UDP_TIMEOUT) * time.Second))
		n, _, err := rconn.ReadFrom(buf)
		// logg.L(n, ad.String(), err)

		if n > 0 {
			ybuf := proxy.GCipher.Encrypt(buf[:n])
			payload := append([]byte{UOT_HEADER, 0, 0}, ybuf...)
			binary.BigEndian.PutUint16(payload[1:3], uint16(len(ybuf)))

			c.SetWriteDeadline(time.Now().Add(time.Duration(UDP_TIMEOUT) * time.Second))
			_, err := c.Write(payload)
			if err != nil {
				if derr(err) {
					logg.E("[TtU] write to downstream - ", err)
				}

				break
			}
		}

		if err != nil {
			if derr(err) {
				logg.E("[TtU] readfrom - ", err)
			}

			break
		}
	}

	quit <- true
	rconn.Close()
}

func (proxy *ProxyClient) dialForUDP(client net.Addr, dst string) (net.Conn, string, bool) {
	proxy.udp.upstream.Lock()
	defer proxy.udp.upstream.Unlock()

	if proxy.udp.upstream.conns == nil {
		proxy.udp.upstream.conns = make(map[string]net.Conn)
	}

	str := client.String() + "-" + dst + "-" + strconv.Itoa(proxy.GCipher.Rand.Intn(proxy.UDPRelayCoconn))
	if conn, ok := proxy.udp.upstream.conns[str]; ok {
		return conn, str, false
	}

	u, _, _ := net.SplitHostPort(proxy.Upstream)
	upstreamConn, err := net.Dial("tcp", u+":"+strconv.Itoa(proxy.UDPRelayPort))
	if err != nil {
		logg.E("[UPSTREAM] udp - ", err)
		return nil, "", false
	}

	proxy.udp.upstream.conns[str] = upstreamConn
	return upstreamConn, str, true
}

func (proxy *ProxyClient) HandleUDPtoTCP(b []byte, src net.Addr) {
	_, dst, ok := ParseDstFrom(nil, b, true)
	if !ok {
		return
	}

	upstreamConn, token, firstTime := proxy.dialForUDP(src, dst.String())
	if upstreamConn == nil {
		return
	}

	// prepare the payload
	buf := proxy.GCipher.Encrypt(b[dst.size:])
	enchost := proxy.GCipher.Encrypt([]byte(dst.HostString()))

	//                                   +-------------- hostlen -------------+
	// | 0x07 (1b header) | hostlen (1b) | host | port (2b) | payloadlen (2b) |
	payload := make([]byte, 2+len(enchost)+2+2+len(buf))

	payload[0], payload[1] = UOT_HEADER, byte(len(enchost)+2+2)

	copy(payload[2:], enchost)

	binary.BigEndian.PutUint16(payload[2+len(enchost):], uint16(dst.port))
	binary.BigEndian.PutUint16(payload[2+len(enchost)+2:], uint16(len(buf)))

	copy(payload[2+len(enchost)+2+2:], buf)

	upstreamConn.Write(payload)

	if !firstTime {
		// we are not the first one using this connection, so just return here
		return
	}

	xbuf := make([]byte, 2048)
	for {
		readFromTCP := func() []byte {
			xbuf := make([]byte, 3)
			upstreamConn.SetReadDeadline(time.Now().Add(time.Duration(TCP_TIMEOUT) * time.Second))

			if _, err := io.ReadAtLeast(upstreamConn, xbuf, 3); err != nil {
				if err != io.EOF && derr(err) {
					logg.E(CANNOT_READ_BUF, err)
				}

				return nil
			}

			payloadlen := int(binary.BigEndian.Uint16(xbuf[1:3]))
			payload := make([]byte, payloadlen)
			if _, err := io.ReadAtLeast(upstreamConn, payload, payloadlen); err != nil {
				if derr(err) {
					logg.E(CANNOT_READ_BUF, err)
				}
				return nil
			}

			return proxy.GCipher.Decrypt(payload)
		}

		// read from upstream
		buf := readFromTCP()

		if buf != nil && len(buf) > 0 {
			logg.D("[UtT] receive - ", len(buf))

			var err error

			if proxy.UDPRelayNoHdr {
				_, err = proxy.udp.relay.WriteTo(buf, src)
			} else {
				copy(xbuf, UDP_REQUEST_HEADER)
				copy(xbuf[len(UDP_REQUEST_HEADER):], buf)

				_, err = proxy.udp.relay.WriteTo(xbuf[:len(buf)+len(UDP_REQUEST_HEADER)], src)
			}

			if err != nil {
				logg.E("[UtT] write - ", err)
				break
			}
		} else {
			break
		}
	}

	proxy.udp.upstream.Lock()
	delete(proxy.udp.upstream.conns, token)
	proxy.udp.upstream.Unlock()

	upstreamConn.Close()
}
