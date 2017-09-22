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

		tryRead := func(buf []byte, min int) bool {
			if _, err := io.ReadAtLeast(c, buf, min); err != nil {
				if derr(err) {
					logg.E(CANNOT_READ_BUF, err)
				}
				return false
			}

			return true
		}

		c.SetReadDeadline(time.Now().Add(time.Duration(TCP_TIMEOUT) * time.Second))
		if !tryRead(xbuf, 2) {
			return "", nil
		}

		if xbuf[0] != UOT_HEADER {
			return "", nil
		}

		authlen := int(xbuf[1])
		if authlen > 0 {
			authdata := make([]byte, authlen)
			if !tryRead(authdata, authlen) {
				return "", nil
			}

			if !proxy.auth(string(proxy.GCipher.Decrypt(authdata))) {
				return "", nil
			}
		} else if proxy.Users != nil {
			return "", nil
		}

		if !tryRead(xbuf[:1], 1) {
			return "", nil
		}

		hostlen := int(xbuf[0])
		hostbuf := make([]byte, hostlen)

		if !tryRead(hostbuf, hostlen) {
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

		if !tryRead(payload, payloadlen) {
			return "", nil
		}

		payload = proxy.GCipher.Decrypt(payload)
		return host, payload
	}

	host, payload := readFromTCP()
	if payload == nil || host == "" {
		return
	}

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

func (proxy *ProxyClient) HandleUDPtoTCP(b []byte, auth string, src net.Addr) {
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

	var encauth []byte
	var authlen = 0

	if auth != "" {
		encauth = proxy.GCipher.Encrypt([]byte(auth))
		authlen = len(encauth)
	}

	//                                   +----len---+              +-------------- hostlen -------------+
	// | 0x07 (1b header) | authlen (1b) | authdata | hostlen (1b) | host | port (2b) | payloadlen (2b) |

	payload := make([]byte, 1+1+authlen+1+len(enchost)+2+2+len(buf))

	payload[0] = UOT_HEADER

	payload[1] = byte(authlen)
	if encauth != nil {
		copy(payload[2:], encauth)
	}

	payload[2+authlen] = byte(len(enchost) + 2 + 2)

	copy(payload[2+authlen+1:], enchost)

	binary.BigEndian.PutUint16(payload[2+authlen+1+len(enchost):], uint16(dst.port))
	binary.BigEndian.PutUint16(payload[2+authlen+1+len(enchost)+2:], uint16(len(buf)))

	copy(payload[2+authlen+1+len(enchost)+2+2:], buf)

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
				// prepare the response header
				if len(dst.ip) == net.IPv4len {
					copy(xbuf, UDP_REQUEST_HEADER)
					copy(xbuf[4:8], dst.ip)
					binary.BigEndian.PutUint16(xbuf[8:], uint16(dst.port))
					copy(xbuf[len(UDP_REQUEST_HEADER):], buf)
				} else {
					copy(xbuf, UDP_REQUEST_HEADER6)
					copy(xbuf[4:20], dst.ip)
					binary.BigEndian.PutUint16(xbuf[20:], uint16(dst.port))
					copy(xbuf[len(UDP_REQUEST_HEADER6):], buf)
				}

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
