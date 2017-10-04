package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"

	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	UOT_HEADER = byte(0x07)
)

type addr_t struct {
	ip   net.IP
	host string
	port int
	size int
}

func (a *addr_t) String() string {
	return a.HostString() + ":" + strconv.Itoa(a.port)
}

func (a *addr_t) HostString() string {
	if a.ip != nil {
		if len(a.ip) == net.IPv4len {
			return a.ip.String()
		} else {
			return "[" + a.ip.String() + "]"
		}
	} else {
		if strings.Contains(a.host, ":") && a.host[0] != '[' {
			return "[" + a.host + "]"
		} else {
			return a.host
		}
	}
}

func (a *addr_t) IP() net.IP {
	if a.ip != nil {
		return a.ip
	}

	ip, err := net.ResolveIPAddr("ip", a.host)
	if err != nil {
		return nil
	}

	return ip.IP
}

func (a *addr_t) IsAllZeros() bool {
	if a.ip != nil {
		return a.ip.IsUnspecified() && a.port == 0
	}

	return false
}

func parseDstFrom(conn net.Conn, typeBuf []byte, omitCheck bool) (byte, *addr_t, bool) {
	var err error
	var n int

	if typeBuf == nil {
		typeBuf, n = make([]byte, 256+3+1+1+2), 0
		// conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		if n, err = io.ReadAtLeast(conn, typeBuf, 3+1+net.IPv4len+2); err != nil {
			logg.E(CANNOT_READ_BUF, err)
			return 0x0, nil, false
		}
	}

	if typeBuf[0] != SOCKS5_VERSION && !omitCheck {
		logg.E(NOT_SOCKS5)
		return 0x0, nil, false
	}

	if typeBuf[1] != 0x01 && typeBuf[1] != 0x03 && !omitCheck { // 0x01: establish a TCP/IP stream connection
		logg.E("socks5 invalid command: ", typeBuf[1])
		return 0x0, nil, false
	}

	addr := &addr_t{}
	switch typeBuf[3] {
	case SOCKS_TYPE_IPv4:
		addr.size = 3 + 1 + net.IPv4len + 2
	case SOCKS_TYPE_IPv6:
		addr.size = 3 + 1 + net.IPv6len + 2
	case SOCKS_TYPE_Dm:
		addr.size = 3 + 1 + 1 + int(typeBuf[4]) + 2
	default:
		logg.E("socks5 invalid address type")
		return 0x0, nil, false
	}

	if conn != nil {
		if _, err = io.ReadFull(conn, typeBuf[n:addr.size]); err != nil {
			logg.E(CANNOT_READ_BUF, err)
			return 0x0, nil, false
		}
	} else {
		if len(typeBuf) < addr.size {
			logg.E(CANNOT_READ_BUF, err)
			return 0x0, nil, false
		}
	}

	rawaddr := typeBuf[3 : addr.size-2]
	addr.port = int(binary.BigEndian.Uint16(typeBuf[addr.size-2 : addr.size]))

	switch typeBuf[3] {
	case SOCKS_TYPE_IPv4:
		addr.ip = net.IP(rawaddr[1:])
	case SOCKS_TYPE_IPv6:
		addr.ip = net.IP(rawaddr[1:])
	default:
		addr.host = string(rawaddr[2:])
	}

	return typeBuf[1], addr, true
}

func derr(err error) bool {
	if ne, ok := err.(net.Error); ok {
		if ne.Timeout() {
			return false
		}
	}

	return true
}

func (proxy *ProxyUpstream) handleTCPtoUDP(c net.Conn) {
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
			logg.E("ttu: invalid hostlen")
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
		logg.E(err)
		return
	}

	rconn.SetWriteDeadline(time.Now().Add(time.Duration(UDP_TIMEOUT) * time.Second))
	if _, err := rconn.Write(payload); err != nil {
		if derr(err) {
			logg.E("ttu: write to target: ", err)
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
							logg.E("ttu: write to target: ", err)
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
					logg.E("ttu: write to downstream: ", err)
				}

				break
			}
		}

		if err != nil {
			if derr(err) {
				logg.E("ttu: readfrom: ", err)
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
		logg.E(err)
		return nil, "", false
	}

	proxy.udp.upstream.conns[str] = upstreamConn
	return upstreamConn, str, true
}

func (proxy *ProxyClient) handleUDPtoTCP(b []byte, relay *net.UDPConn, client net.Conn, auth string, src net.Addr) {
	_, dst, ok := parseDstFrom(nil, b, true)
	if !ok {
		return
	}

	upstreamConn, token, firstTime := proxy.dialForUDP(src, dst.String())
	if upstreamConn == nil {
		return
	}

	// prepare the payload
	buf := proxy.GCipher.Encrypt(b[dst.size:])

	// i know it's better to encrypt ip bytes (4 or 16 + 2 bytes port) rather than
	// string representation (like "100.200.300.400:56789", that is 21 bytes!)
	// but this is one time payload, it's fine, easy.
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
			logg.D("utt receive: ", len(buf))

			var err error
			var ln int
			// prepare the response header
			if len(dst.ip) == net.IPv4len {
				copy(xbuf, UDP_REQUEST_HEADER)
				copy(xbuf[4:8], dst.ip)
				binary.BigEndian.PutUint16(xbuf[8:], uint16(dst.port))
				copy(xbuf[len(UDP_REQUEST_HEADER):], buf)

				ln = len(buf) + len(UDP_REQUEST_HEADER)
			} else {
				copy(xbuf, UDP_REQUEST_HEADER6)
				copy(xbuf[4:20], dst.ip)
				binary.BigEndian.PutUint16(xbuf[20:], uint16(dst.port))
				copy(xbuf[len(UDP_REQUEST_HEADER6):], buf)

				ln = len(buf) + len(UDP_REQUEST_HEADER6)
			}

			_, err = relay.WriteTo(xbuf[:ln], src)

			if err != nil {
				logg.E("utt: write: ", err)
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
	client.Close()
	relay.Close()
	logg.D("udp close: ", client)
}
