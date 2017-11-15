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
	uotMagic = byte(0x07)
)

type udp_tcp_conn_t struct {
	Conn net.Conn
	Hits int64
	Born int64
}

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
		}
		return "[" + a.ip.String() + "]"
	}

	if strings.Contains(a.host, ":") && a.host[0] != '[' {
		return "[" + a.host + "]"
	}
	return a.host
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
			logg.E(socksReadErr, err)
			return 0x0, nil, false
		}
	}

	if typeBuf[0] != socksVersion5 && !omitCheck {
		logg.E(socksVersionErr)
		return 0x0, nil, false
	}

	if typeBuf[1] != 0x01 && typeBuf[1] != 0x03 && !omitCheck { // 0x01: establish a TCP/IP stream connection
		logg.E("socks5 invalid command: ", typeBuf[1])
		return 0x0, nil, false
	}

	addr := &addr_t{}
	switch typeBuf[3] {
	case socksAddrIPv4:
		addr.size = 3 + 1 + net.IPv4len + 2
	case socksAddrIPv6:
		addr.size = 3 + 1 + net.IPv6len + 2
	case socksAddrDomain:
		addr.size = 3 + 1 + 1 + int(typeBuf[4]) + 2
	default:
		logg.E("socks5 invalid address type")
		return 0x0, nil, false
	}

	if conn != nil {
		if _, err = io.ReadFull(conn, typeBuf[n:addr.size]); err != nil {
			logg.E(socksReadErr, err)
			return 0x0, nil, false
		}
	} else {
		if len(typeBuf) < addr.size {
			logg.E(socksReadErr, err)
			return 0x0, nil, false
		}
	}

	rawaddr := typeBuf[3 : addr.size-2]
	addr.port = int(binary.BigEndian.Uint16(typeBuf[addr.size-2 : addr.size]))

	switch typeBuf[3] {
	case socksAddrIPv4:
		addr.ip = net.IP(rawaddr[1:])
	case socksAddrIPv6:
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
					logg.E(socksReadErr, err)
				}
				return false
			}

			return true
		}

		c.SetReadDeadline(time.Now().Add(timeoutTCP))
		if !tryRead(xbuf, 2) {
			return "", nil
		}

		if xbuf[0] != uotMagic {
			return "", nil
		}

		authlen := int(xbuf[1])
		if authlen > 0 {
			authdata := make([]byte, authlen)
			if !tryRead(authdata, authlen) {
				return "", nil
			}

			if !proxy.auth(string(proxy.Cipher.Decrypt(authdata))) {
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

		host := string(proxy.Cipher.Decrypt(hostbuf[:hostlen-4]))
		port := int(binary.BigEndian.Uint16(hostbuf[hostlen-4 : hostlen-2]))
		host = host + ":" + strconv.Itoa(port)

		payloadlen := int(binary.BigEndian.Uint16(hostbuf[hostlen-2:]))
		payload := make([]byte, payloadlen)

		if !tryRead(payload, payloadlen) {
			return "", nil
		}

		payload = proxy.Cipher.Decrypt(payload)
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

	rconn.SetWriteDeadline(time.Now().Add(timeoutUDP))
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
					rconn.SetWriteDeadline(time.Now().Add(timeoutUDP))
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
		rconn.SetReadDeadline(time.Now().Add(timeoutUDP))
		n, _, err := rconn.ReadFrom(buf)
		// logg.L(n, ad.String(), err)

		if n > 0 {
			ybuf := proxy.Cipher.Encrypt(buf[:n])
			payload := append([]byte{uotMagic, 0, 0}, ybuf...)
			binary.BigEndian.PutUint16(payload[1:3], uint16(len(ybuf)))

			c.SetWriteDeadline(time.Now().Add(timeoutUDP))
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

func (proxy *ProxyClient) dialForUDP(client net.Addr, dst string) (net.Conn, string, bool, bool) {
	proxy.UDP.Lock()
	defer proxy.UDP.Unlock()

	if proxy.UDP.Conns == nil {
		proxy.UDP.Conns = make(map[string]*udp_tcp_conn_t)
	}

	if proxy.UDP.Addrs == nil {
		proxy.UDP.Addrs = make(map[net.Addr]bool)
	}

	str := client.String() + "-" + dst + "-" + strconv.Itoa(proxy.Cipher.Rand.Intn(proxy.UDPRelayCoconn))
	if conn, ok := proxy.UDP.Conns[str]; ok {
		conn.Hits++
		return conn.Conn, str, false, proxy.UDP.Addrs[client]
	}

	u, _, _ := net.SplitHostPort(proxy.Upstream)
	flag := proxy.UDP.Addrs[client]
	upstreamConn, err := net.DialTimeout("tcp", u+":"+strconv.Itoa(proxy.UDPRelayPort), 2*time.Second)
	if err != nil {
		logg.E(err)
		return nil, "", false, flag
	}

	proxy.UDP.Addrs[client] = true
	proxy.UDP.Conns[str] = &udp_tcp_conn_t{upstreamConn, 0, time.Now().UnixNano()}
	return upstreamConn, str, true, flag
}

func (proxy *ProxyClient) handleUDPtoTCP(b []byte, relay *net.UDPConn, client net.Conn, src net.Addr) {
	_, dst, ok := parseDstFrom(nil, b, true)
	if !ok {
		relay.Close()
		client.Close()
		return
	}

	upstreamConn, token, firstTime, srcAddrInUse := proxy.dialForUDP(src, dst.String())
	if upstreamConn == nil {
		if !srcAddrInUse {
			// if it is the first time we were trying to create a upstream conn
			// and an error occurred, we should close the relay listener
			// but if it isn't, we cannot close it because another goroutine
			// may use it, let that goroutine closes it.
			relay.Close()
		}
		client.Close()
		return
	}

	// prepare the payload
	buf := proxy.Cipher.Encrypt(b[dst.size:])

	// i know it's better to encrypt ip bytes (4 or 16 + 2 bytes port) rather than
	// string representation (like "100.200.300.400:56789", that is 21 bytes!)
	// but this is one time payload, it's fine, easy.
	enchost := proxy.Cipher.Encrypt([]byte(dst.HostString()))

	var encauth []byte
	var authlen = 0

	if proxy.UserAuth != "" {
		encauth = proxy.Cipher.Encrypt([]byte(proxy.UserAuth))
		authlen = len(encauth)
	}

	//                                   +----len---+              +-------------- hostlen -------------+
	// | 0x07 (1b header) | authlen (1b) | authdata | hostlen (1b) | host | port (2b) | payloadlen (2b) |

	payload := make([]byte, 1+1+authlen+1+len(enchost)+2+2+len(buf))

	payload[0] = uotMagic

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
			upstreamConn.SetReadDeadline(time.Now().Add(timeoutTCP))

			if _, err := io.ReadAtLeast(upstreamConn, xbuf, 3); err != nil {
				if err != io.EOF && derr(err) {
					logg.E(socksReadErr, err)
				}

				return nil
			}

			payloadlen := int(binary.BigEndian.Uint16(xbuf[1:3]))
			payload := make([]byte, payloadlen)
			if _, err := io.ReadAtLeast(upstreamConn, payload, payloadlen); err != nil {
				if derr(err) {
					logg.E(socksReadErr, err)
				}
				return nil
			}

			return proxy.Cipher.Decrypt(payload)
		}

		// read from upstream
		buf := readFromTCP()

		if buf != nil && len(buf) > 0 {
			logg.D("utt receive: ", len(buf))

			var err error
			var ln int
			// prepare the response header
			if len(dst.ip) == net.IPv4len {
				copy(xbuf, udpHeaderIPv4)
				copy(xbuf[4:8], dst.ip)
				binary.BigEndian.PutUint16(xbuf[8:], uint16(dst.port))
				copy(xbuf[len(udpHeaderIPv4):], buf)

				ln = len(buf) + len(udpHeaderIPv4)
			} else {
				copy(xbuf, udpHeaderIPv6)
				copy(xbuf[4:20], dst.ip)
				binary.BigEndian.PutUint16(xbuf[20:], uint16(dst.port))
				copy(xbuf[len(udpHeaderIPv6):], buf)

				ln = len(buf) + len(udpHeaderIPv6)
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

	proxy.UDP.Lock()
	delete(proxy.UDP.Conns, token)
	delete(proxy.UDP.Addrs, src)
	proxy.UDP.Unlock()

	upstreamConn.Close()
	client.Close()
	relay.Close()
}
