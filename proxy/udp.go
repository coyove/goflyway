package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"

	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	UOT_HEADER = byte(0x07)
)

func (proxy *ProxyUpstream) HandleTCPtoUDP(c net.Conn) {
	defer c.Close()

	readFromTCP := func() (string, []byte) {
		xbuf := make([]byte, 2)
		if _, err := io.ReadAtLeast(c, xbuf, 2); err != nil {
			logg.E(CANNOT_READ_BUF, err)
			return "", nil
		}

		hostlen := int(xbuf[1])
		hostbuf := make([]byte, hostlen)

		if _, err := io.ReadAtLeast(c, hostbuf, hostlen); err != nil {
			logg.E(CANNOT_READ_BUF, err)
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
			logg.E(CANNOT_READ_BUF, err)
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

	if _, err := rconn.Write(payload); err != nil {
		logg.E("[TtU] write - ", err)
		return
	}

	quit := make(chan bool)
	go func() {
		for {
			select {
			case <-quit:
				return
			default:
				if _, buf := readFromTCP(); buf != nil {
					rconn.Write(buf)
				} else {
					return
				}
			}
		}
	}()

	buf := make([]byte, 2048)
	for {

		rconn.SetReadDeadline(time.Now().Add(time.Duration(UDP_READ_TIMEOUT) * time.Second))
		n, _, err := rconn.ReadFrom(buf)
		// logg.L(n, ad.String(), err)

		if n > 0 {
			ybuf := proxy.GCipher.Encrypt(buf[:n])
			payload := append([]byte{UOT_HEADER, 0, 0}, ybuf...)
			binary.BigEndian.PutUint16(payload[1:3], uint16(len(ybuf)))

			_, err := c.Write(payload)
			if err != nil {
				logg.E("[TtU] - ", err)
				break
			}
		}

		if err != nil {
			if !err.(net.Error).Timeout() {
				logg.E("[TtU] - ", err)
			}

			break
		}
	}

	quit <- true
	rconn.Close()
}

type upstreamConnState struct {
	sync.Mutex
	conns map[string]net.Conn
}

func (s *upstreamConnState) dial(client net.Addr, dst, upstream string) (net.Conn, bool) {
	s.Lock()
	defer s.Unlock()

	if s.conns == nil {
		s.conns = make(map[string]net.Conn)
	}

	str := client.String() + ":" + dst //src.String()
	if conn, ok := s.conns[str]; ok {
		return conn, false
	}

	upstreamConn, err := net.Dial("tcp", upstream) //u+":"+strconv.Itoa(proxy.UDPRelayPort))
	if err != nil {
		logg.E("[UPSTREAM] udp - ", err)
		return nil, false
	}

	s.conns[str] = upstreamConn
	return upstreamConn, true
}

func (s *upstreamConnState) remove(src string) {
	s.Lock()
	defer s.Unlock()

	delete(s.conns, src)
}

var connsMgr upstreamConnState

func (proxy *ProxyClient) HandleUDPtoTCP(b []byte, src net.Addr) {
	_, dst, ok := ParseDstFrom(nil, b, true)
	if !ok {
		return
	}

	u, _, _ := net.SplitHostPort(proxy.Upstream)
	upstreamConn, firstTime := connsMgr.dial(src, dst.String(), u+":"+strconv.Itoa(proxy.UDPRelayPort))
	if upstreamConn == nil {
		return
	}

	// logg.L(b[dst.size:])
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
		return
	}

	xbuf := make([]byte, 2048)
	for {
		readFromTCP := func() []byte {
			xbuf := make([]byte, 3)
			if _, err := io.ReadAtLeast(upstreamConn, xbuf, 3); err != nil {
				if err != io.EOF {
					logg.E(CANNOT_READ_BUF, err)
				}

				return nil
			}

			payloadlen := int(binary.BigEndian.Uint16(xbuf[1:3]))
			payload := make([]byte, payloadlen)
			if _, err := io.ReadAtLeast(upstreamConn, payload, payloadlen); err != nil {
				logg.E(CANNOT_READ_BUF, err)
				return nil
			}

			return proxy.GCipher.Decrypt(payload)
		}

		// n, err := upstreamConn.Read(buf)
		buf := readFromTCP()

		if buf != nil && len(buf) > 0 {
			logg.L("[UtT] receive - ", len(buf))

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

	connsMgr.remove(src.String() + ":" + dst.String())
	upstreamConn.Close()
}
