package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"

	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"
)

func (proxy *ProxyUpstream) HandleTCPtoUDP(c net.Conn) {
	defer c.Close()

	xbuf := make([]byte, 2)
	if _, err := io.ReadAtLeast(c, xbuf, 2); err != nil {
		logg.E(CANNOT_READ_BUF, err)
		return
	}

	hostlen := int(xbuf[1])
	hostbuf := make([]byte, hostlen)

	if _, err := io.ReadAtLeast(c, hostbuf, hostlen); err != nil {
		logg.E(CANNOT_READ_BUF, err)
		return
	}

	if hostlen < 4 {
		logg.E("invalid hostlen")
		return
	}

	host := string(proxy.GCipher.Decrypt(hostbuf[:hostlen-4]))
	port := int(binary.BigEndian.Uint16(hostbuf[hostlen-4 : hostlen-2]))
	host = host + ":" + strconv.Itoa(port)

	payloadlen := int(binary.BigEndian.Uint16(hostbuf[hostlen-2:]))
	payload := make([]byte, payloadlen)

	if _, err := io.ReadAtLeast(c, payload, payloadlen); err != nil {
		logg.E(CANNOT_READ_BUF, err)
		return
	}

	payload = proxy.GCipher.Decrypt(payload)

	uaddr, _ := net.ResolveUDPAddr("udp", host)
	logg.L("dial ", host)
	rconn, err := net.DialUDP("udp", nil, uaddr)
	if err != nil {
		logg.E("[DIAL UDP] - ", err)
		return
	}

	rconn.Write(payload)

	buf := make([]byte, 2048)
	copy(buf, UDP_REQUEST_HEADER)
	xbuf = buf[len(UDP_REQUEST_HEADER):]

	for {
		rconn.SetReadDeadline(time.Now().Add(time.Duration(UDP_READ_TIMEOUT) * time.Second))
		n, err := rconn.Read(xbuf)

		if n > 0 {
			_, err := c.Write(buf[:n+len(UDP_REQUEST_HEADER)])
			if err != nil {
				logg.E("[TtU] - ", err)
				break
			}
		}

		if err != nil {
			if !err.(*net.OpError).Timeout() {
				logg.E("[TtU] - ", err)
			}
			break
		}
	}

	rconn.Close()

}

func (proxy *ProxyClient) HandleUDPtoTCP(b []byte, src net.Addr) {
	_, dst, _ := ParseDstFrom(nil, b, true)
	u, _, _ := net.SplitHostPort(proxy.Upstream)

	upstreamConn, err := net.Dial("tcp", u+":"+strconv.Itoa(proxy.UDPRelayPort))
	if err != nil {
		logg.E("[UPSTREAM] - ", err)
		return
	}

	go func() {
		buf := make([]byte, 2048)

		for {
			n, err := upstreamConn.Read(buf)
			if n > 0 {
				proxy.udp.relay.WriteTo(buf[:n], src)
			}

			if err != nil {
				if err != io.EOF { //&& !err.(*net.OpError).Timeout() {
					logg.E("[UtT] - ", err)
				}

				break
			}
		}

		logg.L("close ", src.String())
		upstreamConn.Close()
	}()

	buf := proxy.GCipher.Encrypt(b[dst.size:])

	hostbuf := append(proxy.GCipher.Encrypt([]byte(dst.HostString())), 0, 0, 0, 0)
	hostlen := len(hostbuf)

	//                                   +-------------- hostlen -------------+
	// | 0x07 (1b header) | hostlen (1b) | host | port (2b) | payloadlen (2b) |

	binary.BigEndian.PutUint16(hostbuf[hostlen-4:hostlen-2], uint16(dst.port))
	binary.BigEndian.PutUint16(hostbuf[hostlen-2:hostlen-0], uint16(len(buf)))

	upstreamConn.Write([]byte{0x07, byte(hostlen)})
	upstreamConn.Write(hostbuf)
	upstreamConn.Write(buf)

}
