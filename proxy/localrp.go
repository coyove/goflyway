package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	localRPPingInterval = 1 * time.Second
	pingScale           = 10
)

var (
	pingSignal = make([]byte, 16)
)

type dummyConn struct {
	otr, mer io.Reader
	otw, mew io.Writer
}

type dummyConnWrapper struct {
	*dummyConn
}

func (d *dummyConn) Init() {
	d.otr, d.mew = io.Pipe()
	d.mer, d.otw = io.Pipe()
}

func (d *dummyConn) Read(b []byte) (n int, err error)         { return d.otr.Read(b) }
func (d *dummyConn) Write(b []byte) (n int, err error)        { return d.otw.Write(b) }
func (d *dummyConn) Close() error                             { return nil }
func (d *dummyConn) LocalAddr() net.Addr                      { return nil }
func (d *dummyConn) RemoteAddr() net.Addr                     { return nil }
func (d *dummyConn) SetDeadline(t time.Time) error            { return nil }
func (d *dummyConn) SetReadDeadline(t time.Time) error        { return nil }
func (d *dummyConn) SetWriteDeadline(t time.Time) error       { return nil }
func (d *dummyConn) readWritten(b []byte) (n int, err error)  { return d.mer.Read(b) }
func (d *dummyConn) writeForRead(b []byte) (n int, err error) { return d.mew.Write(b) }

func (d *dummyConnWrapper) Read(b []byte) (n int, err error) {
	ok := make(chan bool, 1)
	go func() {
		n, err = d.dummyConn.readWritten(b)
		ok <- true
	}()
	select {
	case <-ok:
		return
	case <-time.After(localRPPingInterval * pingScale):
		return 0, io.EOF
	}
}

func (d *dummyConnWrapper) Write(b []byte) (n int, err error) {
	ok := make(chan bool, 1)
	go func() {
		n, err = d.dummyConn.writeForRead(b)
		ok <- true
	}()
	select {
	case <-ok:
		return
	case <-time.After(localRPPingInterval * pingScale):
		return 0, io.EOF
	}
}

// StartLocalRP is a block call, it will never return
func (proxy *ProxyClient) StartLocalRP(n int) {
	for i := 0; i < n; i++ {
		go func() {
			for {
				proxy.startLocalRPClient()
			}
		}()
	}

	select {}
}

func (proxy *ProxyClient) startLocalRPClient() {
	const redo = 1

	for {
		conn := &dummyConn{}
		conn.Init()
		connw := &dummyConnWrapper{conn}
		signal := make(chan byte, 1)

		upstream, err := proxy.DialUpstream(conn, "localrp", nil, doLocalRP, 0)
		if err != nil {
			proxy.Logger.E("Dial ctrl server error: %v", err)
			return
		}

		go func() {
			for {
				buf := make([]byte, 16)
				_, err := io.ReadAtLeast(connw, buf, 16)
				if err != nil {
					signal <- redo
					return
				}

				localrpr := fmt.Sprintf("%x", buf)
				if bytes.Equal(buf, pingSignal) {
					// ping
					// proxy.Logger.D("Local RP","LocalRP: ping")
					_, err := connw.Write(buf)
					if err != nil {
						signal <- redo
						return
					}
					continue
				}

				if _, err = io.ReadAtLeast(connw, buf[:4], 4); err != nil {
					signal <- redo
					return
				}

				dstlen := int(binary.BigEndian.Uint32(buf[:4]))
				buf = make([]byte, dstlen)
				if _, err = io.ReadAtLeast(connw, buf, dstlen); err != nil {
					signal <- redo
					return
				}

				go func(buf []byte) {
					conn, err := net.Dial("tcp", proxy.ClientConfig.LocalRPBind)
					if err != nil {
						proxy.Logger.E("Dial local bind error: %v", err)
						return
					}

					if _, err := conn.Write(buf); err != nil {
						proxy.Logger.E("Write local bind error: %v", err)
						return
					}

					proxy.DialUpstream(conn, localrpr, nil, doLocalRP, 0)
				}(buf)
			}
		}()

		select {
		case x := <-signal:
			if x == redo {
				proxy.Logger.D("Reconnect ctrl server")
				upstream.Close()
				// dummyConn: no need to close it
				continue
			}
		}
	}
}

func (proxy *ProxyServer) pickAControlConn() dummyConnWrapper {
	proxy.localRP.Lock()
	defer proxy.localRP.Unlock()
	return proxy.localRP.downConns[proxy.Cipher.Rand.Intn(len(proxy.localRP.downConns))]
}

func (proxy *ProxyServer) startLocalRPControlServer(downstream net.Conn, cr *clientRequest, ioc IOConfig) {
	if _, err := downstream.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		proxy.Logger.E("Response error: %v", err)
		downstream.Close()
		return
	}

	if proxy.DisableLRP {
		proxy.Logger.W("RP client ctrl request rejected")
		downstream.Close()
		return
	}

	proxy.localRP.Lock()
	if proxy.localRP.downstreams == nil {
		proxy.localRP.downstreams = make([]net.Conn, 0)
		proxy.localRP.downConns = make([]dummyConnWrapper, 0)
	}
	if proxy.localRP.requests == nil {
		proxy.localRP.requests = make(chan localRPCtrlSrvReq, proxy.LBindCap)
	}
	if proxy.localRP.waiting == nil {
		proxy.localRP.waiting = make(map[string]localRPCtrlSrvResp)
	}

	conn := &dummyConn{}
	conn.Init()
	connw := dummyConnWrapper{conn}

	proxy.localRP.downstreams = append(proxy.localRP.downstreams, downstream)
	proxy.localRP.downConns = append(proxy.localRP.downConns, connw)

	if len(proxy.localRP.downConns) == 1 {
		go func() {
			for {
				select {
				case req := <-proxy.localRP.requests:
					if req.end {
						proxy.Logger.D("RP ctrl server has ended")
						return
					}
					if len(req.dst) >= 65535 {
						req.callback <- localRPCtrlSrvResp{
							err: fmt.Errorf("request too long"),
						}
						continue
					}

					buf := make([]byte, 16+4+len(req.rawReq))
					proxy.Cipher.Rand.Read(buf[:16])

					localrpr := fmt.Sprintf("%x", buf[:16])
					binary.BigEndian.PutUint32(buf[16:20], uint32(len(req.rawReq)))
					copy(buf[20:], req.rawReq)

					proxy.localRP.Lock()
					proxy.localRP.waiting[localrpr] = localRPCtrlSrvResp{
						localrpr: localrpr,
						req:      req,
					}
					proxy.localRP.Unlock()

					connw := proxy.pickAControlConn()
					go connw.Write(buf)
				}
			}
		}()
	}

	proxy.localRP.Unlock()

	go proxy.Cipher.IO.Bridge(downstream, conn, &cr.iv, ioc)

	go func() {

		for {
			buf := make([]byte, 16)
			if _, err := connw.Write(buf); err != nil {
				break
			}
			if _, err := connw.Read(buf); err != nil {
				break
			}
			// proxy.Logger.D("Server","LocalRP: pong")
			time.Sleep(localRPPingInterval)
		}

		proxy.localRP.Lock()
		for i, d := range proxy.localRP.downConns {
			if d == connw {
				proxy.localRP.downstreams = append(proxy.localRP.downstreams[:i], proxy.localRP.downstreams[i+1:]...)
				proxy.localRP.downConns = append(proxy.localRP.downConns[:i], proxy.localRP.downConns[i+1:]...)
				break
			}
		}
		if len(proxy.localRP.downstreams) == 0 {
			proxy.localRP.requests <- localRPCtrlSrvReq{end: true}
			proxy.localRP.waiting = nil
			proxy.localRP.requests = nil
		}
		proxy.localRP.Unlock()
		downstream.Close()
	}()
}
