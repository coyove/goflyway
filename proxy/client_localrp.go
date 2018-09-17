package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/coyove/common/logg"
)

const (
	localRPPingInterval = 1 * time.Second
	pingScale           = 10
)

var (
	pingSignal = make([]byte, 16)
)

type DummyConn struct {
	otr, mer io.Reader
	otw, mew io.Writer
}

type DummyConnWrapper struct {
	*DummyConn
}

func (d *DummyConn) Init() {
	d.otr, d.mew = io.Pipe()
	d.mer, d.otw = io.Pipe()
}

func (d *DummyConn) Read(b []byte) (n int, err error)         { return d.otr.Read(b) }
func (d *DummyConn) Write(b []byte) (n int, err error)        { return d.otw.Write(b) }
func (d *DummyConn) Close() error                             { return nil }
func (d *DummyConn) LocalAddr() net.Addr                      { return nil }
func (d *DummyConn) RemoteAddr() net.Addr                     { return nil }
func (d *DummyConn) SetDeadline(t time.Time) error            { return nil }
func (d *DummyConn) SetReadDeadline(t time.Time) error        { return nil }
func (d *DummyConn) SetWriteDeadline(t time.Time) error       { return nil }
func (d *DummyConn) readWritten(b []byte) (n int, err error)  { return d.mer.Read(b) }
func (d *DummyConn) writeForRead(b []byte) (n int, err error) { return d.mew.Write(b) }

func (d *DummyConnWrapper) Read(b []byte) (n int, err error) {
	ok := make(chan bool, 1)
	go func() {
		n, err = d.DummyConn.readWritten(b)
		ok <- true
	}()
	select {
	case <-ok:
		return
	case <-time.After(localRPPingInterval * pingScale):
		return 0, io.EOF
	}
}
func (d *DummyConnWrapper) Write(b []byte) (n int, err error) {
	ok := make(chan bool, 1)
	go func() {
		n, err = d.DummyConn.writeForRead(b)
		ok <- true
	}()
	select {
	case <-ok:
		return
	case <-time.After(localRPPingInterval * pingScale):
		return 0, io.EOF
	}
}

func (proxy *ProxyClient) StartLocalRP() error {
	const redo = 1

	for {
		conn := &DummyConn{}
		conn.Init()
		connw := &DummyConnWrapper{conn}
		signal := make(chan byte, 1)

		upstream := proxy.DialUpstream(conn, "a", nil, doLocalRP, 0)
		if upstream == nil {
			return nil
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
					// logg.D("LocalRP: ping")
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
						logg.E(err)
						return
					}

					if _, err := conn.Write(buf); err != nil {
						logg.E(err)
						return
					}

					proxy.DialUpstream(conn, localrpr, nil, doLocalRP, 0)
				}(buf)
			}
		}()

		select {
		case x := <-signal:
			if x == redo {
				logg.D("Reconnect to the upstream for control messages")
				upstream.Close()
				// DummyConn: no need to close it
				continue
			}
		}
	}
}
