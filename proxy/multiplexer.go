package proxy

import (
	"io"
	"net"
)

// prefetchReader can prefetch one byte from the reader before Read()
type prefetchReader struct {
	src io.Reader

	first   byte
	reseted bool
	err     error
}

func (ur *prefetchReader) prefetch() (byte, error) {
	buf := make([]byte, 1)
	n, err := ur.src.Read(buf)
	ur.err = err

	if n == 1 {
		ur.first = buf[0]
		return buf[0], nil
	}

	return buf[0], err
}

func (ur *prefetchReader) Read(p []byte) (int, error) {
	if ur.err != nil {
		return 0, ur.err
	}

	if !ur.reseted {
		p[0] = ur.first
		xp := p[1:]

		n, err := ur.src.Read(xp)
		ur.reseted = true

		return n + 1, err
	}

	return ur.src.Read(p)
}

type connWrapper struct {
	net.Conn
	sbuffer *prefetchReader
}

func newConnWrapper(c net.Conn) *connWrapper {
	return &connWrapper{Conn: c, sbuffer: &prefetchReader{src: c}}
}

func (cw *connWrapper) Read(p []byte) (int, error) {
	return cw.sbuffer.Read(p)
}

type listenerWrapper struct {
	net.Listener

	proxy     *ProxyClient
	httpConn  connWrapper
	socksConn connWrapper
}

func (l *listenerWrapper) Accept() (net.Conn, error) {
CONTINUE:
	c, err := l.Listener.Accept()
	wrapper := &connWrapper{Conn: c, sbuffer: &prefetchReader{src: c}}

	switch b, _ := wrapper.sbuffer.prefetch(); b {
	case 0x04, 0x05:
		// we are accepting SOCKS4 in case it goes to the HTTP handler
		go l.proxy.HandleSocks(wrapper)
		goto CONTINUE
	default:
		return wrapper, err
	}
}
