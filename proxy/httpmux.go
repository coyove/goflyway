package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"

	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// prefetchReader can prefetch one byte from the reader before Read()
type prefetchReader struct {
	src io.Reader

	first   byte
	reseted bool
	err     error
	timeout int

	obpool *OneBytePool
}

func (ur *prefetchReader) readTimeout(buf []byte) (n int, err error) {
	finish := make(chan bool, 1)

	go func() {
		n, err = ur.src.Read(buf)
		finish <- true
	}()

	select {
	case <-finish:
	case <-time.After(time.Duration(ur.timeout) * time.Millisecond):
		err = errors.New("i/o read timeout")
	}

	return
}

func (ur *prefetchReader) prefetch() (byte, error) {
	buf := ur.obpool.Get()
	defer ur.obpool.Free(buf)

	n, err := ur.readTimeout(buf)
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

type OneBytePool chan []byte

func NewOneBytePool(s int) *OneBytePool {
	p := OneBytePool(make(chan []byte, s))
	return &p
}

func (p *OneBytePool) Get() []byte {
	select {
	case buf := <-*p:
		return buf
	default:
		return make([]byte, 1)
	}
}

func (p *OneBytePool) Free(buf []byte) {
	select {
	case *p <- buf:
	default:
	}
}

type connWrapper struct {
	net.Conn
	sbuffer *prefetchReader
}

func (cw *connWrapper) Read(p []byte) (int, error) {
	return cw.sbuffer.Read(p)
}

type listenerWrapper struct {
	net.Listener

	proxy     *ProxyClient
	httpConn  connWrapper
	socksConn connWrapper
	obpool    *OneBytePool
	retry24   bool
}

func (l *listenerWrapper) Accept() (net.Conn, error) {
	isC24Retried := false

CONTINUE:
	c, err := l.Listener.Accept()
	if err != nil || c == nil {
		errs := err.Error()
		if l.retry24 && strings.Contains(errs, "too many open files") && !isC24Retried {
			// if this is the first time we encounter "too many open files"
			// inform the daemon to aggresively close the old connections so we can try again
			// normally error 24 is not that likely to happen in most of time
			// even it did happen, you can increase the limit by ulimit -n
			// UNLESS you are using macos, changing this number would be quite painful ;)
			logg.D("encounter 'too many open files', start purging idle connections")
			l.proxy.Cipher.IO.aggr <- true
			<-l.proxy.Cipher.IO.aggr

			isC24Retried = true
			goto CONTINUE
		}

		logg.E("listener: ", err)

		if isClosedConnErr(err) {
			return nil, err
		}

		goto CONTINUE
	}

	wrapper := &connWrapper{
		Conn: c,
		sbuffer: &prefetchReader{
			src:     c,
			obpool:  l.obpool,
			timeout: 2000, // 2 seconds
		},
	}

	b, err := wrapper.sbuffer.prefetch()
	if err != nil {
		if err != io.EOF {
			logg.E("prefetch err: ", err)
		}

		wrapper.Close()
		goto CONTINUE
	}

	isC24Retried = false
	switch b {
	case 0x04, 0x05:
		// we are accepting SOCKS4 in case it goes to the HTTP handler
		go l.proxy.handleSocks(wrapper)
		goto CONTINUE
	default:
		return wrapper, err
	}
}
