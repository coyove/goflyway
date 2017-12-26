package proxy

import (
	"strconv"
	"time"
	"unsafe"

	"github.com/coyove/goflyway/pkg/logg"

	"io"
	"net"
	"strings"
)

// Conn can prefetch one byte from net.Conn before Read()
type Conn struct {
	data  uintptr
	len   int
	cap   int
	first byte

	net.Conn

	err     error
	timeout int // in milliseconds
}

func (c *Conn) FirstByte() (b byte, err error) {
	var n int

	c.data = uintptr(unsafe.Pointer(c)) + strconv.IntSize/8*3
	c.len = 1
	c.cap = 1

	c.Conn.SetReadDeadline(time.Now().Add(time.Duration(c.timeout) * time.Millisecond))
	n, err = c.Conn.Read(*(*[]byte)(unsafe.Pointer(c)))
	c.err = err

	if n == 1 {
		b = c.first
	}

	return
}

func (c *Conn) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}

	if c.len == 1 {
		p[0] = c.first
		xp := p[1:]

		n, err := c.Conn.Read(xp)
		c.len = 0

		return n + 1, err
	}

	return c.Conn.Read(p)
}

type listenerWrapper struct {
	net.Listener

	proxy   *ProxyClient
	retry24 bool
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

	wrapper := &Conn{Conn: c, timeout: 2000}

	b, err := wrapper.FirstByte()
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
