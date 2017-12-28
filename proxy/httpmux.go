package proxy

import (
	"time"

	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/tcpmux"

	"io"
	"net"
	"strings"
)

type listenerWrapper struct {
	net.Listener
	proxy *ProxyClient
}

func (l *listenerWrapper) Accept() (net.Conn, error) {
	isC24Retried := false

CONTINUE:
	c, err := l.Listener.Accept()
	if err != nil || c == nil {
		errs := err.Error()
		if l.proxy.Policy.IsSet(PolicyAggrClosing) && strings.Contains(errs, "too many open files") && !isC24Retried {
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

	wrapper := &tcpmux.Conn{Conn: c}

	wrapper.SetReadDeadline(time.Now().Add(2000 * time.Millisecond))
	b, err := wrapper.FirstByte()
	wrapper.SetReadDeadline(time.Time{})

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

type upstreamListenerWrapper struct {
	net.Listener
	proxy *ProxyUpstream
}

func (l *upstreamListenerWrapper) Accept() (net.Conn, error) {
CONTINUE:
	c, err := l.Listener.Accept()
	if err != nil || c == nil {
		logg.E("listener: ", err)

		if isClosedConnErr(err) {
			return nil, err
		}

		goto CONTINUE
	}

	if conn, _ := c.(*tcpmux.Conn); conn != nil {
		if b, _ := conn.FirstByte(); b == uotMagic {
			go l.proxy.handleTCPtoUDP(c)
			goto CONTINUE
		}
	}

	return c, err
}
