package toh

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coyove/goflyway/v"
)

type Listener struct {
	ln           net.Listener
	closed       bool
	conns        map[uint64]*ServerConn
	connsmu      sync.Mutex
	httpServeErr chan error
	pendingConns chan net.Conn
	blk          cipher.Block

	OnBadRequest http.HandlerFunc
	CommonOptions
}

func (l *Listener) Close() error {
	select {
	case l.httpServeErr <- fmt.Errorf("accept on closed listener"):
	}
	l.closed = true
	return l.ln.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		select {
		case err := <-l.httpServeErr:
			return nil, err
		case conn := <-l.pendingConns:
			return conn, nil
		}
	}
}

func Listen(network string, address string, options ...Option) (net.Listener, error) {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		ln:           ln,
		httpServeErr: make(chan error, 1),
		pendingConns: make(chan net.Conn, 1024),
		conns:        map[uint64]*ServerConn{},
	}

	for _, o := range options {
		o(nil, l)
	}

	l.check()

	l.blk, _ = aes.NewCipher([]byte(network + "0123456789abcdef")[:16])

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", l.handler)
		l.httpServeErr <- http.Serve(ln, mux)
	}()

	if v.Verbose > 0 {
		go func() {
			for range time.Tick(time.Second * 5) {
				ln := 0
				l.connsmu.Lock()
				for _, conn := range l.conns {
					ln += len(conn.write.buf)
					//v.Vprint(conn, len(conn.write.buf))
				}
				l.connsmu.Unlock()
				v.VVprint("listener active connections: ", len(l.conns), ", pending bytes: ", ln)
			}
		}()
	}

	return l, nil
}

type Dialer struct {
	endpoint string
	orch     chan *ClientConn
	blk      cipher.Block

	Transport   http.RoundTripper
	WebSocket   bool
	URLHeader   string
	PathPattern string
	CommonOptions
}

func NewDialer(network string, endpoint string, options ...Option) *Dialer {
	d := &Dialer{
		endpoint: endpoint,
		orch:     make(chan *ClientConn, 128),
	}
	d.blk, _ = aes.NewCipher([]byte(network + "0123456789abcdef")[:16])

	for _, o := range options {
		o(d, nil)
	}

	if d.Transport == nil {
		d.Transport = http.DefaultTransport
	}
	if !d.WebSocket {
		d.startOrch()
	}
	if !strings.HasPrefix(d.PathPattern, "/") {
		d.PathPattern = "/"
	}
	d.check()

	return d
}

func (d *Dialer) Path() string {
	r := strconv.FormatUint(rand.Uint64(), 10)
	if strings.HasSuffix(d.PathPattern, "/") {
		return d.PathPattern + r
	}
	return d.PathPattern + "/" + r
}
