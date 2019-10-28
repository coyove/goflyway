package toh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coyove/common/sched"
	"github.com/coyove/goflyway/v"
)

const (
	PING_OK uint16 = iota + 1
	PING_CLOSED
	PING_OK_VOID
)

type ServerConn struct {
	idx        uint64
	rev        *Listener
	schedPurge sched.SchedKey

	write struct {
		sync.Mutex
		buf     []byte
		counter uint32
	}

	read *readConn
}

func newServerConn(idx uint64, ln *Listener) *ServerConn {
	c := &ServerConn{idx: idx}
	c.rev = ln
	c.read = newReadConn(c.idx, ln.blk, 's')
	return c
}

func (l *Listener) randomReply(w http.ResponseWriter, r *http.Request) {
	v.Vprint("listener random reply: ", r)

	r.Header.Del("Content-Length")

	if l.OnBadRequest != nil {
		l.OnBadRequest(w, r)
		return
	}

	p := [256]byte{}
	for {
		if rand.Intn(8) == 0 {
			break
		}
		rand.Read(p[:])
		w.Write(p[:rand.Intn(128)+128])
	}
}

func (l *Listener) handler(w http.ResponseWriter, r *http.Request) {
	if strings.ToLower(r.Header.Get("Sec-WebSocket-Key")) != "" {
		conn, err := l.wsHandShake(w, r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			v.Eprint("websocket handshake error: ", err)
		} else {
			l.pendingConns <- conn
		}
		return
	}

	hdr, ok := parseframe(r.Body, l.blk)
	if !ok {
		l.randomReply(w, r)
		return
	}

	switch hdr.options {
	case optSyncConnIdx:
	case optClosed:
		l.connsmu.Lock()
		c := l.conns[hdr.connIdx]
		l.connsmu.Unlock()
		if c != nil {
			v.Vprint(c, " received close ping, client side has closed")
			c.Close()
		}
	case optPing:
		l.connsmu.Lock()
		p := bytes.Buffer{}
		for i := 0; i < len(hdr.data); i += 8 {
			connIdx := binary.BigEndian.Uint64(hdr.data[i : i+8])

			if c := l.conns[connIdx]; c != nil && c.read.err == nil && !c.read.closed {
				if len(c.write.buf) > 0 {
					binary.Write(&p, binary.BigEndian, PING_OK)
				} else {
					binary.Write(&p, binary.BigEndian, PING_OK_VOID)
				}
				c.reschedDeath()
			} else {
				binary.Write(&p, binary.BigEndian, PING_CLOSED)
			}

			binary.Write(&p, binary.BigEndian, connIdx)
		}
		l.connsmu.Unlock()

		f := frame{options: optPing, data: p.Bytes()}
		w.Write(f.marshal(l.blk))
		return
	default:
		l.randomReply(w, r)
		return
	}
	connIdx := hdr.connIdx

	var conn *ServerConn
	l.connsmu.Lock()
	if sc, _ := l.conns[connIdx]; sc != nil {
		conn = sc
		l.connsmu.Unlock()
	} else {
		// New incoming connection?
		f, ok := parseframe(r.Body, l.blk)
		if !ok || f.options&optHello == 0 || f.connIdx != connIdx {
			if !ok {
				l.randomReply(w, r)
			} else {
				// TODO: tell client the conn has gone
			}
			l.connsmu.Unlock()
			return
		}

		conn = newServerConn(connIdx, l)
		l.conns[connIdx] = conn
		l.connsmu.Unlock()

		l.pendingConns <- conn
		v.Vprint("accpet new conn: ", conn)
		conn.reschedDeath()
		//conn.writeTo(w)
		return
	}

	if datalen, err := conn.read.feedframes(r.Body); err != nil {
		v.Eprint("listener feed frames, error: ", err, ", ", conn, " will be deleted")
		conn.Close()
		return
	} else if datalen == 0 && len(conn.write.buf) == 0 {
		// Client sent nothing, we treat the request as a ping
		// However too many pings without:
		//   1) sending any valid data to us
		//   2) we sending any valid data to them
		// are meaningless
		// So we won't reschedule its deadline: it will die as expected
	} else {
		conn.reschedDeath()
	}

	conn.writeTo(w)
}

func (conn *ServerConn) reschedDeath() {
	conn.schedPurge.Reschedule(func() {
		v.VVVprint(conn, " will die as scheduled")
		conn.Close()
	}, conn.rev.Timeout)
}

func (conn *ServerConn) writeTo(w io.Writer) {

	for i := 0; ; i++ {
		conn.write.Lock()
		if len(conn.write.buf) == 0 {
			conn.write.Unlock()
			if i == 0 {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return
		}

		f := &frame{
			idx:     conn.write.counter + 1,
			connIdx: conn.idx,
			data:    make([]byte, len(conn.write.buf)),
		}

		copy(f.data, conn.write.buf)
		conn.write.buf = conn.write.buf[:0]
		conn.write.counter++
		conn.write.Unlock()

		deadline := time.Now().Add(conn.rev.Timeout - time.Second)
	AGAIN:
		if _, err := w.Write(f.marshal(conn.read.blk)); err != nil {
			if time.Now().Before(deadline) {
				goto AGAIN
			}
			v.Eprint(conn, " failed to response, error: ", err)
			conn.read.feedError(err)
			conn.Close()
			return
		}
	}
}

func (c *ServerConn) SetReadDeadline(t time.Time) error {
	c.read.ready.SetWaitDeadline(t)
	return nil
}

func (c *ServerConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return nil
}

func (c *ServerConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *ServerConn) Write(p []byte) (n int, err error) {
REWRITE:
	if c.read.closed {
		return 0, errClosedConn
	}

	if c.read.err != nil {
		return 0, c.read.err
	}

	if len(c.write.buf) > c.rev.MaxWriteBuffer {
		v.Vprint(c, " write buffer is full")
		time.Sleep(time.Second)
		goto REWRITE
	}

	c.write.Lock()
	c.write.buf = append(c.write.buf, p...)
	c.write.Unlock()
	return len(p), nil
}

func (c *ServerConn) Read(p []byte) (n int, err error) {
	return c.read.Read(p)
}

func (c *ServerConn) Close() error {
	if c.read.closed {
		return nil
	}

	v.VVprint(c, " closing")
	c.schedPurge.Cancel()
	c.read.close()
	c.rev.connsmu.Lock()
	delete(c.rev.conns, c.idx)
	c.rev.connsmu.Unlock()
	//v.Vprint(c, " delete", c.rev.conns)
	return nil
}

func (c *ServerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *ServerConn) LocalAddr() net.Addr {
	return c.rev.Addr()
}

func (c *ServerConn) String() string {
	return fmt.Sprintf("<S:%s,r:%d,w:%d>", formatConnIdx(c.idx), c.read.counter, c.write.counter)
}
