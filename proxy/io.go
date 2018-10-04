package proxy

import (
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/coyove/common/logg"

	"github.com/coyove/common/rand"
	"github.com/coyove/goflyway/pkg/trafficmon"
	"github.com/coyove/tcpmux"
)

const (
	wsClient = iota + 1
	wsClientDstIsUpstream
	wsClientSrcIsUpstream
	wsServer
	wsServerDstIsDownstream
	wsServerSrcIsDownstream
)

const (
	roleSend = iota + 1
	roleRecv
)

type IOConfig struct {
	Bucket  *TokenBucket
	Chunked bool
	Partial bool
	Print   bool
	Role    byte
	WSCtrl  byte
}

func (iot *io_t) Bridge(target, source net.Conn, key *[ivLen]byte, options IOConfig) {
	// copy from source, decrypt, to target
	o := options
	switch o.WSCtrl {
	case wsServer:
		o.WSCtrl = wsServerDstIsDownstream
	case wsClient:
		o.WSCtrl = wsClientSrcIsUpstream
	}

	// Roles are all relative to the "source"
	o.Role = roleRecv

	if s, _ := target.(*tcpmux.Stream); s != nil {
		s.SetInactiveTimeout(uint32(iot.idleTime))
	}

	if s, _ := source.(*tcpmux.Stream); s != nil {
		s.SetInactiveTimeout(uint32(iot.idleTime))
	}

	exit := make(chan bool)
	go func(config IOConfig) {
		if _, err := iot.Copy(target, source, key, config); err != nil {
			iot.Logger.E("Bridge: %v", err)
		}
		exit <- true
	}(o)

	// copy from target, encrypt, to source
	o = options
	switch o.WSCtrl {
	case wsServer:
		o.WSCtrl = wsServerSrcIsDownstream
	case wsClient:
		o.WSCtrl = wsClientDstIsUpstream
	}

	o.Role = roleSend
	if _, err := iot.Copy(source, target, key, o); err != nil {
		iot.Logger.E("Bridge: %v", err)
	}

	select {
	case <-exit:
	}

	target.Close()
	source.Close()
}

type io_t struct {
	sync.Mutex
	iid uint64
	Tr  trafficmon.Survey // note 64bit align

	started  bool
	sendStat bool
	mconns   map[uintptr]*conn_state_t
	idleTime int64

	Ob     tcpmux.Survey
	Logger *logg.Logger
}

type conn_state_t struct {
	conn net.Conn
	last int64
	iid  uintptr
}

func (iot *io_t) markActive(src interface{}, iid uint64) {
	if !iot.started {
		return
	}

	var srcConn net.Conn

REPEAT:
	switch src.(type) {
	case *tcpmux.Conn:
		src = src.(*tcpmux.Conn).Conn
		goto REPEAT
	case *tls.Conn:
		// field "conn" is always the first in tls.Conn (at least from go 1.4)
		// so it is safe to cast *tls.Conn to net.Conn
		src = *(*net.Conn)(unsafe.Pointer(src.(*tls.Conn)))
		goto REPEAT
	case *udpBridgeConn:
		srcConn = src.(*udpBridgeConn)
	case net.Conn:
		srcConn = src.(net.Conn)
	case *tcpmux.Stream:
		// Stream has its own management of timeout
		return
	default:
		return
	}

	iot.Lock()
	id := uintptr((*[2]unsafe.Pointer)(unsafe.Pointer(&src))[1])

	if iot.mconns[id] == nil {
		iot.mconns[id] = &conn_state_t{srcConn, time.Now().UnixNano(), id}
	} else {
		iot.mconns[id].last = time.Now().UnixNano()
	}
	iot.Unlock()
}

const trafficSurveyinterval = 5

func (iot *io_t) StartPurgeConns(maxIdleTime int) {
	const keepConnectionsUnder = 200
	if iot.started {
		return
	}

	iot.started = true
	iot.mconns = make(map[uintptr]*conn_state_t)
	iot.idleTime = int64(maxIdleTime)
	tcpmux.MasterTimeout = uint32(maxIdleTime)
	iot.Tr.Init(20*60, trafficSurveyinterval) // 20 mins

	go func() {
		count := 0

		for tick := range time.Tick(time.Second) {
			iot.Lock()
			ns := tick.UnixNano()

			purged := 0
			for id, state := range iot.mconns {
				if (ns - state.last) > int64(maxIdleTime)*1e9 {
					state.conn.Close()
					delete(iot.mconns, id)
					purged++
				}
			}
			count++

			if count%trafficSurveyinterval == 0 {
				iot.Tr.Update()
			}

			if count == 60 {
				count = 0
				if len(iot.mconns) > 0 {
					iot.Logger.D("GC +%ds: %d active, %d purged", maxIdleTime, len(iot.mconns), purged)
				}

				if iot.Ob != nil {
					c, s := iot.Ob.Count()
					iot.Logger.D("Mux: %d masters, %d streams", c, s)
				}
			}

			iot.Unlock()

			if iot.sendStat {
				sendTrafficStats(&iot.Tr)
			}
		}
	}()
}

// wsWrite and wsRead are simple implementations of RFC6455
// we assume that all payloads are 65535 bytes at max
// we don't care control frames and everything is binary
// we don't close it explicitly, it closes when the TCP connection closes
// we don't ping or pong
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-------+-+-------------+-------------------------------+
//   |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//   |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//   |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//   | |1|2|3|       |K|             |                               |
//   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//   |     Extended payload length continued, if payload len == 127  |
//   + - - - - - - - - - - - - - - - +-------------------------------+
//   |                               |Masking-key, if MASK set to 1  |
//   +-------------------------------+-------------------------------+
//   | Masking-key (continued)       |          Payload Data         |
//   +-------------------------------- - - - - - - - - - - - - - - - +
//   :                     Payload Data continued ...                :
//   + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//   |                     Payload Data continued ...                |
//   +---------------------------------------------------------------+
func wsWrite(dst io.Writer, payload []byte, mask bool) (n int, err error) {
	if len(payload) > 65535 {
		panic("don't support payload larger than 65535 yet")
	}

	buf := make([]byte, 4)
	buf[0] = 2 // binary
	buf[1] = 126
	binary.BigEndian.PutUint16(buf[2:], uint16(len(payload)))

	if mask {
		buf[1] |= 0x80
		buf = append(buf, 0, 0, 0, 0)
		key := uint32(rand.GetCounter())
		binary.BigEndian.PutUint32(buf[4:8], key)

		for i, b := 0, buf[4:8]; i < len(payload); i++ {
			payload[i] ^= b[i%4]
		}
	}

	if n, err = dst.Write(buf); err != nil {
		return
	}

	return dst.Write(payload)
}

func (iot *io_t) wsRead(src io.Reader) (payload []byte, n int, err error) {
	buf := make([]byte, 4)
	if n, err = io.ReadAtLeast(src, buf[:2], 2); err != nil {
		return
	}

	if buf[0] != 2 {
		iot.Logger.W("Invalid websocket opcode: %v", buf[0])
	}

	mask := (buf[1] & 0x80) > 0
	ln := int(buf[1] & 0x7f)

	switch ln {
	case 126:
		if n, err = io.ReadAtLeast(src, buf[2:4], 2); err != nil {
			return
		}
		ln = int(binary.BigEndian.Uint16(buf[2:4]))
	case 127:
		iot.Logger.E("Websocket payload too large")
		return
	default:
	}

	if mask {
		if n, err = io.ReadAtLeast(src, buf[:4], 4); err != nil {
			return
		}
		// now buf contains mask key
	}

	payload = make([]byte, ln)
	if n, err = io.ReadAtLeast(src, payload, ln); err != nil {
		return
	}

	if mask {
		for i, b := 0, buf[:4]; i < len(payload); i++ {
			payload[i] ^= b[i%4]
		}
	}

	// n == ln, err == nil,
	return
}

func (iot *io_t) Copy(dst io.Writer, src io.Reader, key *[ivLen]byte, config IOConfig) (written int64, err error) {
	if iot.Logger.GetLevel() == logg.LvDebug {
		defer func() {
			if r := recover(); r != nil {
				iot.Logger.E("Copy panic: %v", r)
			}
		}()
	}

	buf := make([]byte, 32*1024)
	ctr := (*Cipher)(unsafe.Pointer(iot)).getCipherStream(key)
	encrypted := 0

	u := atomic.AddUint64(&iot.iid, 1)

	for {
		iot.markActive(src, u)
		var nr int
		var er error

		switch config.WSCtrl {
		case wsClientSrcIsUpstream, wsServerSrcIsDownstream:
			// we are client, reading from upstream, or
			// we are server, reading from downstream
			buf, nr, er = iot.wsRead(src)
		default:
			nr, er = src.Read(buf)
		}
		if nr > 0 {
			xbuf := buf[0:nr]
			if config.Role == roleSend {
				iot.Tr.Send(int64(nr))
			} else if config.Role == roleRecv {
				iot.Tr.Recv(int64(nr))
			}

			if ctr != nil {
				if encrypted+nr > sslRecordLen && config.Partial {
					ybuf := xbuf[:sslRecordLen-encrypted]
					ctr.XORKeyStream(ybuf, ybuf)
					encrypted = sslRecordLen
					// we are done, the traffic coming later will be transfered as is
				} else {
					ctr.XORKeyStream(xbuf, xbuf)
					encrypted += nr
				}

			}

			if config.Bucket != nil {
				config.Bucket.Consume(int64(len(xbuf)))
			}

			var nw int
			var ew error
			iot.markActive(dst, u)
			if config.Chunked {
				hlen := strconv.FormatInt(int64(nr), 16)
				if _, ew = dst.Write([]byte(hlen + "\r\n")); ew == nil {
					if nw, ew = dst.Write(xbuf); ew == nil {
						_, ew = dst.Write([]byte("\r\n"))
					}
				}

			} else {
				switch config.WSCtrl {
				case wsServerDstIsDownstream:
					nw, ew = wsWrite(dst, xbuf, false)
				case wsClientDstIsUpstream:
					nw, ew = wsWrite(dst, xbuf, true)
				default:
					nw, ew = dst.Write(xbuf)
				}
			}

			if nw > 0 {
				written += int64(nw)
			}

			if ew != nil {
				if !isClosedConnErr(ew) && !isTimeoutErr(ew) {
					err = ew
				}
				break
			}

			if nr != nw {
				err = io.ErrShortWrite
				break
			}

			// retries = 0
		}

		if er != nil {
			if er != io.EOF && !isClosedConnErr(er) && !isTimeoutErr(er) {
				err = er
			}
			break
		}
	}

	if config.Chunked {
		dst.Write([]byte("0\r\n\r\n"))
	}

	return written, err
}

func (iot *io_t) NewReadCloser(src io.ReadCloser, key *[ivLen]byte) *IOReadCloserCipher {
	return &IOReadCloserCipher{
		src: src,
		ctr: (*Cipher)(unsafe.Pointer(iot)).getCipherStream(key),
		tr:  &iot.Tr,
	}
}

type IOReadCloserCipher struct {
	src io.ReadCloser
	ctr cipher.Stream
	tr  *trafficmon.Survey
}

func (rc *IOReadCloserCipher) Read(p []byte) (n int, err error) {
	if rc.src == nil {
		return 0, io.EOF
	}

	n, err = rc.src.Read(p)
	if n > 0 && rc.ctr != nil {
		rc.ctr.XORKeyStream(p[:n], p[:n])
		rc.tr.Send(int64(n))
	}

	return
}

func (rc *IOReadCloserCipher) Close() error {
	if rc.src == nil {
		return nil
	}
	return rc.src.Close()
}
