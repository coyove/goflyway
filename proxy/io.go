package proxy

import (
	"bytes"
	"crypto/cipher"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/coyove/common/logg"
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
	Mode    _CipherMode
	Print   bool
	Role    byte
	WSCtrl  byte
}

func (iot *io_t) Bridge(target, source net.Conn, key [ivLen]byte, options IOConfig) {
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
			iot.Logger.Errorf("Bridge: %v", err)
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
		iot.Logger.Errorf("Bridge: %v", err)
	}

	select {
	case <-exit:
	}

	target.Close()
	source.Close()
}

type io_t struct {
	sync.Mutex
	iid      uint64
	Tr       trafficmon.Survey
	stop     chan bool
	sendStat bool
	mconns   map[uintptr]*conn_state_t
	idleTime int64
	Ob       interface{}
	Logger   *logg.Logger
}

type conn_state_t struct {
	conn net.Conn
	last int64
	iid  uintptr
}

func (iot *io_t) markActive(src interface{}, iid uint64) {
	if iot.stop == nil {
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

func (iot *io_t) Stop() {
	select {
	case iot.stop <- true:
	default:
	}
}

func (iot *io_t) Start(maxIdleTime int) {
	const keepConnectionsUnder = 200
	if iot.stop != nil {
		return
	}

	iot.stop = make(chan bool, 1)
	iot.mconns = make(map[uintptr]*conn_state_t)
	iot.idleTime = int64(maxIdleTime)
	tcpmux.MasterTimeout = uint32(maxIdleTime)
	iot.Tr.Init(20*60, trafficSurveyinterval) // 20 mins

	go func() {
		count := 0
		// lastSent, lastRecved := uint64(0), uint64(0)

		for {
			select {
			case <-iot.stop:
				iot.stop = nil
				return
			case tick := <-time.Tick(time.Second):
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

				if count == 60 && iot.Logger.GetLevel() == logg.LvDebug {
					count = 0
					iot.Logger.If(len(iot.mconns) > 0).Dbgf("GC b+%ds: %d active, %d purged", maxIdleTime, len(iot.mconns), purged)

					if ob, _ := iot.Ob.(*tcpmux.DialPool); ob != nil {
						conns := ob.Count()
						s, b := 0, bytes.Buffer{}
						for _, c := range conns {
							s += c
							b.WriteString(" /" + strconv.Itoa(c))
						}
						iot.Logger.If(s > 0).Dbgf("Mux: %d masters, %d streams%s", len(conns), s, b.String())
					} else if ob, _ := iot.Ob.(*tcpmux.ListenPool); ob != nil {
						waitings, swaitings, conns := ob.Count()
						s, v := 0, 0.0
						if len(conns) >= 2 {
							K := conns[0]
							n, Ex, Ex2 := 0.0, 0.0, 0.0
							for _, c := range conns {
								s += c
								n = n + 1
								Ex += float64(c - K)
								Ex2 += float64((c - K) * (c - K))
							}
							v = (Ex2 - (Ex*Ex)/n) / (n - 1)
							iot.Logger.Dbgf("Mux: %d masters, %d streams (%.2f), %d + %d waitings", len(conns), s, v, waitings, swaitings)
						}
					}
				}

				iot.Unlock()

				if iot.sendStat {
					sendTrafficStats(&iot.Tr)
				}
			}
		}
	}()
}

func (iot *io_t) Copy(dst io.Writer, src io.Reader, key [ivLen]byte, config IOConfig) (written int64, err error) {
	if iot.Logger.GetLevel() == logg.LvDebug {
		defer func() {
			if r := recover(); r != nil {
				iot.Logger.Errorf("Copy panic: %v", r)
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
			buf, nr, er = tcpmux.WSRead(src)
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

			if config.Mode == NoneCipher {
				// Cipher is disabled, goto direct transmission
			} else if config.Mode == PartialCipher && encrypted == sslRecordLen {
				// We have encrypted enough bytes, goto direct transmission
			} else if ctr != nil {

				if encrypted+nr > sslRecordLen && config.Mode == PartialCipher {
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
					nw, ew = tcpmux.WSWrite(dst, xbuf, false)
				case wsClientDstIsUpstream:
					nw, ew = tcpmux.WSWrite(dst, xbuf, true)
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

func (iot *io_t) NewReadCloser(src io.ReadCloser, key [ivLen]byte) *IOReadCloserCipher {
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
