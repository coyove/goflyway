package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"runtime"
	"sort"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/coyove/goflyway/pkg/fd"
	"github.com/coyove/goflyway/pkg/logg"
)

type IOConfig struct {
	Bucket  *TokenBucket
	Chunked bool
	Partial bool
}

func (iot *io_t) Bridge(target, source net.Conn, key []byte, options IOConfig) {

	var targetTCP *net.TCPConn
	var targetOK bool

	switch target.(type) {
	case *net.TCPConn:
		targetTCP, targetOK = target.(*net.TCPConn)
	case *connWrapper:
		targetTCP, targetOK = target.(*connWrapper).Conn.(*net.TCPConn)
	}

	sourceTCP, sourceOK := source.(*net.TCPConn)

	if !targetOK || !sourceOK || sourceTCP == nil || targetTCP == nil {
		logg.E("casting failed: ", target, " ", source)
		return
	}

	// if targetOK && sourceOK {
	// copy from source, decrypt, to target
	go iot.copyClose(targetTCP, sourceTCP, key, options)

	// copy from target, encrypt, to source
	go iot.copyClose(sourceTCP, targetTCP, key, options)
}

func (iot *io_t) copyClose(dst, src *net.TCPConn, key []byte, config IOConfig) {
	ts := time.Now()

	if _, err := iot.Copy(dst, src, key, config); err != nil {
		logg.E("io copy ", int(time.Now().Sub(ts).Seconds()), "s: ", err)
	}

	dst.CloseWrite()
	src.CloseRead()
}

type conn_state_t struct {
	conn net.Conn
	fd   uintptr
	last int64
	iid  uintptr
}

type conns_state_t []*conn_state_t

func (cs conns_state_t) Len() int { return len(cs) }

func (cs conns_state_t) Swap(i, j int) { cs[i], cs[j] = cs[j], cs[i] }

func (cs conns_state_t) Less(i, j int) bool { return cs[i].last < cs[j].last }

func (iot *io_t) markActive(src interface{}, iid uint64) {
	if !iot.started {
		return
	}

	var srcConn net.Conn

REPEAT:
	switch src.(type) {
	case *connWrapper:
		src = src.(*connWrapper).Conn
		goto REPEAT
	case *tls.Conn:
		// field "conn" is always the first in tls.Conn (at least from go 1.4)
		// so it is safe to cast *tls.Conn to net.Conn
		src = *(*net.Conn)(unsafe.Pointer(src.(*tls.Conn)))
		goto REPEAT
	case net.Conn:
		srcConn = src.(net.Conn)
	default:
		return
	}

	iot.Lock()
	id := uintptr((*[2]unsafe.Pointer)(unsafe.Pointer(&src))[1])

	if iot.mconns[id] == nil {
		iot.mconns[id] = &conn_state_t{srcConn, fd.ConnFD(srcConn), time.Now().UnixNano(), id}
	} else {
		iot.mconns[id].last = time.Now().UnixNano()
	}
	iot.Unlock()
}

func (iot *io_t) StartPurgeConns(maxIdleTime int) {
	const keepConnectionsUnder = 200
	if iot.started {
		return
	}

	iot.started = true
	iot.mconns = make(map[uintptr]*conn_state_t)
	iot.aggr = make(chan bool)

	go func() {
		count := 0
		for {
			iot.Lock()
			ns := time.Now().UnixNano()

			select {
			case <-iot.aggr:
				if iot.count24++; iot.count24%4 == 0 && logg.GetLevel() == logg.LvDebug && runtime.GOOS == "darwin" {
					// if had too many errno 24, we forcefully close fds larger than 100
					// this is a very dangerous action, which is just a workaround under macOS
					// and cannot guarantee that everything works after closing
					fmt.Print("\a")
					logg.W("goflyway is now trying to close down all file descriptors larger than 100")
					for i := 100; i <= int(iot.maxfd); i++ {
						fd.CloseFD(i)
					}
					iot.aggr <- true
					break
				}

				if len(iot.mconns) <= keepConnectionsUnder {
					logg.W("total connections is under ", keepConnectionsUnder, ", nothing to do")
					iot.aggr <- true
					break
				}

				arr := conns_state_t{}
				for _, state := range iot.mconns {
					arr = append(arr, state)
				}
				sort.Sort(arr)
				for i := 0; i < len(arr)-keepConnectionsUnder; i++ {
					ms := (ns - arr[i].last) / 1e6
					logg.L("closing ", arr[i].iid, ": ", arr[i].conn.RemoteAddr(), ", last active: ", ms, "ms ago")
					arr[i].conn.Close()
					delete(iot.mconns, arr[i].iid)
				}

				if logg.GetLevel() == logg.LvDebug {
					fmt.Print("\a")
				}
				iot.aggr <- true
			default:
				iot.maxfd = 0
				for id, state := range iot.mconns {
					if state.fd > iot.maxfd {
						// quite meaningless to compare handles under Windows
						iot.maxfd = state.fd
					}

					if (ns - state.last) > int64(maxIdleTime)*1e9 {
						//logg.D("closing ", state.conn.RemoteAddr(), " ", state.iid)
						state.conn.Close()
						delete(iot.mconns, id)
					}
				}

				if count++; count == 60 {
					count = 0
					if len(iot.mconns) > 0 {
						logg.D("active connections: ", len(iot.mconns), ", max fd: ", iot.maxfd)
					}
				}
			}

			iot.Unlock()
			time.Sleep(time.Second)
		}
	}()
}

func (iot *io_t) Copy(dst io.Writer, src io.Reader, key []byte, config IOConfig) (written int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			logg.E("wtf, ", r)
		}
	}()

	buf := make([]byte, 32*1024)
	ctr := (*Cipher)(unsafe.Pointer(iot)).getCipherStream(key)
	encrypted := 0

	u := atomic.AddUint64(&iot.iid, 1)

	// logg.D("open ", u)
	// retries := 0
	// srcConn, _ := src.(*net.TCPConn)
	// if srcConn != nil {

	// }

	for {
		iot.markActive(src, u)
		nr, er := src.Read(buf)
		if nr > 0 {
			xbuf := buf[0:nr]

			if config.Partial && encrypted == sslRecordLen {
				// goto direct_transmission
			} else if ctr != nil {

				if encrypted+nr > sslRecordLen && config.Partial {
					ctr.XorBuffer(xbuf[:sslRecordLen-encrypted])
					encrypted = sslRecordLen
					// we are done, the traffic coming later will be transfered as is
				} else {
					ctr.XorBuffer(xbuf)
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
				nw, ew = dst.Write(xbuf)
			}

			if nw > 0 {
				written += int64(nw)
			}

			if ew != nil {
				if !isClosedConnErr(ew) {
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
			// if ne, _ := er.(net.Error); ne != nil && ne.Timeout() {
			// 	logg.D(u, " ", retries, " ", addr)
			// 	if retries++; retries < 10 {
			// 		continue
			// 	}
			// }

			if er != io.EOF && !isClosedConnErr(er) {
				err = er
			}
			break
		}
	}

	if config.Chunked {
		dst.Write([]byte("0\r\n\r\n"))
	}

	// logg.D("close ", u)
	return written, err
}

func (iot *io_t) NewReadCloser(src io.ReadCloser, key []byte) *IOReadCloserCipher {
	return &IOReadCloserCipher{
		src: src,
		key: key,
		ctr: (*Cipher)(unsafe.Pointer(iot)).getCipherStream(key),
	}
}

type IOReadCloserCipher struct {
	src io.ReadCloser
	key []byte
	ctr *inplace_ctr_t
}

func (rc *IOReadCloserCipher) Read(p []byte) (n int, err error) {
	n, err = rc.src.Read(p)
	if n > 0 && rc.ctr != nil {
		rc.ctr.XorBuffer(p[:n])
	}

	return
}

func (rc *IOReadCloserCipher) Close() error {
	return rc.src.Close()
}
