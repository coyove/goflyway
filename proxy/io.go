package proxy

import (
	. "../config"
	"../logg"

	"bytes"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const sslRecordMax = 18 * 1024 // 18kb

func getIOCipherSimple(dst io.Writer, src io.Reader, key string, throttle bool) *IOCopyCipher {
	if throttle {
		return getIOCipher(dst, src, key, DO_THROTTLING)
	} else {
		return getIOCipher(dst, src, key, DO_NOTHING)
	}
}

func getIOCipher(dst io.Writer, src io.Reader, key string, options int) *IOCopyCipher {
	iocc := &IOCopyCipher{
		Dst:     dst,
		Src:     src,
		Key:     ReverseRandomKey(key),
		Partial: *G_PartialEncrypt,
	}

	if (options & DO_THROTTLING) != 0 {
		iocc.Throttling = NewTokenBucket(int64(*G_Throttling), int64(*G_ThrottlingMax))
	}

	return iocc
}

func copyAndClose(dst, src *net.TCPConn, key string, options int) {
	ts := time.Now()

	if _, err := getIOCipher(dst, src, key, options).DoCopy(); err != nil {
		logg.E("[COPY] ", time.Now().Sub(ts).Seconds(), "s - ", err)
	}

	dst.CloseWrite()
	src.CloseRead()
}

func copyOrWarn(dst io.Writer, src io.Reader, key string, options int, wg *sync.WaitGroup) {
	ts := time.Now()

	if _, err := getIOCipher(dst, src, key, options).DoCopy(); err != nil {
		logg.E("[COPYW] ", time.Now().Sub(ts).Seconds(), "s - ", err)
	}

	wg.Done()
}

func TwoWayBridge(target, source net.Conn, key string, options int) {

	targetTCP, targetOK := target.(*net.TCPConn)
	sourceTCP, sourceOK := source.(*net.TCPConn)

	if targetOK && sourceOK {
		// copy from source, decrypt, to target
		go copyAndClose(targetTCP, sourceTCP, key, options)

		// copy from target, encrypt, to source
		go copyAndClose(sourceTCP, targetTCP, key, options)
	} else {
		go func() {
			var wg sync.WaitGroup

			wg.Add(2)
			go copyOrWarn(target, source, key, options, &wg)
			go copyOrWarn(source, target, key, options, &wg)
			wg.Wait()

			source.Close()
			target.Close()
		}()
	}
}

type IOCopyCipher struct {
	Dst        io.Writer
	Src        io.Reader
	Key        []byte
	Throttling *TokenBucket
	Partial    bool
}

func (cc *IOCopyCipher) DoCopy() (written int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			logg.E("[WTF] - ", r)
		}
	}()

	buf := make([]byte, 32*1024)
	ctr := GetCipherStream(cc.Key)
	encrypted := 0

	for {
		nr, er := cc.Src.Read(buf)
		if nr > 0 {
			xbuf := buf[0:nr]

			if cc.Partial && encrypted == sslRecordMax {
				goto direct_transmission
			}

			if ctr != nil {
				xs := 0
				if written == 0 {
					// ignore the header
					if bytes.HasPrefix(xbuf, OK_HTTP) {
						xs = len(OK_HTTP)
					} else if bytes.HasPrefix(xbuf, OK_SOCKS) {
						xs = len(OK_SOCKS)
					}
				}

				if encrypted+nr > sslRecordMax && cc.Partial {
					ctr.XorBuffer(xbuf[:sslRecordMax-encrypted])
					encrypted = sslRecordMax
					// we are done, the traffic coming later will be transfered as is
				} else {
					ctr.XorBuffer(xbuf[xs:])
					encrypted += (nr - xs)
				}

			}

		direct_transmission:
			if cc.Throttling != nil {
				cc.Throttling.Consume(int64(len(xbuf)))
			}

			nw, ew := cc.Dst.Write(xbuf)

			if nw > 0 {
				written += int64(nw)
			}

			if ew != nil {
				err = ew
				break
			}

			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}

type IOReaderCipher struct {
	Src io.Reader
	Key []byte

	ctr *InplaceCTR
}

func (rc *IOReaderCipher) Init() *IOReaderCipher {
	rc.ctr = GetCipherStream(rc.Key)
	return rc
}

func (rc *IOReaderCipher) Read(p []byte) (n int, err error) {
	n, err = rc.Src.Read(p)
	if n > 0 && rc.ctr != nil {
		rc.ctr.XorBuffer(p[:n])
	}

	return
}

func XorWrite(w http.ResponseWriter, r *http.Request, p []byte, code int) (n int, err error) {
	key := ReverseRandomKey(SafeGetHeader(r, RKEY_HEADER))

	if ctr := GetCipherStream(key); ctr != nil {
		ctr.XorBuffer(p)
	}

	w.WriteHeader(code)
	return w.Write(p)
}
