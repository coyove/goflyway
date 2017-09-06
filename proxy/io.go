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

func copyAndClose(dst, src *net.TCPConn, key string, throttle bool) {
	ts := time.Now()

	iocc := &IOCopyCipher{Dst: dst, Src: src, Key: ReverseRandomKey(key)}
	if throttle {
		iocc.Throttling = NewTokenBucket(int64(*G_Throttling), int64(*G_ThrottlingMax))
	}

	if _, err := iocc.DoCopy(); err != nil {
		logg.E("[COPY] ", time.Now().Sub(ts).Seconds(), "s - ", err)
	}

	dst.CloseWrite()
	src.CloseRead()
}

func copyOrWarn(dst io.Writer, src io.Reader, key string, throttle bool, wg *sync.WaitGroup) {
	ts := time.Now()

	iocc := &IOCopyCipher{Dst: dst, Src: src, Key: ReverseRandomKey(key)}
	if throttle {
		iocc.Throttling = NewTokenBucket(int64(*G_Throttling), int64(*G_ThrottlingMax))
	}

	if _, err := iocc.DoCopy(); err != nil {
		logg.E("[COPYW] ", time.Now().Sub(ts).Seconds(), "s - ", err)
	}

	wg.Done()
}

func TwoWayBridge(target, source net.Conn, key string, throttleTargetToSource bool) {

	targetTCP, targetOK := target.(*net.TCPConn)
	sourceTCP, sourceOK := source.(*net.TCPConn)

	if targetOK && sourceOK {
		// copy from source, decrypt, to target
		go copyAndClose(targetTCP, sourceTCP, key, false)

		// copy from target, encrypt, to source
		go copyAndClose(sourceTCP, targetTCP, key, throttleTargetToSource)
	} else {
		go func() {
			var wg sync.WaitGroup

			wg.Add(2)
			go copyOrWarn(target, source, key, false, &wg)
			go copyOrWarn(source, target, key, throttleTargetToSource, &wg)
			wg.Wait()

			source.Close()
			target.Close()
		}()
	}
}

type IOCopyCipher struct {
	Dst io.Writer
	Src io.Reader
	Key []byte

	Throttling *TokenBucket
}

func (cc *IOCopyCipher) DoCopy() (written int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			logg.E("[WTF] - ", r)
		}
	}()

	buf := make([]byte, 32*1024)
	// cbuf := make([]byte, len(buf))

	ctr := GetCipherStream(cc.Key)

	for {
		nr, er := cc.Src.Read(buf)
		if nr > 0 {
			xbuf := buf[0:nr]

			if ctr != nil {
				xs := 0
				if bytes.HasPrefix(xbuf, OK200) {
					xs = len(OK200)
				}

				// copy(cbuf, xbuf)
				// ctr.XORKeyStream(cbuf[xs:nr], xbuf[xs:])
				// copy(xbuf[xs:], cbuf[xs:nr])
				ctr.XorBuffer(xbuf[xs:])
			}

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
		// cp := make([]byte, n)
		// copy(cp, p[:n])
		//rc.ctr.XORKeyStream(cp, p[:n])
		// copy(p, cp)
		rc.ctr.XorBuffer(p[:n])
	}

	return
}

func XorWrite(w http.ResponseWriter, r *http.Request, p []byte, code int) (n int, err error) {
	key := ReverseRandomKey(SafeGetHeader(r, rkeyHeader))

	if ctr := GetCipherStream(key); ctr != nil {
		// cp := make([]byte, len(p))
		// copy(cp, p)
		// ctr.XORKeyStream(cp, p)
		// copy(p, cp)
		ctr.XorBuffer(p)
	}

	w.WriteHeader(code)
	return w.Write(p)
}
