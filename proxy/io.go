package proxy

import (
	. "../config"
	"../logg"

	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

func copyAndClose(dst, src *net.TCPConn, key string) {
	ts := time.Now()

	if _, err := (&IOCopyCipher{
		Dst: dst,
		Src: src,
		Key: ReverseRandomKey(key),
	}).DoCopy(); err != nil && !*G_SuppressSocketReadWriteError {
		logg.E("[COPY] ~", time.Now().Sub(ts).Seconds(), " - ", err)
	}

	dst.CloseWrite()
	src.CloseRead()
}

func copyOrWarn(dst io.Writer, src io.Reader, key string, wg *sync.WaitGroup) {
	ts := time.Now()

	if _, err := (&IOCopyCipher{
		Dst: dst,
		Src: src,
		Key: ReverseRandomKey(key),
	}).DoCopy(); err != nil && !*G_SuppressSocketReadWriteError {
		logg.E("[COPYW] ~", time.Now().Sub(ts).Seconds(), " - ", err)
	}

	wg.Done()
}

func TwoWayBridge(target, source net.Conn, key string) {

	targetTCP, targetOK := target.(*net.TCPConn)
	sourceTCP, sourceOK := source.(*net.TCPConn)

	if targetOK && sourceOK {
		go copyAndClose(targetTCP, sourceTCP, key) // copy from source, decrypt, to target
		go copyAndClose(sourceTCP, targetTCP, key) // copy from target, encrypt, to source
	} else {
		go func() {
			var wg sync.WaitGroup
			wg.Add(2)
			go copyOrWarn(target, source, key, &wg)
			go copyOrWarn(source, target, key, &wg)
			wg.Wait()

			source.Close()
			target.Close()
		}()
	}
}

type IOCopyCipher struct {
	Dst io.Writer
	Src io.Reader
	Key [][]byte

	read int64
}

func (cc *IOCopyCipher) DoCopy() (written int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			logg.E("[WTF] - ", r)
		}
	}()

	buf := make([]byte, 32*1024)
	cc.read = 0

	for {
		// ts := time.Now()
		nr, er := cc.Src.Read(buf)
		if nr > 0 {
			xbuf := buf[0:nr]

			if cc.Key != nil && len(cc.Key) > 0 {
				// if key is not null, do the en/decryption
				xs := 0

				if bytesStartWith(xbuf, OK200) {
					xs = len(OK200)
				}

				for c := 0; c < len(cc.Key); c++ {
					ln := len(cc.Key[c])
					for i := xs; i < nr; i++ {
						xbuf[i] ^= cc.Key[c][(int(cc.read)+i-xs)%ln]
					}
				}

				cc.read += int64(nr - xs)
			}

			nw, ew := cc.Dst.Write(xbuf)

			if nw > 0 {
				written += int64(nw)
			}

			if ew != nil {
				err = ew
				// logg.W("[IO TIMING 0] ", time.Now().Sub(ts).Seconds())
				break
			}

			if nr != nw {
				err = io.ErrShortWrite
				// logg.W("[IO TIMING 1] ", time.Now().Sub(ts).Seconds())
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
	Key [][]byte

	read int64
}

func (rc *IOReaderCipher) Read(p []byte) (n int, err error) {
	n, err = rc.Src.Read(p)
	if n > 0 {

		if rc.Key != nil && len(rc.Key) > 0 {
			for c := 0; c < len(rc.Key); c++ {
				ln := len(rc.Key[c])
				for i := 0; i < n; i++ {
					p[i] ^= rc.Key[c][(int(rc.read)+i)%ln]
				}
			}
		}
		// logg.L(string(p[:n]))
		rc.read += int64(n)
	}

	return
}

func XorWrite(w http.ResponseWriter, r *http.Request, p []byte) (n int, err error) {
	key := ReverseRandomKey(SafeGetHeader(r, rkeyHeader))

	if key != nil && len(key) > 0 {
		for c := 0; c < len(key); c++ {
			ln := len(key[c])
			for i := 0; i < len(p); i++ {
				p[i] ^= key[c][i%ln]
			}
		}
	}

	return w.Write(p)
}
