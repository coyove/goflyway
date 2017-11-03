package proxy

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/coyove/goflyway/pkg/logg"
)

type IOConfig struct {
	Bucket  *TokenBucket
	Chunked bool
}

func (gc *Cipher) blockedIO(target, source interface{}, key []byte, options *IOConfig) {
	var wg sync.WaitGroup

	wg.Add(2)
	go gc.ioCopyOrWarn(target.(io.Writer), source.(io.Reader), key, options, &wg)
	go gc.ioCopyOrWarn(source.(io.Writer), target.(io.Reader), key, options, &wg)
	wg.Wait()
}

func (gc *Cipher) Bridge(target, source net.Conn, key []byte, options *IOConfig) {

	var targetTCP *net.TCPConn
	var targetOK bool

	switch target.(type) {
	case *net.TCPConn:
		targetTCP, targetOK = target.(*net.TCPConn)
	case *connWrapper:
		targetTCP, targetOK = target.(*connWrapper).Conn.(*net.TCPConn)
	}

	sourceTCP, sourceOK := source.(*net.TCPConn)

	if targetTCP == nil || sourceTCP == nil {
		return
	}

	if targetOK && sourceOK {
		// copy from source, decrypt, to target
		go gc.ioCopyAndClose(targetTCP, sourceTCP, key, options)

		// copy from target, encrypt, to source
		go gc.ioCopyAndClose(sourceTCP, targetTCP, key, options)
	} else {
		go func() {
			gc.blockedIO(target, source, key, options)
			source.Close()
			target.Close()
		}()
	}
}

func (gc *Cipher) WrapIO(dst io.Writer, src io.Reader, key []byte, options *IOConfig) *IOCopyCipher {

	return &IOCopyCipher{
		Dst:     dst,
		Src:     src,
		Key:     key,
		Partial: gc.Partial,
		Cipher:  gc,
		Config:  options,
	}
}

func (gc *Cipher) ioCopyAndClose(dst, src *net.TCPConn, key []byte, options *IOConfig) {
	ts := time.Now()

	if _, err := gc.WrapIO(dst, src, key, options).DoCopy(); err != nil {
		logg.E("tcp.copy ", int(time.Now().Sub(ts).Seconds()), "s: ", err)
	}

	dst.CloseWrite()
	src.CloseRead()
}

func (gc *Cipher) ioCopyOrWarn(dst io.Writer, src io.Reader, key []byte, options *IOConfig, wg *sync.WaitGroup) {
	ts := time.Now()

	if _, err := gc.WrapIO(dst, src, key, options).DoCopy(); err != nil {
		logg.E("io.copy ", int(time.Now().Sub(ts).Seconds()), "s: ", err)
	}

	wg.Done()
}

type IOCopyCipher struct {
	Dst    io.Writer
	Src    io.Reader
	Key    []byte
	Cipher *Cipher
	Config *IOConfig

	// can be altered outside
	Partial bool
}

func (cc *IOCopyCipher) DoCopy() (written int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			logg.E("wtf, ", r)
		}
	}()

	buf := make([]byte, 32*1024)
	ctr := cc.Cipher.getCipherStream(cc.Key)
	encrypted := 0
	chunked := cc.Config != nil && cc.Config.Chunked

	for {
		nr, er := cc.Src.Read(buf)
		if nr > 0 {
			xbuf := buf[0:nr]
			xs := 0

			if cc.Partial && encrypted == SSL_RECORD_MAX {
				goto direct_transmission
			}

			if ctr != nil {
				if written == 0 {
					// ignore the header
					if bytes.HasPrefix(xbuf, OK_HTTP) {
						xs = len(OK_HTTP)
					} else if bytes.HasPrefix(xbuf, OK_SOCKS) {
						xs = len(OK_SOCKS)
					}
				}

				if encrypted+nr > SSL_RECORD_MAX && cc.Partial {
					ctr.XorBuffer(xbuf[:SSL_RECORD_MAX-encrypted])
					encrypted = SSL_RECORD_MAX
					// we are done, the traffic coming later will be transfered as is
				} else {
					ctr.XorBuffer(xbuf[xs:])
					encrypted += (nr - xs)
				}

			}

		direct_transmission:
			if cc.Config != nil && cc.Config.Bucket != nil {
				cc.Config.Bucket.Consume(int64(len(xbuf)))
			}

			var nw int
			var ew error
			if chunked {
				hlen := strconv.FormatInt(int64(nr), 16)
				if _, ew = cc.Dst.Write([]byte(hlen + "\r\n")); ew == nil {
					if nw, ew = cc.Dst.Write(xbuf); ew == nil {
						_, ew = cc.Dst.Write([]byte("\r\n"))
					}
				}

			} else {
				nw, ew = cc.Dst.Write(xbuf)
			}

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

	if chunked {
		cc.Dst.Write([]byte("0\r\n\r\n"))
	}

	return written, err
}

type IOReaderCipher struct {
	Src    io.Reader
	Key    []byte
	Cipher *Cipher
	ctr    *inplace_ctr_t
}

func (rc *IOReaderCipher) Init() *IOReaderCipher {
	rc.ctr = rc.Cipher.getCipherStream(rc.Key)
	return rc
}

func (rc *IOReaderCipher) Read(p []byte) (n int, err error) {
	n, err = rc.Src.Read(p)
	if n > 0 && rc.ctr != nil {
		rc.ctr.XorBuffer(p[:n])
	}

	return
}
