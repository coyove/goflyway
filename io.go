package goflyway

import (
	"io"
	"net"
	"sync/atomic"

	. "github.com/coyove/goflyway/v"
)

func Bridge(target, source net.Conn, timeout *TokenBucket, stat *Traffic) {
	go func() {
		if err := ioCopy(target, source, timeout, stat.Sent()); err != nil {
			Eprint("bridge: ", err)
		}
		target.Close()
		source.Close()
	}()

	if err := ioCopy(source, target, timeout, stat.Recv()); err != nil {
		Eprint("bridge: ", err)
	}

	// Multiple closes, but for tohConn they are just fine
	target.Close()
	source.Close()
}

func ioCopy(dst io.WriteCloser, src io.ReadCloser, bk *TokenBucket, bytes *int64) (err error) {
	buf := make([]byte, 32*1024)

	for {
		nr, er := src.Read(buf)

		if nr > 0 {
			if bk != nil {
				bk.Consume(int64(nr))
			}

			nw, ew := dst.Write(buf[0:nr])

			if nw > 0 && bytes != nil {
				atomic.AddInt64(bytes, int64(nw))
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
		}

		if er != nil {
			if er != io.EOF && !isClosedConnErr(er) && !isTimeoutErr(er) {
				err = er
			}
			break
		}
	}

	return err
}
