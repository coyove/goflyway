package goflyway

import (
	"io"
	"net"

	. "github.com/coyove/goflyway/v"
)

func Bridge(target, source net.Conn, timeout *TokenBucket) {
	go func() {
		if _, err := ioCopy(target, source, timeout); err != nil {
			Vprint("Bridge:", err)
		}
		target.Close()
		source.Close()
	}()

	if _, err := ioCopy(source, target, timeout); err != nil {
		Vprint("Bridge:", err)
	}

	// Multiple closes, but for tcpmux/toh they are just fine
	target.Close()
	source.Close()
}

func ioCopy(dst io.WriteCloser, src io.ReadCloser, bk *TokenBucket) (written int64, err error) {
	buf := make([]byte, 32*1024)

	for {
		nr, er := src.Read(buf)

		if nr > 0 {
			if bk != nil {
				bk.Consume(int64(nr))
			}

			nw, ew := dst.Write(buf[0:nr])
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

	return written, err
}
