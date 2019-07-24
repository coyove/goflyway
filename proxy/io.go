package proxy

import (
	"io"
	"log"
	"net"
)

func Bridge(target, source net.Conn) {
	exit := make(chan bool)

	go func() {
		if _, err := ioCopy(target, source); err != nil {
			log.Println("Bridge:", err)
		}
		exit <- true
	}()

	if _, err := ioCopy(source, target); err != nil {
		log.Println("Bridge:", err)
	}
	<-exit
}

func ioCopy(dst io.Writer, src io.Reader) (written int64, err error) {
	buf := make([]byte, 32*1024)

	for {
		nr, er := src.Read(buf)

		if nr > 0 {
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
