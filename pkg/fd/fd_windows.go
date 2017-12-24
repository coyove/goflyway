package fd

import (
	"net"
	"syscall"
)

func ConnFD(conn net.Conn) (fd uintptr) {
	switch conn.(type) {
	case *net.TCPConn:
		if f, err := conn.(*net.TCPConn).File(); err == nil {
			fd = f.Fd()
		}
	case *net.UDPConn:
		if f, err := conn.(*net.UDPConn).File(); err == nil {
			fd = f.Fd()
		}
	}

	return
}

func CloseFD(fd int) {
	syscall.Close(syscall.Handle(fd))
}
