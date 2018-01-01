package proxy

import (
	"encoding/binary"
	"errors"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/coyove/goflyway/pkg/fd"
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/tcpmux"

	"io"
	"net"
)

type listenerWrapper struct {
	net.Listener
	proxy *ProxyClient
}

func (l *listenerWrapper) Accept() (net.Conn, error) {

CONTINUE:
	c, err := l.Listener.Accept()
	if err != nil || c == nil {
		logg.E("listener: ", err)

		if isClosedConnErr(err) {
			return nil, err
		}

		goto CONTINUE
	}

	wrapper := &tcpmux.Conn{Conn: c}

	wrapper.SetReadDeadline(time.Now().Add(2000 * time.Millisecond))
	b, err := wrapper.FirstByte()
	wrapper.SetReadDeadline(time.Time{})

	if err != nil {
		if err != io.EOF {
			logg.E("prefetch err: ", err)
		}

		wrapper.Close()
		goto CONTINUE
	}

	switch b {
	case 0x04, 0x05:
		// we are accepting SOCKS4 in case it goes to the HTTP handler
		go l.proxy.handleSocks(wrapper)
		goto CONTINUE
	default:
		return wrapper, err
	}
}

func vpnDial(address string) (net.Conn, error) {
	sock, err := fd.Socket(syscall.AF_INET)
	if err != nil {
		return nil, err
	}

	if err := protectFD(sock); err != nil {
		return nil, err
	}

	return fd.DialWithFD(sock, address)
}

func protectFD(fd int) error {
	sock, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}

	var addr syscall.SockaddrUnix
	addr.Name = "protect_path"

	if err := (syscall.Connect(sock, &addr)); err != nil {
		return err
	}

	if err := sendFD(sock, fd); err != nil {
		return err
	}

	ret := []byte{9}
	if n, err := syscall.Read(sock, ret); err != nil {
		return err
	} else if n != 1 {
		return errors.New("protecting failed")
	}

	syscall.Close(sock)

	if ret[0] != 0 {
		return errors.New("protecting failed")
	}

	return nil
}

var _int_value_one int = 1
var _little_endian = *(*byte)(unsafe.Pointer(&_int_value_one)) == 1

func sendFD(sock int, fd int) error {
	cmsg := &syscall.Cmsghdr{
		Level: syscall.SOL_SOCKET,
		Type:  syscall.SCM_RIGHTS,
	}

	// cmsghdr.len may be uint64 or uint32, depending on the platform
	ln := syscall.SizeofCmsghdr + strconv.IntSize/8
	h := (*[8]byte)(unsafe.Pointer(&cmsg.Len))

	if _little_endian {
		h[0] = byte(ln)
	} else {
		var i interface{} = cmsg.Len
		switch i.(type) {
		case uint64:
			binary.BigEndian.PutUint64(h[:8], uint64(ln))
		case uint32:
			binary.BigEndian.PutUint32(h[:4], uint32(ln))
		}
	}

	buffer := make([]byte, cmsg.Len)

	copy(buffer, (*[syscall.SizeofCmsghdr]byte)(unsafe.Pointer(cmsg))[:])
	*(*int)(unsafe.Pointer(&buffer[syscall.SizeofCmsghdr])) = fd

	return syscall.Sendmsg(sock, []byte{'!'}, buffer, nil, 0)
}
