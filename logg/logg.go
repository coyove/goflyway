package logg

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func timestamp() string {
	t := time.Now()
	mil := t.UnixNano() % 1e9
	mil /= 1e6

	return fmt.Sprintf("%02d%02d %02d:%02d:%02d.%03d", t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), mil)
}

func lead(l string) string {
	return ("[" + l + " " + timestamp() + "] ")
}

// Widnows WSA error messages are way too long to print
// ex: An established connection was aborted by the software in your host machine.write tcp 127.0.0.1:8100->127.0.0.1:52466: wsasend: An established connection was aborted by the software in your host machine.
func tryShortenWSAError(err interface{}) (ret string) {
	defer recover()

	ret = "not a network error"

	e := err.(*net.OpError).Err.(*os.SyscallError).Err.(syscall.Errno)
	if msg, ok := WSAErrno[int(e)]; ok {
		ret = msg
	} else {
		// messages on linux are short enough
		ret = fmt.Sprintf("C%d, %s", uintptr(e), e.Error())
	}

	return
}

func print(l string, params ...interface{}) {
	l = lead(l)

	for _, p := range params {
		s := fmt.Sprintf("%+v", p)
		switch p.(type) {
		case *net.OpError:
			op := p.(*net.OpError)
			l += fmt.Sprintf("%v -[%s]-> %v, %s", op.Source, op.Op, op.Addr, tryShortenWSAError(p))
		case *net.DNSError:
			op := p.(*net.DNSError)
			l += fmt.Sprintf("lookup: %s, timeout: %v", op.Name, op.IsTimeout)
		default:
			l += (s)
		}
	}

	fmt.Println(l)
}

func L(params ...interface{}) {
	print(" ", params...)
}

func W(params ...interface{}) {
	print("W", params...)
}

func E(params ...interface{}) {
	print("E", params...)
}

func F(params ...interface{}) {
	print("X", params...)
	os.Exit(1)
}
