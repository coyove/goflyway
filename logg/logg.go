package logg

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

var ignoreLocalhost = true

func RecordLocalhostError(r bool) {
	ignoreLocalhost = !r
}

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
	defer func() {
		if recover() != nil {
			ret = fmt.Sprintf("%v", err)
		}
	}()

	if e, sysok := err.(*net.OpError).Err.(*os.SyscallError); sysok {
		errno := e.Err.(syscall.Errno)
		if msg, ok := WSAErrno[int(errno)]; ok {
			ret = msg
		} else {
			// messages on linux are short enough
			ret = fmt.Sprintf("C%d, %s", uintptr(errno), e.Error())
		}

		return
	}

	ret = err.(*net.OpError).Err.Error()
	return
}

func print(l string, params ...interface{}) {
	l = lead(l)

	for _, p := range params {
		switch p.(type) {
		case *net.OpError:
			op := p.(*net.OpError)
			if ignoreLocalhost && op.Source != nil && op.Addr != nil {
				if strings.Split(op.Source.String(), ":")[0] == strings.Split(op.Addr.String(), ":")[0] {
					return
				}
			}

			if op.Source == nil && op.Addr == nil {
				l += fmt.Sprintf("%s, %s", op.Op, tryShortenWSAError(p))
			} else if op.Source == nil {
				l += fmt.Sprintf("[%s]-> %v, %s", op.Op, op.Addr, tryShortenWSAError(p))
			} else {
				l += fmt.Sprintf("%v -[%s]-> %v, %s", op.Source, op.Op, op.Addr, tryShortenWSAError(p))
			}
		case *net.DNSError:
			op := p.(*net.DNSError)
			if op.IsTimeout {
				l += fmt.Sprintf("dns lookup: %s", op.Name)
			} else {
				l += fmt.Sprintf("dns lookup: %s, timed out", op.Name)
			}
		default:
			l += fmt.Sprintf("%+v", p)
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
