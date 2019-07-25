package v

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var (
	Verbose    = true
	Stacktrace = new(int)
)

func Vprint(v ...interface{}) {
	if !Verbose {
		return
	}

	for i := range v {
		if err, _ := v[i].(error); err != nil {
			v[i] = tryShortenWSAError(err)
		}
		if v[i] == Stacktrace {
			p := bytes.Buffer{}
			pc := make([]uintptr, 32)
			n := runtime.Callers(2, pc)
			frame := runtime.CallersFrames(pc[:n])

			for {
				f, ok := frame.Next()
				if !ok {
					break
				}
				idx := strings.Index(f.File, "/src/")
				if idx == -1 {
					break
				}
				f.File = f.File[idx+5:]

				for i, fn := 0, f.File; i < len(fn) && i < len(f.Function); {
					if fn[i] == f.Function[i] {
						fn, f.Function = fn[1:], f.Function[1:]
					} else {
						break
					}
				}

				p.WriteString(fmt.Sprintf("%s%s:%d---", f.File, f.Function, f.Line))
			}
			if p.Len() > 3 {
				p.Truncate(p.Len() - 3)
			}
			v[i] = p.String()
		}
	}

	_, fn, line, _ := runtime.Caller(1)
	now := time.Now().Format("Jan _2 15:04:05.000")
	str := fmt.Sprint(v...)
	fmt.Fprintf(os.Stdout, "%s %s:%d] %s\n", now, filepath.Base(fn), line, str)
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
