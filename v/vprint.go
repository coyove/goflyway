package v

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	Verbose    = 0
	Stacktrace = new(int)
	FloatPrec  = 3
)

func Eprint(v ...interface{}) { vprint(0, v...) }

func Vprint(v ...interface{}) { vprint(1, v...) }

func VVprint(v ...interface{}) { vprint(2, v...) }

func VVVprint(v ...interface{}) { vprint(3, v...) }

func vprint(b int, v ...interface{}) {
	if b > Verbose {
		return
	}

	for i := range v {
		if err, _ := v[i].(error); err != nil {
			v[i] = tryShortenWSAError(err)
		}
		if num, ok := v[i].(float64); ok && float64(int64(num)) != num {
			v[i] = strconv.FormatFloat(num, 'f', FloatPrec, 64)
		}
		if num, ok := v[i].(float32); ok && float32(int32(num)) != num {
			v[i] = strconv.FormatFloat(float64(num), 'f', FloatPrec, 64)
		}
		if v[i] == Stacktrace {
			p := bytes.Buffer{}
			pc := make([]uintptr, 32)
			n := runtime.Callers(3, pc)
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

	var (
		_, fn, line, _ = runtime.Caller(2)
		str            = strings.TrimRightFunc(fmt.Sprint(v...), trimNewline)
		now            = time.Now()
		lead           = "dbg" + strconv.Itoa(b)
		out            = os.Stdout
	)

	if b == 0 {
		lead, out = "error", os.Stderr
	}

	fmt.Fprintf(out, lead+" %s%02d %02d:%02d:%02d %s:%-3d ] %s\n",
		"123456789OXZ"[now.Month()-1:now.Month()], now.Day(), now.Hour(), now.Minute(), now.Second(),
		filepath.Base(fn), line, str)
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

func trimNewline(r rune) bool {
	return r == '\r' || r == '\n'
}
