package xl

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

type Logger struct {
	Verbose byte
}

func (l *Logger) print(lv string, args ...interface{}) {
	p := bytes.Buffer{}
	p.WriteByte('<')
	p.WriteString(lv)

	t := time.Now().Format("2006-01-02T15:04:05Z")
	p.WriteString(` t="` + t + `"`)

	if l.Verbose == 'v' || l.Verbose == 'V' {
		_, fn, line, _ := runtime.Caller(3)
		p.WriteString(` src="` + filepath.Base(fn) + ":" + strconv.Itoa(line) + `"`)
	}

	p.WriteByte('>')

	for i, arg := range args {
		switch op := arg.(type) {
		case *net.OpError:
			if op.Source == nil && op.Addr == nil {
				p.WriteString("<Type>")
				p.WriteString(op.Op)
				tryShortenWSAError(arg)
			} else {
				args[i] = fmt.Sprintf("%s %v, %s", op.Op, op.Addr, tryShortenWSAError(arg))
			}
		case *net.DNSError:
			x = fmt.Sprintf("DNS lookup failed: %v", op)
			params[i] = x
		default:
		}

	}

	p.WriteString("</")
	p.WriteString(lv)
	p.WriteByte('>')
}
