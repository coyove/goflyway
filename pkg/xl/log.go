package xl

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

var M interface{} = new(int)

type xmlbuffer struct {
	stack  []string
	indent bool
	buf    bytes.Buffer
}

func (x *xmlbuffer) windent() {
	const tabs = "\t\t\t\t\t\t\t\t"
	if x.indent {
		x.buf.WriteString(tabs[:len(x.stack)])
	}
}

func (x *xmlbuffer) Begin(tag string, attrs ...string) {
	x.windent()
	x.buf.WriteByte('<')
	x.buf.WriteString(tag)
	for i := 0; i < len(attrs); i += 2 {
		k, v := attrs[i], attrs[i+1]
		x.buf.WriteByte(' ')
		x.buf.WriteString(k)
		x.buf.WriteString(`="`)
		xml.EscapeText(&x.buf, []byte(v))
		x.buf.WriteString(`"`)
	}
	x.buf.WriteByte('>')

	if x.indent {
		x.buf.WriteByte('\n')
	}

	if x.stack == nil {
		x.stack = []string{tag}
	} else {
		x.stack = append(x.stack, tag)
	}
}

func (x *xmlbuffer) Write(raw string) {
	x.windent()
	xml.EscapeText(&x.buf, []byte(raw))
	if x.indent {
		x.buf.WriteByte('\n')
	}
}

func (x *xmlbuffer) End() {
	tag := x.stack[len(x.stack)-1]
	x.stack = x.stack[:len(x.stack)-1]
	x.windent()
	x.buf.WriteByte('<')
	x.buf.WriteByte('/')
	x.buf.WriteString(tag)
	x.buf.WriteByte('>')

	if x.indent {
		x.buf.WriteByte('\n')
	}

}

func (x *xmlbuffer) EndAll() {
	for len(x.stack) > 0 {
		x.End()
	}
}

func (x *xmlbuffer) OneLine(tag string, value string) {
	i := x.indent
	x.windent()
	x.indent = false
	x.buf.WriteByte('<')
	x.buf.WriteString(tag)
	x.buf.WriteByte('>')
	x.Write(value)
	x.buf.WriteByte('<')
	x.buf.WriteByte('/')
	x.buf.WriteString(tag)
	x.buf.WriteByte('>')

	if i {
		x.buf.WriteByte('\n')
	}
	x.indent = i
}

type Logger struct {
	Verbose byte
}

func (l *Logger) print(lv string, args ...interface{}) {
	if l == nil {
		return
	}
	if lv == "Debug" && l.Verbose != 'V' {
		return
	}
	if lv == "Info" && l.Verbose != 'V' && l.Verbose != 'v' {
		return
	}

	p := xmlbuffer{indent: lv == "Error"}

	t := time.Now().Format("2006-01-02T15:04:05Z")

	if l.Verbose == 'v' || l.Verbose == 'V' {
		_, fn, line, _ := runtime.Caller(2)
		p.Begin(lv, "time", t, "src", filepath.Base(fn)+":"+strconv.Itoa(line))
	} else {
		p.Begin(lv, "time", t)
	}

	for i := 0; i < len(args); i += 2 {
		key := args[i].(string)
		p.Begin(key)
		arg := args[i+1]
		if arg == M {
			continue
		}

		switch op := arg.(type) {
		case *net.OpError:
			p.OneLine("Type", op.Op)

			if op.Source != nil {
				p.OneLine("Source", op.Source.String())
			}

			if op.Addr != nil {
				p.OneLine("Address", op.Addr.String())
			}

			p.OneLine("Message", (tryShortenWSAError(arg)))
		default:
			p.Write(fmt.Sprintf("%v", arg))
		}
		p.End()
	}

	p.EndAll()
	fmt.Println(p.buf.String())
}

func (l *Logger) Dbg(args ...interface{})  { l.print("Debug", args...) }
func (l *Logger) Info(args ...interface{}) { l.print("Info", args...) }
func (l *Logger) Err(args ...interface{})  { l.print("Error", args...) }

func (l *Logger) If(b bool) *Logger {
	if b {
		return l
	}
	return nil
}

const ERROR = "Error"
const PROTOCOL = "Protocol"
const CIPHER = "Cipher"
const CONFIG = "Config"
const ACL = "ACL"
