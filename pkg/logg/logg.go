package logg

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var ignoreLocalhost = true
var fatalAsError = false
var logLevel = 0
var started = false
var logCallback func(ts int64, msg string)

func RecordLocalhostError(r bool) {
	ignoreLocalhost = !r
}

func SetLevel(lv string) {
	switch lv {
	case "dbg":
		logLevel = -1
	case "log":
		logLevel = 0
	case "warn":
		logLevel = 1
	case "err":
		logLevel = 2
	case "off":
		logLevel = 3
	case "pp":
		logLevel = 99
	default:
		panic("unexpected log level: " + lv)
	}
}

func SetCallback(f func(ts int64, msg string)) {
	logCallback = f
}

func TreatFatalAsError(flag bool) {
	fatalAsError = flag
}

func timestamp() string {
	t := time.Now()
	mil := t.UnixNano() % 1e9
	mil /= 1e6

	return fmt.Sprintf("%02d%02d %02d:%02d:%02d.%03d", t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), mil)
}

func lead(l string) string {
	return ("[" + timestamp() + " " + l + "] ")
}

func trunc(fn string) string {
	idx := strings.LastIndex(fn, "/")
	if idx == -1 {
		idx = strings.LastIndex(fn, "\\")
	}

	fn = fn[idx+1:]
	if strings.HasSuffix(fn, ".go") {
		fn = fn[:len(fn)-3]
	}

	return fn
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

type msg_t struct {
	dst     string
	lead    string
	ts      int64
	message string
}

var msgQueue = make(chan msg_t)

func print(l string, params ...interface{}) {
	_, fn, line, _ := runtime.Caller(2)
	m := msg_t{lead: lead(fmt.Sprintf("%s:%03d%s", trunc(fn), line, strings.ToLower(l))), ts: time.Now().UnixNano()}

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
				m.message += fmt.Sprintf("%s, %s", op.Op, tryShortenWSAError(p))
			} else {
				m.message += fmt.Sprintf("%s %v, %s", op.Op, op.Addr, tryShortenWSAError(p))

				if op.Source != nil && op.Addr != nil {
					m.dst, _, _ = net.SplitHostPort(op.Addr.String())
				}
			}
		case *net.DNSError:
			op := p.(*net.DNSError)

			if m.message += fmt.Sprintf("dns lookup err: %s", op.Name); op.IsTimeout {
				m.message += ", timed out"
			}
		default:
			m.message += fmt.Sprintf("%+v", p)
		}
	}

	msgQueue <- m
}

func Start() {
	if started {
		return
	}

	started = true
	go func() {
		var count int
		var lastMsg *msg_t
		var lastTime time.Time = time.Now()

		for {
		L:
			for {
				select {
				case m := <-msgQueue:
					if lastMsg != nil {
						if (m.dst != "" && m.dst == lastMsg.dst) || m.message == lastMsg.message {
							if time.Now().Sub(lastTime).Seconds() < 5.0 {
								count++

								if count < 100 {
									continue L
								}
							}
						}

						if count > 0 {
							str := fmt.Sprintf(strings.Repeat(" ", len(m.lead))+"... %d similar message(s)", count)
							if logCallback != nil {
								logCallback(m.ts, str)
							} else {
								fmt.Println(str)
							}
						}
					}

					if logCallback != nil {
						logCallback(m.ts, m.lead+m.message)
					} else {
						fmt.Println(m.lead + m.message)
					}
					lastMsg, lastTime, count = &m, time.Now(), 0
				default:
					// nothing in queue to print, quit loop
					break L
				}
			}

			time.Sleep(200 * time.Millisecond)
		}
	}()
}

func D(params ...interface{}) {
	if logLevel <= -1 {
		print("D", params...)
	}
}

func L(params ...interface{}) {
	if logLevel <= 0 {
		print("_", params...)
	}
}

func W(params ...interface{}) {
	if logLevel <= 1 {
		print("W", params...)
	}
}

func E(params ...interface{}) {
	if logLevel <= 2 {
		print("E", params...)
	}
}

func P(params ...interface{}) {
	if logLevel == 99 {
		print("P", params...)
	}
}

func F(params ...interface{}) {
	print("X", params...)

	if !fatalAsError {
		os.Exit(1)
	}
}
