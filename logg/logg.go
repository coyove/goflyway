package logg

import (
	"fmt"
	"net"
	"os"
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

func print(l string, params ...interface{}) {
	l = lead(l)

	for _, p := range params {
		s := fmt.Sprintf("%+v", p)

		if _, ok := p.(error); ok {
			op, ok := p.(*net.OpError)
			if ok {

				l += fmt.Sprintf("src: %v, addr: %v, op: %s\n", op.Source, op.Addr, op.Op)
				s = fmt.Sprintf("%serr: %+v", lead("^"), op.Err)
			}

			if len(s) > 120 {
				s = s[:120] + "..."
			}
		}

		l += (s)
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
