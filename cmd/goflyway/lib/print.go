package lib

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

var Slient = false

var Prefix = "*"

func Println(args ...interface{}) {
	if Slient {
		return
	}

	buf := bytes.Buffer{}
	buf.WriteString(Prefix)
	buf.WriteString(" ")

	for _, arg := range args {
		s := fmt.Sprintf("%v", arg)
		p := strings.Split(s, "\n")

		buf.WriteString(p[0])

		for i := 1; i < len(p); i++ {
			buf.WriteByte('\n')
			buf.WriteString(Prefix)
			buf.WriteByte(' ')
			buf.WriteString(p[i])
		}

		buf.WriteString(" ")
	}
	fmt.Println(buf.String())
}

func PrintInErr(args ...interface{}) {
	for _, arg := range args {
		os.Stderr.WriteString(fmt.Sprintf("%v", arg))
	}
}
