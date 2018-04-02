package lib

import (
	"fmt"
	"os"
)

var Slient = false

func Println(args ...interface{}) {
	if !Slient {
		fmt.Println(args...)
	}
}

func PrintInErr(args ...interface{}) {
	for _, arg := range args {
		os.Stderr.WriteString(fmt.Sprintf("%v", arg))
	}
}
