package lib

import (
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

	fmt.Print(Prefix + " ")

	for _, arg := range args {
		s := fmt.Sprintf("%v", arg)
		p := strings.Split(s, "\n")

		fmt.Print(p[0])

		for i := 1; i < len(p); i++ {
			fmt.Println()
			fmt.Print(Prefix + " ")
			fmt.Print(p[i])
		}

		fmt.Print(" ")
	}
	fmt.Println()
}

func PrintInErr(args ...interface{}) {
	for _, arg := range args {
		os.Stderr.WriteString(fmt.Sprintf("%v", arg))
	}
}
