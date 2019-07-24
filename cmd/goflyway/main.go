package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/coyove/goflyway/proxy"
)

var version = "__devel__"

func printHelp() {
	fmt.Println("usage: goflyway")
	os.Exit(0)
}

func main() {
	var (
		remoteAddr string
		localAddr  string
		addr       string
		cconfig    = &proxy.ClientConfig{}
		sconfig    = &proxy.ServerConfig{}
	)

	for i, last := 1, rune(0); i < len(os.Args); i++ {
		p := strings.TrimLeft(os.Args[i], "-")
		if len(p) != len(os.Args[i]) {
			for i, c := range p {
				switch c {
				case 'h':
					printHelp()
				case 'V':
					fmt.Println("goflyway v2 (" + version + ")")
					os.Exit(0)
				case 'L', 'g', 'p', 'k', 't':
					last = c
				case 'v':
				case 'K':
					sconfig.KCP, cconfig.KCP = true, true
				default:
					if last == 0 {
						fmt.Println("goflyway: illegal option --", string(c))
						printHelp()
					}
					p = p[i:]
					goto PARSE
				}
			}
			continue
		}
	PARSE:
		switch last {
		case 'L':
			switch parts := strings.Split(p, ":"); len(parts) {
			case 1:
				localAddr = ":" + parts[0]
			case 2:
				localAddr = p
			case 3:
				localAddr, remoteAddr = ":"+parts[0], parts[1]+":"+parts[2]
			case 4:
				localAddr, remoteAddr = parts[0]+":"+parts[1], parts[2]+":"+parts[3]
			default:
				fmt.Println("goflyway: illegal option --", string(last), p)
				printHelp()
			}
		case 'g':
			sconfig.ProxyPassAddr = p
		case 't':
			*(*int64)(&cconfig.Timeout), _ = strconv.ParseInt(p+"000000000", 10, 64)
			sconfig.Timeout = cconfig.Timeout
		case 'p', 'k':
			sconfig.Key, cconfig.Key = p, p
		default:
			addr = p
		}
		last = 0
	}

	if addr == "" {
		fmt.Println("goflyway: missing address")
		printHelp()
	}

	if localAddr != "" && remoteAddr == "" {
		_, port, err1 := net.SplitHostPort(localAddr)
		host, _, err2 := net.SplitHostPort(addr)
		remoteAddr = host + ":" + port
		if err1 != nil || err2 != nil {
			fmt.Println("goflyway: invalid address --", localAddr, addr)
			printHelp()
		}
	}

	if localAddr != "" && remoteAddr != "" {
		cconfig.Bind = remoteAddr
		cconfig.Upstream = addr
		log.Println(proxy.NewClient(localAddr, cconfig))
	} else {
		log.Println(proxy.NewServer(addr, sconfig))
	}
}
