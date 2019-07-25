package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/coyove/goflyway/proxy"
)

var (
	version    = "__devel__"
	remoteAddr string
	localAddr  string
	addr       string
	cconfig    = &proxy.ClientConfig{}
	sconfig    = &proxy.ServerConfig{}
)

func printHelp(a ...interface{}) {
	if len(a) > 0 {
		fmt.Printf("goflyway: ")
		fmt.Println(a...)
	}
	fmt.Println("usage: goflyway -LhvVkKgptTw [address]")
	os.Exit(0)
}

func main() {
	for i, last := 1, rune(0); i < len(os.Args); i++ {
		p := strings.TrimLeft(os.Args[i], "-")
		if len(p) != len(os.Args[i]) {
			for i, c := range p {
				switch c {
				case 'h':
					printHelp()
				case 'V':
					printHelp(version)
				case 'L', 'g', 'p', 'k', 't', 'T':
					last = c
				case 'v':
				case 'w':
					cconfig.WebSocket = true
				case 'K':
					sconfig.KCP, cconfig.KCP = true, true
				case '=':
					i++
					fallthrough
				default:
					if last == 0 {
						printHelp("illegal option --", string(c))
					}
					p = p[i:]
					goto PARSE
				}
			}
			continue
		}
	PARSE:
		if strings.HasPrefix(p, "\"") {
			if p, _ = strconv.Unquote(p); p == "" {
				printHelp("illegal option --", string(last))
			}
		}
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
				printHelp("illegal option --", string(last), p)
			}
		case 'g':
			sconfig.ProxyPassAddr = p
		case 'T':
			speed, _ := strconv.ParseInt(p, 10, 64)
			sconfig.SpeedThrot = proxy.NewTokenBucket(speed, speed*25)
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
		printHelp("missing address")
	}

	if localAddr != "" && remoteAddr == "" {
		_, port, err1 := net.SplitHostPort(localAddr)
		host, _, err2 := net.SplitHostPort(addr)
		remoteAddr = host + ":" + port
		if err1 != nil || err2 != nil {
			printHelp("invalid address --", localAddr, addr)
		}
	}

	with := ""
	switch {
	case cconfig.WebSocket:
		with = "using websocket"
	case cconfig.KCP, sconfig.KCP:
		with = "using KCP"
	}

	if localAddr != "" && remoteAddr != "" {
		cconfig.Bind = remoteAddr
		cconfig.Upstream = addr

		fmt.Println("goflyway client binds", remoteAddr, "at", addr, "to", localAddr, with)
		panic(proxy.NewClient(localAddr, cconfig))
	} else {
		fmt.Println("goflyway server listens on", addr, with)
		panic(proxy.NewServer(addr, sconfig))
	}
}
