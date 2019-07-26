package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coyove/common/sched"
	"github.com/coyove/goflyway"
	"github.com/coyove/goflyway/v"
)

var (
	version    = "__devel__"
	remoteAddr string
	localAddr  string
	addr       string
	cconfig    = &goflyway.ClientConfig{}
	sconfig    = &goflyway.ServerConfig{}
)

func printHelp(a ...interface{}) {
	if len(a) > 0 {
		fmt.Printf("goflyway: ")
		fmt.Println(a...)
	}
	fmt.Println("usage: goflyway -LhIvVkKgptTwW address:port")
	os.Exit(0)
}

func main() {
	sched.Verbose = false

	for i, last := 1, rune(0); i < len(os.Args); i++ {
		p := strings.TrimLeft(os.Args[i], "-")
		if len(p) != len(os.Args[i]) {
			for i, c := range p {
				switch c {
				case 'h':
					printHelp()
				case 'V':
					printHelp(version)
				case 'L', 'g', 'p', 'k', 't', 'T', 'W', 'I':
					last = c
				case 'v':
					v.Verbose++
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
			sconfig.SpeedThrot = goflyway.NewTokenBucket(speed, speed*25)
		case 'W':
			writebuffer, _ := strconv.ParseInt(p, 10, 64)
			sconfig.WriteBuffer, cconfig.WriteBuffer = writebuffer, writebuffer
		case 't':
			*(*int64)(&cconfig.Timeout), _ = strconv.ParseInt(p+"000000000", 10, 64)
			sconfig.Timeout = cconfig.Timeout
		case 'p', 'k':
			sconfig.Key, cconfig.Key = p, p
		case 'I':
			sconfig.URLPath, cconfig.URLPath = p, p
		default:
			addr = p
		}
		last = 0
	}

	if addr == "" {
		printHelp("missing address:port")
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
		cconfig.Stat = &goflyway.Traffic{}

		go func() {
			p := func(v int64) string {
				if v > 1024*1024*1024*10 {
					return fmt.Sprintf("%.3fG", float64(v)/1024/1024/1024)
				}
				return fmt.Sprintf("%.3fM", float64(v)/1024/1024)
			}

			var lastSent, lastRecv int64

			for range time.Tick(time.Second * 5) {
				s, r := *cconfig.Stat.Sent(), *cconfig.Stat.Recv()
				ss := strconv.FormatFloat(float64(s-lastSent)/1024/1024/5, 'f', 3, 64)
				rs := strconv.FormatFloat(float64(r-lastRecv)/1024/1024/5, 'f', 3, 64)
				lastSent, lastRecv = s, r

				v.Vprint("client send: ", p(s), " (", ss, "M/s), recv: ", p(r), " (", rs, "M/s)")
			}
		}()

		fmt.Println("goflyway client binds", remoteAddr, "at", addr, "to", localAddr, with)

		if a := os.Getenv("http_proxy") + os.Getenv("HTTP_PROXY"); a != "" {
			fmt.Println("note: system HTTP proxy is set to:", a)
		}
		if a := os.Getenv("https_proxy") + os.Getenv("HTTPS_PROXY"); a != "" {
			fmt.Println("note: system HTTPS proxy is set to:", a)
		}

		panic(goflyway.NewClient(localAddr, cconfig))
	} else {
		fmt.Println("goflyway server listens on", addr, with)
		panic(goflyway.NewServer(addr, sconfig))
	}
}
