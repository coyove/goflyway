package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coyove/common/sched"
	"github.com/coyove/goflyway"
	"github.com/coyove/goflyway/v"
)

var (
	version      = "__devel__"
	remoteAddr   string
	localAddr    string
	addr         string
	resetTraffic bool
	cconfig      = &goflyway.ClientConfig{}
	sconfig      = &goflyway.ServerConfig{}
)

func printHelp(a ...interface{}) {
	if len(a) > 0 {
		fmt.Printf("goflyway: ")
		fmt.Println(a...)
	}
	fmt.Println("usage: goflyway -DLhHUvkqpPtTwWy address:port")
	os.Exit(0)
}

func main() {
	sched.Verbose = false

	for i, last := 1, rune(0); i < len(os.Args); i++ {
		p := strings.TrimLeft(os.Args[i], "-")

		// HACK: ss-local compatible command flags
		if p == "fast-open" || p == "V" || p == "u" || p == "m" || p == "b" {
			if i < len(os.Args)-1 && !strings.HasPrefix(os.Args[i+1], "-") {
				i++
			}
			continue
		}

		if len(p) != len(os.Args[i]) {
			for i, c := range p {
				switch c {
				case 'h':
					printHelp()
				//case 'V':
				//	printHelp(version)
				case 'L', 'P', 'p', 'k', 't', 'T', 'W', 'H', 'U', 'D', 'c':
					last = c
				case 'v':
					v.Verbose++
				case 'q':
					v.Verbose = -1
				case 'w':
					cconfig.WebSocket = true
				case 'y':
					resetTraffic = true
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
		case 'D':
			cconfig.Dynamic = true
			fallthrough
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
		case 'P':
			sconfig.ProxyPassAddr = p
		case 'U':
			cconfig.PathPattern = p
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
		case 'H':
			cconfig.URLHeader = p
		case 'c':
			buf, _ := ioutil.ReadFile(p)
			cmds := make(map[string]interface{})
			json.Unmarshal(buf, &cmds)
			cconfig.Key, cconfig.VPN = cmds["password"].(string), true
			addr = fmt.Sprintf("%v:%v", cmds["server"], cmds["server_port"])

			v.Verbose = 3
			v.Vprint(os.Args, " config: ", cmds)
		default:
			addr = p
		}
		last = 0
	}

	if addr == "" {
		if localAddr == "" {
			v.Vprint("assume you want a default server at :8100")
			addr = ":8100"
		} else {
			printHelp("missing address:port to listen/connect")
		}
	}

	if localAddr != "" && remoteAddr == "" {
		_, port, err1 := net.SplitHostPort(localAddr)
		host, _, err2 := net.SplitHostPort(addr)
		remoteAddr = host + ":" + port
		if err1 != nil || err2 != nil {
			printHelp("invalid address --", localAddr, addr)
		}
	}

	if localAddr != "" && remoteAddr != "" {
		cconfig.Bind = remoteAddr
		cconfig.Upstream = addr
		cconfig.Stat = &goflyway.Traffic{}

		if v.Verbose > 0 {
			go watchTraffic(cconfig, resetTraffic)
		}
		if cconfig.Dynamic {
			v.Vprint("dynamic: forward ", localAddr, " to * through ", addr)
		} else {
			v.Vprint("forward ", localAddr, " to ", remoteAddr, " through ", addr)
		}
		if cconfig.WebSocket {
			v.Vprint("relay: use Websocket protocol")
		}
		if a := os.Getenv("http_proxy") + os.Getenv("HTTP_PROXY"); a != "" {
			v.Vprint("note: system HTTP proxy is set to: ", a)
		}
		if a := os.Getenv("https_proxy") + os.Getenv("HTTPS_PROXY"); a != "" {
			v.Vprint("note: system HTTPS proxy is set to: ", a)
		}

		v.Eprint(goflyway.NewClient(localAddr, cconfig))
	} else {
		v.Vprint("server listen on ", addr)
		v.Eprint(goflyway.NewServer(addr, sconfig))
	}
}

func watchTraffic(cconfig *goflyway.ClientConfig, reset bool) {
	path := filepath.Join(os.TempDir(), "goflyway_traffic")

	tmpbuf, _ := ioutil.ReadFile(path)
	if len(tmpbuf) != 16 || reset {
		tmpbuf = make([]byte, 16)
	}

	cconfig.Stat.Set(int64(binary.BigEndian.Uint64(tmpbuf)), int64(binary.BigEndian.Uint64(tmpbuf[8:])))

	var lastSent, lastRecv int64
	for range time.Tick(time.Second * 5) {
		s, r := *cconfig.Stat.Sent(), *cconfig.Stat.Recv()
		sv, rv := float64(s-lastSent)/1024/1024/5, float64(r-lastRecv)/1024/1024/5
		lastSent, lastRecv = s, r

		if sv >= 0.001 || rv >= 0.001 {
			v.Vprint("client send: ", float64(s)/1024/1024, "M (", sv, "M/s), recv: ", float64(r)/1024/1024, "M (", rv, "M/s)")
		}

		binary.BigEndian.PutUint64(tmpbuf, uint64(s))
		binary.BigEndian.PutUint64(tmpbuf[8:], uint64(r))
		ioutil.WriteFile(path, tmpbuf, 0644)
	}
}
