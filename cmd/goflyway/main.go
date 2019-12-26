package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coyove/common/sched"
	"github.com/coyove/goflyway"
	"github.com/coyove/goflyway/v"
	"golang.org/x/crypto/acme/autocert"
)

var (
	version      = "__devel__"
	remoteAddr   string
	localAddr    string
	addr         string
	httpsProxy   string
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
			httpsProxy = p
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
	} else if httpsProxy != "" {
		v.Vprint("server listen on ", addr, " (https://", httpsProxy, ")")
		m := &autocert.Manager{
			Cache:      autocert.DirCache("secret-dir"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(httpsProxy),
		}
		s := &http.Server{
			Addr:      addr,
			TLSConfig: m.TLSConfig(),
		}
		for i, p := range s.TLSConfig.NextProtos {
			if p == "h2" {
				s.TLSConfig.NextProtos[i] = "h2-disabled"
			}
		}
		s.Handler = &connector{
			realm: "R" + strconv.FormatInt(time.Now().Unix(), 16),
		}
		v.Eprint(s.ListenAndServeTLS("", ""))
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

type connector struct {
	realm     string
	whitelist sync.Map
}

func (c *connector) getClientIP(r *http.Request) string {
	clientIP := r.Header.Get("X-Forwarded-For")
	clientIP = strings.TrimSpace(strings.Split(clientIP, ",")[0])
	if clientIP == "" {
		clientIP = strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	}
	if clientIP != "" {
		return clientIP
	}
	if ip, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return ip
	}
	return ""
}

func (c *connector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/"+sconfig.Key {
		ip := r.UserAgent()
		if ip == "" {
			w.WriteHeader(400)
			return
		}
		c.whitelist.Store(ip, true)
		w.WriteHeader(200)
		w.Write([]byte("ok"))
		return
	}

	plain := false

	if r.URL.Hostname() == httpsProxy {
		// we proxy the traffic to ourselves without auth
		goto OK
	}

	if parts := strings.Split(r.Header.Get("Proxy-Authorization"), " "); len(parts) == 2 {
		pa, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
		if string(pa) == "admin:"+sconfig.Key {
			goto OK
		}
	}

	if _, ok := c.whitelist.Load(r.UserAgent()); ok {
		w.Header().Set("Proxy-Authenticate", "Basic realm="+c.realm)
		w.WriteHeader(http.StatusProxyAuthRequired)
	} else {
		w.WriteHeader(400)
	}
	return

OK:
	if r.Method != "CONNECT" {
		if r.URL.Host == "" {
			w.WriteHeader(404)
			return
		}

		v.VVprint("plain http proxy: ", r.URL)
		plain = true
	}

	// we are inside GFW and should pass data to upstream
	host := r.URL.Host
	if !regexp.MustCompile(`:\d+$`).MatchString(host) {
		if plain {
			host += ":80"
		} else {
			host += ":443"
		}
	}

	up, err := net.DialTimeout("tcp", host, sconfig.Timeout)
	if err != nil {
		v.Eprint(host, err)
		w.WriteHeader(500)
		return
	}

	hij, _ := w.(http.Hijacker) // No HTTP2
	proxyClient, _, err := hij.Hijack()
	if err != nil {
		v.Eprint(host, err)
		w.WriteHeader(500)
		return
	}

	if plain {
		req, _ := httputil.DumpRequestOut(r, false)
		io.Copy(up, io.MultiReader(bytes.NewReader(req), r.Body))
	} else {
		proxyClient.Write([]byte("HTTP/1.0 200 Connection Established\r\n\r\n"))
	}

	go func() {
		wait := make(chan bool)
		go func() {
			if err, to := bridge(proxyClient, up, sconfig.Timeout); err != nil {
				v.Eprint(err)
			} else if to {
				v.VVprint(host, " server read timedout")
			}
			wait <- true
		}()
		if err, to := bridge(up, proxyClient, sconfig.Timeout); err != nil {
			v.Eprint(err)
		} else if to {
			v.VVprint(host, " client read timedout")
		}
		select {
		case <-wait:
		}
		proxyClient.Close()
		up.Close()
	}()
}

func bridge(dst, src net.Conn, t time.Duration) (err error, timedout bool) {
	buf := make([]byte, 1024*64)
	for {
		if t > 0 {
			src.SetDeadline(time.Now().Add(t))
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if ne, _ := er.(net.Error); ne != nil && ne.Timeout() {
				timedout = true
				break
			}
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

func readUntil(r io.Reader, eoh string) ([]byte, error) {
	buf, respbuf := make([]byte, 1), &bytes.Buffer{}
	eidx, found := 0, false

	for {
		n, err := r.Read(buf)
		if n == 1 {
			respbuf.WriteByte(buf[0])
		}

		if buf[0] == eoh[eidx] {
			if eidx++; eidx == len(eoh) {
				found = true
				break
			}
		} else {
			eidx = 0
		}

		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("readUntil cannot find the pattern: %v", []byte(eoh))
	}

	return respbuf.Bytes(), nil
}
