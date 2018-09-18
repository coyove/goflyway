package main

import (
	"compress/gzip"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	_url "net/url"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/coyove/common/config"
	"github.com/coyove/common/logg"
	"github.com/coyove/common/lru"
	"github.com/coyove/goflyway/cmd/goflyway/lib"
	"github.com/coyove/goflyway/pkg/aclrouter"
	"github.com/coyove/goflyway/proxy"

	"flag"
	"fmt"
	"io/ioutil"
	"strings"
)

var version = "__devel__"

var (
	// General flags
	cmdHelp     = flag.Bool("h", false, "Display help message")
	cmdHelp2    = flag.Bool("help", false, "Display detailed help message")
	cmdConfig   = flag.String("c", "", "Config file path")
	cmdLogLevel = flag.String("lv", "log", "Logging level: {dbg, log, warn, err, off}")
	cmdLogFile  = flag.String("lf", "", "Log to file")
	cmdAuth     = flag.String("a", "", "Proxy authentication, form: username:password (remember the colon)")
	cmdKey      = flag.String("k", "0123456789abcdef", "Password, do not use the default one")
	cmdLocal    = flag.String("l", ":8100", "Listening address")
	cmdTimeout  = flag.Int64("t", 20, "Connection timeout in seconds, 0 to disable")
	cmdSection  = flag.String("y", "default", "Section to read in the config, 'cli' to disable")

	// Server flags
	cmdThrot      = flag.Int64("throt", 0, "[S] Traffic throttling in bytes")
	cmdThrotMax   = flag.Int64("throt-max", 1024*1024, "[S] Traffic throttling token bucket max capacity")
	cmdDiableUDP  = flag.Bool("disable-udp", false, "[S] Disable UDP relay")
	cmdProxyPass  = flag.String("proxy-pass", "", "[S] Use goflyway as a reverse HTTP proxy")
	cmdAnswer     = flag.String("answer", "", "[S] Answer client config setup")
	cmdLBindWaits = flag.Int64("lbind-timeout", 5, "[S] Local bind timeout in seconds")

	// Client flags
	cmdGlobal     = flag.Bool("g", false, "[C] Global proxy")
	cmdUpstream   = flag.String("up", "", "[C] Upstream server address")
	cmdPartial    = flag.Bool("partial", false, "[C] Partially encrypt the tunnel traffic")
	cmdUDPonTCP   = flag.Int64("udp-tcp", 1, "[C] Use N TCP connections to relay UDP")
	cmdWebConPort = flag.Int64("web-port", 65536, "[C] Web console listening port, 0 to disable, 65536 to auto select")
	cmdDNSCache   = flag.Int64("dns-cache", 1024, "[C] DNS cache size")
	cmdMux        = flag.Int64("mux", 0, "[C] limit the total number of TCP connections, 0 means no limit")
	cmdVPN        = flag.Bool("vpn", false, "[C] VPN mode, used on Android only")
	cmdACL        = flag.String("acl", "chinalist.txt", "[C] Load ACL file")
	cmdMITMDump   = flag.String("mitm-dump", "", "[C] Dump HTTPS requests to file")
	cmdRemote     = flag.Bool("remote", false, "[C] Get config setup from the upstream")
	cmdBind       = flag.String("bind", "", "[C] Bind to an address at server")
	cmdLBind      = flag.String("lbind", "", "[C] Bind a local address to server")
	cmdGenCA      = flag.Bool("gen-ca", false, "[C] Generate certificate (ca.pem) and private key (key.pem)")

	// curl flags
	cmdVerbose    = flag.Bool("v", false, "[Cu] Verbose output")
	cmdForm       = flag.String("F", "", "[Cu] Post form")
	cmdHeaders    = flag.String("H", "", "[Cu] Headers")
	cmdCookie     = flag.String("C", "", "[Cu] Cookies")
	cmdMultipart  = flag.Bool("M", false, "[Cu] Multipart")
	cmdPrettyJSON = flag.Bool("pj", false, "[Cu] JSON pretty output")

	// Shadowsocks compatible flags
	cmdLocal2 = flag.String("p", "", "Server listening address")

	// Shadowsocks-android compatible flags, no meanings
	_ = flag.Bool("u", true, "-- Placeholder --")
	_ = flag.String("m", "", "-- Placeholder --")
	_ = flag.String("b", "", "-- Placeholder --")
	_ = flag.Bool("V", true, "-- Placeholder --")
	_ = flag.Bool("fast-open", true, "-- Placeholder --")
)

func loadConfig() {
	if *cmdSection == "cli" {
		return
	}

	path := *cmdConfig
	if path == "" {
		if runtime.GOOS == "windows" {
			path = os.Getenv("USERPROFILE") + "/gfw.conf"
		} else {
			path = os.Getenv("HOME") + "/gfw.conf"
		}
	}

	if _, err := os.Stat(path); err != nil {
		return
	}

	buf, err := ioutil.ReadFile(path)
	if err != nil {
		lib.Println("Can't load config file:", err)
		return
	}

	if strings.Contains(path, "shadowsocks.conf") {
		lib.Println("Read shadowsocks config")

		cmds := make(map[string]interface{})
		if err := json.Unmarshal(buf, &cmds); err != nil {
			lib.Println("Can't parse config file:", err)
			return
		}

		*cmdKey = cmds["password"].(string)
		*cmdUpstream = fmt.Sprintf("%v:%v", cmds["server"], cmds["server_port"])
		if port := int(cmds["server_port"].(float64)); port > 50000 {
			*cmdRemote = true
			*cmdUpstream = fmt.Sprintf("%v:%v", cmds["server"], port-50000)
		}
		*cmdMux = 10
		*cmdLogLevel = "dbg"
		*cmdVPN = true
		*cmdGlobal = true
		return
	}

	cf, err := config.ParseConf(string(buf))
	if err != nil {
		lib.Println("Can't parse config file:", err)
		return
	}

	lib.Println("reading config section:", *cmdSection)
	func(args ...interface{}) {
		for i := 0; i < len(args); i += 2 {
			switch f, name := args[i+1], strings.TrimSpace(args[i].(string)); f.(type) {
			case *string:
				*f.(*string) = cf.GetString(*cmdSection, name, *f.(*string))
			case *int64:
				*f.(*int64) = cf.GetInt(*cmdSection, name, *f.(*int64))
			case *bool:
				*f.(*bool) = cf.GetBool(*cmdSection, name, *f.(*bool))
			}
		}
	}(
		"password   ", cmdKey,
		"auth       ", cmdAuth,
		"listen     ", cmdLocal,
		"upstream   ", cmdUpstream,
		"disableudp ", cmdDiableUDP,
		"udptcp     ", cmdUDPonTCP,
		"global     ", cmdGlobal,
		"acl        ", cmdACL,
		"partial    ", cmdPartial,
		"timeout    ", cmdTimeout,
		"mux        ", cmdMux,
		"proxypass  ", cmdProxyPass,
		"webconport ", cmdWebConPort,
		"dnscache   ", cmdDNSCache,
		"loglevel   ", cmdLogLevel,
		"logfile    ", cmdLogFile,
		"throt      ", cmdThrot,
		"throtmax   ", cmdThrotMax,
		"bind       ", cmdBind,
		"lbind      ", cmdLBind,
		"lbindwaits ", cmdLBindWaits,
		"mitmdump   ", cmdMITMDump,
		"remote     ", cmdRemote,
		"answer     ", cmdAnswer,
	)
}

var logger *logg.Logger

func main() {
	method, url := lib.ParseExtendedOSArgs()
	flag.Parse()
	if *cmdHelp2 {
		flag.Usage()
		return
	}

	if *cmdHelp {
		fmt.Println("Client: \n\t./goflyway -up SERVER_IP:SERVER_PORT -k PASSWORD")
		fmt.Println("Server: \n\t./goflyway -l :SERVER_PORT -k PASSWORD")
		return
	}

	logger = &logg.Logger{}
	logger.SetLevel(*cmdLogLevel)

	if *cmdLogFile != "" {
		logger.LogFile(*cmdLogFile, 1024*1024*1)
	}

	lib.Slient = (method != "" && !*cmdVerbose)
	logger.L("Start goflyway", "build "+version)
	loadConfig()

	if *cmdGenCA {
		lib.Println("Generating CA...")

		cert, key, err := lib.GenCA("goflyway")
		if err != nil {
			lib.Println(err)
			return
		}

		err1, err2 := ioutil.WriteFile("ca.pem", cert, 0755), ioutil.WriteFile("key.pem", key, 0755)
		if err1 != nil || err2 != nil {
			lib.Println("Error ca.pem:", err1)
			lib.Println("Error key.pem:", err2)
			return
		}

		lib.Println("Successfully generated ca.pem/key.pem, please leave them in the same directory with goflyway")
		lib.Println("They will be automatically read when goflyway launched as client")
		return
	}

	if *cmdUpstream != "" {
		lib.Println("Launched as client")
	} else {
		lib.Println("Launched as server (aka upstream)")
	}

	if *cmdKey == "0123456789abcdef" {
		lib.Println("You are using the default password, please change it: -k=<NEW PASSWORD>")
	}

	cipher := &proxy.Cipher{Partial: *cmdPartial}
	cipher.Init(*cmdKey)
	cipher.IO.Logger =logger

	var cc *proxy.ClientConfig
	var sc *proxy.ServerConfig

	if *cmdMux > 0 {
		lib.Println("TCP multiplexer enabled, limit:", *cmdMux)
	}

	if *cmdUpstream != "" {
		acl, err := aclrouter.LoadACL(*cmdACL)
		if err != nil {
			lib.Println("Failed to read ACL config (but it's fine, you can ignore this message)")
			lib.Println("  Err:", err)
		}

		for _, r := range acl.OmitRules {
			lib.Println("ACL omit rule:", r)
		}

		cc = &proxy.ClientConfig{}
		cc.Cipher = cipher
		cc.DNSCache = lru.NewCache(*cmdDNSCache)
		cc.CACache = lru.NewCache(256)
		cc.ACL = acl
		cc.UserAuth = *cmdAuth
		cc.UDPRelayCoconn = int(*cmdUDPonTCP)
		cc.Mux = int(*cmdMux)
		cc.Upstream = *cmdUpstream
		cc.LocalRPBind = *cmdLBind
		cc.Logger = logger
		parseUpstream(cc, *cmdUpstream)

		if *cmdGlobal {
			lib.Println("Global proxy enabled, ignore all private IPs")
			cc.Policy.Set(proxy.PolicyGlobal)
		}

		if *cmdVPN {
			cc.Policy.Set(proxy.PolicyVPN)
		}

		if *cmdMITMDump != "" {
			cc.MITMDump, _ = os.Create(*cmdMITMDump)
		}
	}

	if *cmdUpstream == "" {
		sc = &proxy.ServerConfig{
			Cipher:        cipher,
			Throttling:    *cmdThrot,
			ThrottlingMax: *cmdThrotMax,
			ProxyPassAddr: *cmdProxyPass,
			DisableUDP:    *cmdDiableUDP,
			ClientAnswer:  *cmdAnswer,
			LBindTimeout:  *cmdLBindWaits,
			Logger:        logger,
		}

		if *cmdAuth != "" {
			sc.Users = map[string]proxy.UserConfig{
				*cmdAuth: {},
			}
		}
	}

	if *cmdTimeout > 0 {
		cipher.IO.StartPurgeConns(int(*cmdTimeout))
	}

	var localaddr string
	if *cmdLocal2 != "" {
		// -p has higher priority than -l, for the sack of SS users
		localaddr = *cmdLocal2
	} else {
		localaddr = *cmdLocal
	}

	if *cmdUpstream != "" {
		client := proxy.NewClient(localaddr, cc)

		if *cmdRemote {
			lib.Println("Get config from the upstream")
			cm := client.GetRemoteConfig()
			if cm == "" {
				logger.F("Can't get remote config")
			}

			parseUpstream(cc, cm)
			client = proxy.NewClient(localaddr, cc)
		}

		if method != "" {
			curl(client, method, url, nil)
		} else if *cmdBind != "" {
			lib.Println("Bind", localaddr, "to", *cmdBind)
			ln, err := net.Listen("tcp", localaddr)
			if err != nil {
				logger.F(err)
			}
			for {
				conn, err := ln.Accept()
				if err != nil {
					logger.E(err)
					continue
				}
				logger.L("Bridge", conn.LocalAddr().String(), *cmdBind)
				client.Bridge(conn, *cmdBind)
			}
		} else {
			if *cmdLBind != "" {
				lib.Println("Local reverse proxy", client.Cipher.Alias, "bind [", client.ClientConfig.LocalRPBind, "], upstream: [", client.Upstream, "]")
				logger.F(client.StartLocalRP())
			} else {
				if *cmdWebConPort != 0 {
					go func() {
						addr := fmt.Sprintf("127.0.0.1:%d", *cmdWebConPort)
						if *cmdWebConPort == 65536 {
							_addr, _ := net.ResolveTCPAddr("tcp", client.Localaddr)
							addr = fmt.Sprintf("127.0.0.1:%d", _addr.Port+10)
						}

						http.HandleFunc("/", lib.WebConsoleHTTPHandler(client))
						lib.Println("Access client web console at [", addr, "]")
						logger.F(http.ListenAndServe(addr, nil))
					}()
				}
				lib.Println("Proxy", client.Cipher.Alias, "started at [", client.Localaddr, "], upstream: [", client.Upstream, "]")
				logger.F(client.Start())
			}
		}
	} else {
		server := proxy.NewServer(localaddr, sc)
		lib.Println("Upstream", server.Cipher.Alias, "started at [", server.Localaddr, "]")
		if strings.HasPrefix(sc.ProxyPassAddr, "http") {
			lib.Println("Alternatively act as a reverse proxy:", sc.ProxyPassAddr)
		} else if sc.ProxyPassAddr != "" {
			lib.Println("Alternatively act as a file server:", sc.ProxyPassAddr)
		}
		logger.F(server.Start())
	}
}

func parseUpstream(cc *proxy.ClientConfig, upstream string) {
	if is := func(in string) bool { return strings.HasPrefix(upstream, in) }; is("https://") {
		cc.Connect2Auth, cc.Connect2, _, cc.Upstream = parseAuthURL(upstream)
		lib.Println("Use HTTPS proxy [", cc.Connect2, "] as the frontend, proxy auth: [", cc.Connect2Auth, "]")

		if cc.Mux > 0 {
			logger.F("Can't use an HTTPS proxy with TCP multiplexer")
		}

	} else if gfw, http, ws, cf, fwd, fwdws :=
		is("gfw://"), is("http://"), is("ws://"),
		is("cf://"), is("fwd://"), is("fwds://"); gfw || http || ws || cf || fwd || fwdws {

		cc.Connect2Auth, cc.Upstream, cc.URLHeader, cc.DummyDomain = parseAuthURL(upstream)

		switch true {
		case cf:
			lib.Println("Connect to the upstream [", cc.Upstream, "] hosted on cloudflare")
			cc.DummyDomain = cc.Upstream
		case fwdws, fwd:
			if cc.URLHeader == "" {
				cc.URLHeader = "X-Forwarded-Url"
			}
			lib.Println("Forward request to [", cc.Upstream, "], store the true URL in [",
				cc.URLHeader+": http://"+cc.DummyDomain+"/... ]")
		case cc.DummyDomain != "":
			lib.Println("Use dummy host [", cc.DummyDomain, "] to connect [", cc.Upstream, "]")
		}

		switch true {
		case fwdws, cf, ws:
			cc.Policy.Set(proxy.PolicyWebSocket)
			lib.Println("Use WebSocket protocol to transfer data")
		case fwd, http:
			cc.Policy.Set(proxy.PolicyMITM)
			lib.Println("Use MITM to intercept HTTPS (HTTP proxy mode only)")
			cc.CA = lib.TryLoadCert()
		}
	}
}

func parseAuthURL(in string) (auth string, upstream string, header string, dummy string) {
	// <scheme>://[<username>:<password>@]<host>:<port>[/[?<header>=]<dummy_host>:<dummy_port>]
	if idx := strings.Index(in, "://"); idx > -1 {
		in = in[idx+3:]
	}

	if idx := strings.Index(in, "/"); idx > -1 {
		dummy = in[idx+1:]
		in = in[:idx]
		if idx = strings.Index(dummy, "="); dummy[0] == '?' && idx > -1 {
			header = dummy[1:idx]
			dummy = dummy[idx+1:]
		}
	}

	upstream = in
	if idx := strings.Index(in, "@"); idx > -1 {
		auth = in[:idx]
		upstream = in[idx+1:]
	}

	if _, _, err := net.SplitHostPort(upstream); err != nil {
		lib.Println("Invalid upstream destination:", upstream, err)
		os.Exit(1)
	}

	return
}

func curl(client *proxy.ProxyClient, method string, url string, cookies []*http.Cookie) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		lib.Println("Can't create the request:", err)
		return
	}

	if err := lib.ParseHeadersAndPostBody(*cmdHeaders, *cmdForm, *cmdMultipart, req); err != nil {
		lib.Println("Invalid headers:", err)
		return
	}

	if len(cookies) > 0 {
		cs := make([]string, len(cookies))
		for i, cookie := range cookies {
			cs[i] = cookie.Name + "=" + cookie.Value
			lib.Println("Cookie:", cookie.String())
		}

		oc := req.Header.Get("Cookie")
		if oc != "" {
			oc += ";" + strings.Join(cs, ";")
		} else {
			oc = strings.Join(cs, ";")
		}

		req.Header.Set("Cookie", oc)
	}

	reqbuf, _ := httputil.DumpRequest(req, false)
	lib.Println(string(reqbuf))

	var totalBytes int64
	var startTime = time.Now().UnixNano()
	var r *lib.ResponseRecorder
	r = lib.NewRecorder(func(bytes int64) {
		totalBytes += bytes
		length, _ := strconv.ParseInt(r.HeaderMap.Get("Content-Length"), 10, 64)
		x := "\r* Copy body: " + lib.PrettySize(totalBytes) + " / " + lib.PrettySize(length) + " "
		if len(x) < 36 {
			x += strings.Repeat(" ", 36-len(x))
		}
		lib.PrintInErr(x)
	})

	client.ServeHTTP(r, req)
	cookies = append(cookies, lib.ParseSetCookies(r.HeaderMap)...)

	if r.HeaderMap.Get("Content-Encoding") == "gzip" {
		lib.Println("Decoding gzip content")
		r.Body, _ = gzip.NewReader(r.Body)
	}

	if r.Body == nil {
		lib.Println("Empty body")
		r.Body = &lib.NullReader{}
	}

	defer r.Body.Close()

	if r.IsRedir() {
		location := r.Header().Get("Location")
		if location == "" {
			lib.Println("Invalid redirection location")
			return
		}

		if !strings.HasPrefix(location, "http") {
			if strings.HasPrefix(location, "/") {
				u, _ := _url.Parse(url)
				location = u.Scheme + "://" + u.Host + location
			} else {
				idx := strings.LastIndex(url, "/")
				location = url[:idx+1] + location
			}
		}

		lib.Println("Redirect:", location)
		curl(client, method, location, cookies)
	} else {
		respbuf, _ := httputil.DumpResponse(r.Result(), false)
		lib.Println(string(respbuf), "\n")

		lib.IOCopy(os.Stdout, r, *cmdPrettyJSON)

		if totalBytes > 0 {
			lib.PrintInErr("\n")
		}

		lib.PrintInErr("* Completed in ",
			strconv.FormatFloat(float64(time.Now().UnixNano()-startTime)/1e9, 'f', 3, 64), "s\n")
	}
}
