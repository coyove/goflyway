package main

import (
	"compress/gzip"
	"crypto/tls"
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
	"golang.org/x/crypto/acme/autocert"

	"flag"
	"fmt"
	"io/ioutil"
	"strings"
)

var version = "__devel__"

var (
	// General flags
	cmdHelp     = flag.Bool("h", false, "Display help message")
	cmdHelp2    = flag.Bool("help", false, "Display long help message")
	cmdConfig   = flag.String("c", "", "Config file path")
	cmdLogLevel = flag.String("lv", "log", "Logging level: {dbg, log, warn, err, off}")
	cmdAuth     = flag.String("a", "", "Proxy authentication, form: username:password (remember the colon)")
	cmdKey      = flag.String("k", "0123456789abcdef", "Password, do not use the default one")
	cmdLocal    = flag.String("l", ":8100", "Listening address")
	cmdTimeout  = flag.Int64("t", 20, "Connection timeout in seconds, 0 to disable")
	cmdSection  = flag.String("y", "", "Config section to read, empty to disable")
	cmdUnderlay = flag.String("U", "http", "Underlay protocol: {http, kcp, https}")
	cmdGenCA    = flag.Bool("gen-ca", false, "Generate certificate (ca.pem) and private key (key.pem)")

	// Server flags
	cmdThrot      = flag.Int64("throt", 0, "[S] Traffic throttling in bytes")
	cmdThrotMax   = flag.Int64("throt-max", 1024*1024, "[S] Traffic throttling token bucket max capacity")
	cmdDisableUDP = flag.Bool("disable-udp", false, "[S] Disable UDP relay")
	cmdDisableLRP = flag.Bool("disable-localrp", false, "[S] Disable client localrp control request")
	cmdProxyPass  = flag.String("proxy-pass", "", "[S] Use goflyway as a reverse HTTP proxy")
	cmdLBindWaits = flag.Int64("lbind-timeout", 5, "[S] Local bind timeout in seconds")
	cmdLBindCap   = flag.Int64("lbind-cap", 100, "[S] Local bind requests buffer")
	cmdAutoCert   = flag.String("autocert", "www.example.com", "[S] Use autocert to get a valid certificate")

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
	cmdBind       = flag.String("bind", "", "[C] Bind to an address at server")
	cmdLBind      = flag.String("lbind", "", "[C] Bind a local address to server")
	cmdLBindConn  = flag.Int64("lbind-conns", 1, "[C] Local bind request connections")

	// curl flags
	cmdGet        = flag.String("get", "", "[Cu] Issue a GET request")
	cmdHead       = flag.String("head", "", "[Cu] Issue an HEAD request")
	cmdPost       = flag.String("post", "", "[Cu] Issue a POST request")
	cmdPut        = flag.String("put", "", "[Cu] Issue a PUT request")
	cmdDelete     = flag.String("delete", "", "[Cu] Issue a DELETE request")
	cmdOptions    = flag.String("options", "", "[Cu] Issue an OPTIONS request")
	cmdTrace      = flag.String("trace", "", "[Cu] Issue a TRACE request")
	cmdPatch      = flag.String("patch", "", "[Cu] Issue a PATCH request")
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

func loadConfig() error {
	path := *cmdConfig
	if path == "" {
		if runtime.GOOS == "windows" {
			path = os.Getenv("USERPROFILE") + "/gfw.conf"
		} else {
			path = os.Getenv("HOME") + "/gfw.conf"
		}
	}

	if _, err := os.Stat(path); err != nil {
		return nil
	}

	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	if strings.Contains(path, "shadowsocks.conf") {
		cmds := make(map[string]interface{})
		if err := json.Unmarshal(buf, &cmds); err != nil {
			return err
		}

		*cmdKey = cmds["password"].(string)
		*cmdUpstream = fmt.Sprintf("%v:%v", cmds["server"], cmds["server_port"])
		if strings.HasPrefix(*cmdKey, "?") {
			switch (*cmdKey)[1] {
			case 'w':
				*cmdUpstream = "ws://" + *cmdUpstream
			case 'c':
				*cmdUpstream = "ws://" + *cmdUpstream + "/" + (*cmdKey)[2:]
			}
		}
		*cmdMux = 10
		*cmdLogLevel = "dbg"
		*cmdVPN = true
		*cmdGlobal = true
		return nil
	}

	if *cmdSection == "" {
		return nil
	}

	cf, err := config.ParseConf(string(buf))
	if err != nil {
		return err
	}

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
		"disableudp ", cmdDisableUDP,
		"disablelrp ", cmdDisableLRP,
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
		"throt      ", cmdThrot,
		"throtmax   ", cmdThrotMax,
		"bind       ", cmdBind,
		"lbind      ", cmdLBind,
		"lbindwaits ", cmdLBindWaits,
		"lbindcap   ", cmdLBindCap,
		"lbindconns ", cmdLBindConn,
		"mitmdump   ", cmdMITMDump,
		"underlay   ", cmdUnderlay,
		"autocert   ", cmdAutoCert,
	)

	return nil
}

var logger *logg.Logger

func main() {
	method, url := "", ""
	flag.Parse()

	if *cmdHelp2 {
		flag.Usage()
		return
	}

	if *cmdHelp {
		fmt.Print("Launch as client: \n\n\t./goflyway -up SERVER_IP:SERVER_PORT -k PASSWORD\n\n")
		fmt.Print("Launch as server: \n\n\t./goflyway -l :SERVER_PORT -k PASSWORD\n\n")
		fmt.Print("Generate ca.pem and key.pem: \n\n\t./goflyway -gen-ca\n\n")
		fmt.Print("POST request: \n\n\t./goflyway -post URL -up ... -H \"h1: v1 \\r\\n h2: v2\" -F \"k1=v1&k2=v2\"\n\n")
		return
	}

	if *cmdGenCA {
		fmt.Println("Generating CA...")

		cert, key, err := lib.GenCA("goflyway")
		if err != nil {
			fmt.Println(err)
			return
		}

		err1, err2 := ioutil.WriteFile("ca.pem", cert, 0755), ioutil.WriteFile("key.pem", key, 0755)
		if err1 != nil || err2 != nil {
			fmt.Println("Error ca.pem:", err1)
			fmt.Println("Error key.pem:", err2)
			return
		}

		fmt.Println("Successfully generated ca.pem/key.pem, please leave them in the same directory with goflyway")
		fmt.Println("They will be automatically read when goflyway launched")
		return
	}

	switch {
	case *cmdGet != "":
		method, url = "GET", *cmdGet
	case *cmdPost != "":
		method, url = "POST", *cmdPost
	case *cmdPut != "":
		method, url = "PUT", *cmdPut
	case *cmdDelete != "":
		method, url = "DELETE", *cmdDelete
	case *cmdHead != "":
		method, url = "HEAD", *cmdHead
	case *cmdOptions != "":
		method, url = "OPTIONS", *cmdOptions
	case *cmdTrace != "":
		method, url = "TRACE", *cmdTrace
	case *cmdPatch != "":
		method, url = "PATCH", *cmdPatch
	}

	runtime.GOMAXPROCS(runtime.NumCPU() * 4)
	configerr := loadConfig()

	logger = &logg.Logger{}
	logger.SetFormats(logg.FmtLongTime, logg.FmtShortFile, logg.FmtLevel)
	logger.Parse(*cmdLogLevel)

	if *cmdSection != "" {
		logger.L("Config section: %v", *cmdSection)
	}

	if configerr != nil {
		logger.L("Config parse error: %v", configerr)
	}

	if *cmdUpstream != "" {
		logger.L("Client role (goflyway %s)", version)
	} else {
		logger.L("Server role (goflyway %s)", version)
	}

	if *cmdKey == "0123456789abcdef" {
		logger.W("Cipher vulnerability: please change the default password: -k=<NEW PASSWORD>")
	}

	cipher := &proxy.Cipher{Partial: *cmdPartial}
	cipher.Init(*cmdKey)
	cipher.IO.Logger = logger

	var cc *proxy.ClientConfig
	var sc *proxy.ServerConfig

	if *cmdMux > 0 {
		logger.L("TCP multiplexer: %d masters", *cmdMux)
	}

	if *cmdUnderlay == "kcp" {
		logger.L("KCP enabled")
	}

	if *cmdUnderlay == "https" {
		logger.L("HTTPS enabled")
	}

	if *cmdUpstream != "" {
		acl, err := aclrouter.LoadACL(*cmdACL)
		if err != nil {
			logger.W("Failed to read ACL config: %v", err)
		} else {
			logger.D("ACL %s: %d black rules, %d white rules, %d gray rules", *cmdACL, acl.Black.Size, acl.White.Size, acl.Gray.Size)
			for _, r := range acl.OmitRules {
				logger.L("ACL omitted rule: %s", r)
			}
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
		cc.KCP.Enable = *cmdUnderlay == "kcp"
		cc.HTTPS = *cmdUnderlay == "https"
		parseUpstream(cc, *cmdUpstream)

		if *cmdGlobal {
			logger.L("Global proxy enabled")
			cc.Policy.Set(proxy.PolicyGlobal)
		}

		if *cmdVPN {
			logger.L("Android shadowsocks compatible mode enabled")
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
			DisableUDP:    *cmdDisableUDP,
			DisableLRP:    *cmdDisableLRP,
			LBindTimeout:  *cmdLBindWaits,
			LBindCap:      *cmdLBindCap,
			Logger:        logger,
			KCP: proxy.KCPConfig{
				Enable: *cmdUnderlay == "kcp",
			},
		}

		if *cmdAuth != "" {
			sc.Users = map[string]proxy.UserConfig{
				*cmdAuth: {},
			}
		}

		if *cmdAutoCert != "www.example.com" {
			*cmdLocal = ":443"
			*cmdLocal2 = ":443"

			m := &autocert.Manager{
				Cache:      autocert.DirCache("cert"),
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(*cmdAutoCert),
			}

			logger.L("AutoCert host: %v", *cmdAutoCert)
			sc.HTTPS = &tls.Config{GetCertificate: m.GetCertificate}

			logger.L("AutoCert listen :80 for HTTP validation")
			go http.ListenAndServe(":http", m.HTTPHandler(nil))
		} else if *cmdUnderlay == "https" {
			var cl, kl int
			var ca tls.Certificate
			ca, cl, kl = lib.TryLoadCert()
			if cl == 0 {
				logger.L("HTTPS can't find cert.pem, use the default one")
			}
			if kl == 0 {
				logger.L("HTTPS can't find key.pem, use the default one")
			}
			sc.HTTPS = &tls.Config{Certificates: []tls.Certificate{ca}}
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

	logger.L("Alias code: %s", cipher.Alias)
	if *cmdUpstream != "" {
		client, err := proxy.NewClient(localaddr, cc)
		if err != nil {
			logger.F("Init failed: %v", err)
		}
		logger.L("Dial upstream: %s", client.Upstream)

		if method != "" {
			curl(client, method, url, nil)
		} else if *cmdBind != "" {
			ln, err := net.Listen("tcp", localaddr)
			if err != nil {
				logger.F("Local port forwarding failed to start: %v", err)
			}
			logger.L("Local port forwarding bind at %s", localaddr)
			for {
				conn, err := ln.Accept()
				if err != nil {
					logger.E("Bind accept: %v", err)
					continue
				}
				logger.L("Bind bridge local:%s->remote:%s", conn.LocalAddr().String(), *cmdBind)
				client.Bridge(conn, *cmdBind)
			}
		} else {

			if *cmdLBind != "" {
				logger.L("Remote port forwarding bind at %s", client.ClientConfig.LocalRPBind)
				client.StartLocalRP(int(*cmdLBindConn))
			} else {
				if *cmdWebConPort != 0 {
					go func() {
						addr := fmt.Sprintf("127.0.0.1:%d", *cmdWebConPort)
						if *cmdWebConPort == 65536 {
							_addr, _ := net.ResolveTCPAddr("tcp", client.Localaddr)
							addr = fmt.Sprintf("127.0.0.1:%d", _addr.Port+10)
						}

						http.HandleFunc("/", lib.WebConsoleHTTPHandler(client))
						logger.L("Web console started at %s", addr)
						logger.F("Web console exited: %v", http.ListenAndServe(addr, nil))
					}()
				}
				logger.L("Proxy started at %s", client.Localaddr)
				logger.F("Client exited: %v", client.Start())
			}
		}
	} else {
		if method != "" {
			logger.F("You are issuing an HTTP request without the upstream server")
		}
		server, err := proxy.NewServer(localaddr, sc)
		if err != nil {
			logger.F("Init failed: %v", err)
		}
		logger.L("Proxy started at %s", server.Localaddr)

		if strings.HasPrefix(sc.ProxyPassAddr, "http") {
			logger.L("Reverse proxy started, pass to %s", sc.ProxyPassAddr)
		} else if sc.ProxyPassAddr != "" {
			logger.L("File server started, root: %s", sc.ProxyPassAddr)
		}
		logger.F("Server exited: %v", server.Start())
	}
}

func parseUpstream(cc *proxy.ClientConfig, upstream string) {
	logger.L("Upstream config: %s", upstream)
	if is := func(in string) bool { return strings.HasPrefix(upstream, in) }; is("https://") {
		cc.Connect2Auth, cc.Connect2, _, cc.Upstream = parseAuthURL(upstream)
		logger.L("HTTPS proxy auth: %s@%s", cc.Connect2, cc.Connect2Auth)

		if cc.Mux > 0 {
			logger.L("Can't use an HTTPS proxy with TCP multiplexer")
		}

	} else if gfw, http, ws, cf, fwd, fwdws :=
		is("gfw://"), is("http://"), is("ws://"),
		is("cf://"), is("fwd://"), is("fwds://"); gfw || http || ws || cf || fwd || fwdws {

		cc.Connect2Auth, cc.Upstream, cc.URLHeader, cc.DummyDomain = parseAuthURL(upstream)

		switch true {
		case cf:
			logger.L("Cloudflare upstream: %s", cc.Upstream)
			cc.DummyDomain = cc.Upstream
		case fwdws, fwd:
			if cc.URLHeader == "" {
				cc.URLHeader = "X-Forwarded-Url"
			}
			logger.L("Forward using HTTP header '%s: http://%s/...'", cc.URLHeader, cc.DummyDomain)
		case cc.DummyDomain != "":
			logger.L("Use fake HTTP header 'Host: %s'", cc.DummyDomain)
		}

		switch true {
		case fwdws, cf, ws:
			cc.Policy.Set(proxy.PolicyWebSocket)
			if *cmdLBind != "" {
				logger.F("Remote port forwarding can't be used with Websocket")
			}
			logger.L("Websocket enabled")
		case fwd, http:
			cc.Policy.Set(proxy.PolicyMITM)
			logger.L("MITM enabled")

			var cl, kl int
			cc.CA, cl, kl = lib.TryLoadCert()
			if cl == 0 {
				logger.L("MITM can't find cert.pem, use the default one")
			}
			if kl == 0 {
				logger.L("MITM can't find key.pem, use the default one")
			}
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
		if strings.Count(upstream, ":") > 1 {
			lc := strings.LastIndex(upstream, ":")
			port := upstream[lc+1:]
			upstream = upstream[:lc]
			upip := net.ParseIP(upstream)
			if bs := []byte(upip); len(bs) == net.IPv6len {
				upstream = "["
				for i := 0; i < 16; i += 2 {
					upstream += strconv.FormatInt(int64(bs[i])*256+int64(bs[i+1]), 16) + ":"
				}
				upstream = upstream[:len(upstream)-1] + "]:" + port
				return
			}
		}

		logger.F("Invalid server destination: %s, %v", upstream, err)
	}

	return
}

func curl(client *proxy.ProxyClient, method string, url string, cookies []*http.Cookie) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		logger.E("[curl] Can't create the request: %v", err)
		return
	}

	if err := lib.ParseHeadersAndPostBody(*cmdHeaders, *cmdForm, *cmdMultipart, req); err != nil {
		logger.E("[curl] Invalid headers: %v", err)
		return
	}

	if len(cookies) > 0 {
		cs := make([]string, len(cookies))
		for i, cookie := range cookies {
			cs[i] = cookie.Name + "=" + cookie.Value
			logger.D("[curl] Cookie: %s", cookie.String())
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
	logger.D("[curl] Request: %s", string(reqbuf))

	var totalBytes, counter int64
	var startTime = time.Now().UnixNano()
	var r *lib.ResponseRecorder
	r = lib.NewRecorder(func(bytes int64) {
		totalBytes += bytes
		length, _ := strconv.ParseInt(r.HeaderMap.Get("Content-Length"), 10, 64)
		if counter++; counter%10 == 0 || totalBytes == length {
			logger.D("[curl] Downloading %d bytes / %d bytes", lib.PrettySize(totalBytes), lib.PrettySize(length))
		}
	})

	client.ServeHTTP(r, req)
	cookies = append(cookies, lib.ParseSetCookies(r.HeaderMap)...)

	if r.HeaderMap.Get("Content-Encoding") == "gzip" {
		logger.D("[curl] Decoding gzip content")
		r.Body, _ = gzip.NewReader(r.Body)
	}

	if r.Body == nil {
		logger.D("[curl] Empty body")
		r.Body = &lib.NullReader{}
	}

	defer r.Body.Close()

	if r.IsRedir() {
		location := r.Header().Get("Location")
		if location == "" {
			logger.E("[curl] Invalid redirection")
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

		logger.L("[curl] Redirect: %s", location)
		curl(client, method, location, cookies)
	} else {
		respbuf, _ := httputil.DumpResponse(r.Result(), false)
		logger.D("[curl] Response: %s", string(respbuf))

		lib.IOCopy(os.Stdout, r, *cmdPrettyJSON)

		logger.L("[curl] Elapsed time: %d ms", (time.Now().UnixNano()-startTime)/1e6)
	}
}
