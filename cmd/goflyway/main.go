package main

import (
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	_url "net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/coyove/common/config"
	"github.com/coyove/common/logg"
	"github.com/coyove/common/lru"
	"github.com/coyove/goflyway/cmd/goflyway/lib"
	"github.com/coyove/goflyway/pkg/aclrouter"
	"github.com/coyove/goflyway/proxy"
	"golang.org/x/crypto/acme/autocert"
)

var version = "__devel__"

var (
	// General flags
	cmdHelp     = flag.Bool("h", false, "Display help message")
	cmdHelp2    = flag.Bool("help", false, "Display long help message")
	cmdConfig   = flag.String("c", "", "Config file path")
	cmdLogLevel = flag.String("lv", "info", "[loglevel] Logging level: {dbg0, dbg, log, info, warn, err, off}")
	cmdAuth     = flag.String("a", "", "[auth] Proxy authentication, form: username:password (remember the colon)")
	cmdKey      = flag.String("k", "0123456789abcdef", "[password] Password, do not use the default one")
	cmdLocal    = flag.String("l", ":8100", "[listen] Listening address")
	cmdTimeout  = flag.Int64("t", 20, "[timeout] Connection timeout in seconds, 0 to disable")
	cmdSection  = flag.String("y", "", "Config section to read, empty to disable")
	cmdUnderlay = flag.String("U", "http", "[underlay] Underlay protocol: {http, kcp, https}")
	cmdGenCA    = flag.Bool("gen-ca", false, "Generate certificate (ca.pem) and private key (key.pem)")
	cmdACL      = flag.String("acl", "chinalist.txt", "[acl] Load ACL file")
	cmdACLCache = flag.Int64("acl-cache", 1024, "[aclcache] ACL cache size")

	// Server flags
	cmdThrot      = flag.Int64("throt", 0, "[throt] S. Traffic throttling in bytes")
	cmdThrotMax   = flag.Int64("throt-max", 1024*1024, "[throtmax] S. Traffic throttling token bucket max capacity")
	cmdDisableUDP = flag.Bool("disable-udp", false, "[disableudp] S. Disable UDP relay")
	cmdDisableLRP = flag.Bool("disable-localrp", false, "[disablelrp] S. Disable client localrp control request")
	cmdProxyPass  = flag.String("proxy-pass", "", "[proxypass] S. Use goflyway as a reverse HTTP proxy")
	cmdLBindWaits = flag.Int64("lbind-timeout", 5, "[lbindwaits] S. Local bind timeout in seconds")
	cmdLBindCap   = flag.Int64("lbind-cap", 100, "[lbindcap] S. Local bind requests buffer")
	cmdAutoCert   = flag.String("autocert", "www.example.com", "[autocert] S. Use autocert to get a valid certificate")

	// Client flags
	cmdGlobal     = flag.Bool("g", false, "[global] C. Global proxy")
	cmdUpstream   = flag.String("up", "", "[upstream] C. Upstream server address")
	cmdCipher     = flag.String("cipher", "full", "[cipher] C. Set the cipher {full, partial, none}")
	cmdUDPonTCP   = flag.Int64("udp-tcp", 1, "[udptcp] C. Use N TCP connections to relay UDP")
	cmdWebConPort = flag.Int64("web-port", 65536, "[webconport] C. Web console listening port, 0 to disable, 65536 to auto select")
	cmdMux        = flag.Int64("mux", 0, "[mux] C. TCP multiplexer master count, 0 to disable")
	cmdVPN        = flag.Bool("vpn", false, "C. VPN mode, used on Android only")
	cmdMITMDump   = flag.String("mitm-dump", "", "[mitmdump] C. Dump HTTPS requests to file")
	cmdBind       = flag.String("bind", "", "[bind] C. Bind to an address at server")
	cmdLBind      = flag.String("lbind", "", "[lbind] C. Bind a local address to server")
	cmdLBindConn  = flag.Int64("lbind-conns", 1, "[lbindconns] C. Local bind request connections")

	// curl flags
	cmdGet     = flag.String("get", "", "Cu. Issue a GET request")
	cmdHead    = flag.String("head", "", "Cu. Issue a HEAD request")
	cmdPost    = flag.String("post", "", "Cu. Issue a POST request")
	cmdPut     = flag.String("put", "", "Cu. Issue a PUT request")
	cmdDelete  = flag.String("delete", "", "Cu. Issue a DELETE request")
	cmdOptions = flag.String("options", "", "Cu. Issue an OPTIONS request")
	cmdTrace   = flag.String("trace", "", "Cu. Issue a TRACE request")
	cmdPatch   = flag.String("patch", "", "Cu. Issue a PATCH request")
	cmdForm    = flag.String("F", "", "Cu. Set post form of the request")
	cmdHeaders = flag.String("H", "", "Cu. Set headers of the request")
	cmdCookie  = flag.String("C", "", "Cu. set cookies of the request")

	cmdMultipart  = flag.Bool("M", false, "Cu. Set content type to multipart")
	cmdPrettyJSON = flag.Bool("pj", false, "Cu. JSON pretty output")

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
		"cipher     ", cmdCipher,
		"timeout    ", cmdTimeout,
		"mux        ", cmdMux,
		"proxypass  ", cmdProxyPass,
		"webconport ", cmdWebConPort,
		"aclcache   ", cmdACLCache,
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
		fmt.Print("Full help: \n\n\t./goflyway -help\n\n")
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

	logger = logg.NewLogger(*cmdLogLevel)
	var cipher *proxy.Cipher
	switch *cmdCipher {
	case "full", "f":
		cipher = proxy.NewCipher(*cmdKey, proxy.FullCipher)
	case "partial", "p":
		cipher = proxy.NewCipher(*cmdKey, proxy.PartialCipher)
	case "none", "disabled", "n":
		cipher = proxy.NewCipher(*cmdKey, proxy.NoneCipher)
	}
	cipher.IO.Logger = logger

	logger.Infof("goflyway %s", version)
	logger.If(*cmdSection != "").Infof("Config section: %v", *cmdSection)
	logger.If(configerr != nil).Warnf("Config reading failed: %v", configerr)
	logger.If(*cmdKey == "0123456789abcdef").Warnf("Please change the default password: -k=<NEW PASSWORD>")
	logger.If(*cmdCipher != "full").Infof("Cipher mode: %s", *cmdCipher)
	logger.If(*cmdMux > 0).Infof("TCP multiplexer: %d masters", *cmdMux)
	logger.If(*cmdUnderlay == "kcp").Infof("KCP enabled")
	logger.If(*cmdUnderlay == "https").Infof("HTTPS enabled")

	acl, err := aclrouter.LoadACL(*cmdACL)
	if err != nil {
		logger.Warnf("Failed to read ACL config: %v", err)
	} else {
		logger.Dbgf("ACL %s: %d black rules, %d white rules, %d gray rules", *cmdACL, acl.Black.Size, acl.White.Size, acl.Gray.Size)
		for _, r := range acl.OmitRules {
			logger.Infof("ACL omitted rule: %s", r)
		}
	}

	var cc *proxy.ClientConfig
	var ccchain string
	var sc *proxy.ServerConfig

	if *cmdUpstream != "" {
		cc = &proxy.ClientConfig{}
		cc.Cipher = cipher
		cc.DNSCache = lru.NewCache(*cmdACLCache)
		cc.CACache = lru.NewCache(256)
		cc.ACL = acl
		cc.UserAuth = *cmdAuth
		cc.UDPRelayCoconn = *cmdUDPonTCP
		cc.Mux = *cmdMux
		cc.Upstream = *cmdUpstream
		cc.LocalRPBind = *cmdLBind
		cc.Logger = logger
		cc.Policy.SetBool(*cmdUnderlay == "kcp", proxy.PolicyKCP)
		cc.Policy.SetBool(*cmdUnderlay == "https", proxy.PolicyHTTPS)
		cc.Policy.SetBool(*cmdGlobal, proxy.PolicyGlobal)
		cc.Policy.SetBool(*cmdVPN, proxy.PolicyVPN)

		ccchain = parseUpstream(cc, *cmdUpstream)

		logger.If(*cmdGlobal).Infof("Global proxy enabled")
		logger.If(*cmdVPN).Infof("Android shadowsocks compatible mode enabled")

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
			LBindTimeout:  *cmdLBindWaits,
			LBindCap:      *cmdLBindCap,
			Logger:        logger,
			ACL:           acl,
			ACLCache:      lru.NewCache(*cmdACLCache),
		}

		sc.Policy.SetBool(*cmdDisableUDP, proxy.PolicyDisableUDP)
		sc.Policy.SetBool(*cmdDisableLRP, proxy.PolicyDisableLRP)
		sc.Policy.SetBool(*cmdUnderlay == "kcp", proxy.PolicyKCP)

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

			sc.HTTPS = &tls.Config{GetCertificate: m.GetCertificate}
			sc.Policy.Set(proxy.PolicyHTTPS)

			logger.Infof("AutoCert host: %v, listen :80 for HTTP validation", *cmdAutoCert)
			go http.ListenAndServe(":http", m.HTTPHandler(nil))
		} else if *cmdUnderlay == "https" {
			var cl, kl int
			var ca tls.Certificate
			ca, cl, kl = lib.TryLoadCert()
			logger.If(cl == 0).Warnf("HTTPS can't find cert.pem, use the default one")
			logger.If(kl == 0).Warnf("HTTPS can't find key.pem, use the default one")
			sc.HTTPS = &tls.Config{Certificates: []tls.Certificate{ca}}
			sc.Policy.Set(proxy.PolicyHTTPS)
		}
	}

	if *cmdTimeout > 0 {
		cipher.IO.Start(int(*cmdTimeout))
	}

	var localaddr string
	if *cmdLocal2 != "" {
		// -p has higher priority than -l, for the sack of SS users
		localaddr = *cmdLocal2
	} else {
		localaddr = *cmdLocal
	}

	if *cmdUpstream != "" {
		client, err := proxy.NewClient(localaddr, cc)
		logger.If(err != nil).Fatalf("Init client failed: %v", err)

		if method != "" {
			curl(client, method, url, nil)
		} else if *cmdBind != "" {
			ln, err := net.Listen("tcp", localaddr)
			logger.If(err != nil).Fatalf("Local port forwarding failed to start: %v", err)
			logger.Infof("Local port forwarding bind at %s, forward to %s:%s", localaddr, client.Upstream, *cmdBind)
			for {
				conn, err := ln.Accept()
				if err != nil {
					logger.Errorf("Bind accept: %v", err)
					continue
				}
				logger.Infof("Bind bridge local %s", conn.LocalAddr().String())
				client.Bridge(conn, *cmdBind)
			}
		} else {

			if *cmdLBind != "" {
				logger.Infof("Remote port forwarding bind at local %s", client.ClientConfig.LocalRPBind)
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
						logger.Infof("Web console started at %s", addr).Fatal(http.ListenAndServe(addr, nil))
					}()
				}
				logger.
					Infof("Client %s started: "+ccchain, cipher.Alias, client.Localaddr).
					Fatal(client.Start())
			}
		}
	} else {
		logger.If(method != "").Fatalf("You are issuing an HTTP request without the upstream server")

		server, err := proxy.NewServer(localaddr, sc)
		logger.If(err != nil).Fatalf("Init server failed: %v", err)

		if strings.HasPrefix(sc.ProxyPassAddr, "http") {
			logger.Infof("Reverse proxy started, pass to %s", sc.ProxyPassAddr)
		} else if sc.ProxyPassAddr != "" {
			logger.Infof("File server started, root: %s", sc.ProxyPassAddr)
		}
		logger.Infof("Server %s started at %s", cipher.Alias, server.Localaddr).Fatal(server.Start())
	}
}

func parseUpstream(cc *proxy.ClientConfig, upstream string) (chain string) {
	logger.Infof("Upstream config: %s", upstream)
	chain = "you->%s->" + upstream
	is := func(in string) bool { return strings.HasPrefix(upstream, in) }

	if is("https://") {
		cc.Connect2Auth, cc.Connect2, cc.Upstream = parseAuthURL(upstream)
		logger.If(cc.Mux > 0).Fatalf("Can't use an HTTPS proxy with TCP multiplexer (TODO)")
		chain = "you->%s->" + cc.Connect2Auth + "@" + cc.Connect2 + "(proxy)->" + cc.Upstream
	} else if gfw, http, ws, cf, cfs, fwd, fwdws, agent :=
		is("gfw://"), is("http://"), is("ws://"),
		is("cf://"), is("cfs://"),
		is("fwd://"), is("fwds://"), is("agent://"); gfw || http || ws || cf || cfs || fwd || fwdws || agent {

		cc.Connect2Auth, cc.Upstream, cc.DummyDomain = parseAuthURL(upstream)
		logger.If(*cmdLBind != "" && !gfw).Fatalf("Remote port forwarding can only be used schema 'gfw://'")
		logger.If(cc.Policy.IsSet(proxy.PolicyKCP) && !gfw).Fatalf("KCP can only be used schema 'gfw://'")

		switch {
		case cf:
			cc.Policy.Set(proxy.PolicyWebSocket)
			cc.DummyDomain = cc.Upstream
			chain = "you->%s->cloudflare->" + cc.DummyDomain
		case cfs:
			cc.Policy.Set(proxy.PolicyWebSocket)
			cc.Policy.Set(proxy.PolicyHTTPS)
			cc.DummyDomain = cc.Upstream
			chain = "you->%s->wss->cloudflare->" + cc.DummyDomain
		case fwdws:
			cc.Policy.Set(proxy.PolicyWebSocket)
			cc.Policy.Set(proxy.PolicyForward)
			chain = "you->%s->" + cc.Upstream + "(relay)->ws->" + cc.DummyDomain
		case fwd:
			cc.Policy.Set(proxy.PolicyMITM)
			cc.Policy.Set(proxy.PolicyForward)
			chain = "you->mitm->%s->" + cc.Upstream + "(relay)->" + cc.DummyDomain
		case agent:
			cc.Policy.Set(proxy.PolicyMITM)
			cc.Policy.Set(proxy.PolicyAgent)
			chain = "you->mitm->%s->" + cc.Upstream + "(agent)"
			logger.Warnf("Agent is not safe, don't use it to access your important data")
			if strings.HasSuffix(cc.Upstream, ":80") {
				logger.Warnf("Please use an HTTPS agent")
			}
		case ws:
			cc.Policy.Set(proxy.PolicyWebSocket)
			if cc.DummyDomain == "" {
				chain = "you->%s->ws->" + cc.Upstream
			} else {
				chain = "you->%s->" + cc.DummyDomain + "(fake)->ws->" + cc.Upstream
			}
		case http:
			cc.Policy.Set(proxy.PolicyMITM)
			if cc.DummyDomain == "" {
				chain = "you->mitm->%s->" + cc.Upstream
			} else {
				chain = "you->mitm->%s->" + cc.DummyDomain + "(fake)->" + cc.Upstream
			}
		case gfw:
			if cc.DummyDomain == "" {
				chain = "you->%s->" + cc.Upstream
			} else {
				chain = "you->%s->" + cc.DummyDomain + "(fake)->" + cc.Upstream
			}
		}

		if cc.Policy.IsSet(proxy.PolicyMITM) {
			var cl, kl int
			cc.CA, cl, kl = lib.TryLoadCert()
			logger.If(cl == 0).Warnf("MITM can't find cert.pem, use the default one")
			logger.If(kl == 0).Warnf("MITM can't find key.pem, use the default one")
		}
	}
	return
}

func parseAuthURL(in string) (auth string, upstream string, dummy string) {
	// <scheme>://[<username>:<password>@]<host>:<port>[/<dummy_host>:<dummy_port>]
	if idx := strings.Index(in, "://"); idx > -1 {
		in = in[idx+3:]
	}

	if idx := strings.Index(in, "/"); idx > -1 {
		dummy = in[idx+1:]
		in = in[:idx]
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

		logger.Fatalf("Invalid server destination: %s, %v", upstream, err)
	}

	return
}

func curl(client *proxy.ProxyClient, method string, url string, cookies []*http.Cookie) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		logger.Errorf("[curl] Can't create the request: %v", err)
		return
	}

	if err := lib.ParseHeadersAndPostBody(*cmdHeaders, *cmdForm, *cmdMultipart, req); err != nil {
		logger.Errorf("[curl] Invalid headers: %v", err)
		return
	}

	if len(cookies) > 0 {
		cs := make([]string, len(cookies))
		for i, cookie := range cookies {
			cs[i] = cookie.Name + "=" + cookie.Value
			logger.Dbgf("[curl] Cookie: %s", cookie.String())
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
	logger.Dbgf("[curl] Request: %s", string(reqbuf))

	var totalBytes, counter int64
	var startTime = time.Now().UnixNano()
	var r *lib.ResponseRecorder
	r = lib.NewRecorder(func(bytes int64) {
		totalBytes += bytes
		length, _ := strconv.ParseInt(r.HeaderMap.Get("Content-Length"), 10, 64)
		if counter++; counter%10 == 0 || totalBytes == length {
			logger.Dbgf("[curl] Downloading %s / %s", lib.PrettySize(totalBytes), lib.PrettySize(length))
		}
	})

	logger.Logf("[curl] Dial upstream: %s", client.Upstream)
	client.ServeHTTP(r, req)
	cookies = append(cookies, lib.ParseSetCookies(r.HeaderMap)...)

	if r.HeaderMap.Get("Content-Encoding") == "gzip" {
		logger.Dbgf("[curl] Decoding gzip content")
		r.Body, _ = gzip.NewReader(r.Body)
	}

	if r.Body == nil {
		logger.Dbgf("[curl] Empty body")
		r.Body = &lib.NullReader{}
	}

	defer r.Body.Close()

	if r.IsRedir() {
		location := r.Header().Get("Location")
		if location == "" {
			logger.Errorf("[curl] Invalid redirection")
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

		logger.Infof("[curl] Redirect: %s", location)
		curl(client, method, location, cookies)
	} else {
		respbuf, _ := httputil.DumpResponse(r.Result(), false)
		logger.Dbgf("[curl] Response: %s", string(respbuf))

		lib.IOCopy(os.Stdout, r, *cmdPrettyJSON)

		logger.Infof("[curl] Elapsed time: %d ms", (time.Now().UnixNano()-startTime)/1e6)
	}
}
