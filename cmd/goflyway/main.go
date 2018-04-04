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

	"github.com/coyove/goflyway/cmd/goflyway/lib"
	"github.com/coyove/goflyway/pkg/aclrouter"
	"github.com/coyove/goflyway/pkg/config"
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lru"
	"github.com/coyove/goflyway/proxy"

	"flag"
	"fmt"
	"io/ioutil"
	"strings"
)

var version = "__devel__"

var (
	cmdGenCA = flag.Bool("gen-ca", false, "generate certificate (ca.pem) and private key (key.pem)")
	cmdDebug = flag.Bool("debug", false, "turn on debug mode")

	// General flags
	cmdConfig   = flag.String("c", "", "[SC] config file path")
	cmdLogLevel = flag.String("lv", "log", "[SC] logging level: {dbg, log, warn, err, off}")
	cmdLogFile  = flag.String("lf", "", "[SC] log to file")
	cmdAuth     = flag.String("a", "", "[SC] proxy authentication, form: username:password (remember the colon)")
	cmdKey      = flag.String("k", "0123456789abcdef", "[SC] password, do not use the default one")
	cmdLocal    = flag.String("l", ":8100", "[SC] local listening address")
	cmdTimeout  = flag.Int64("t", 20, "[SC] close connections when they go idle for at least N sec")
	cmdSection  = flag.String("y", "default", "[SC] section to read in the config")

	// Server flags
	cmdThrot     = flag.Int64("throt", 0, "[S] traffic throttling in bytes")
	cmdThrotMax  = flag.Int64("throt-max", 1024*1024, "[S] traffic throttling token bucket max capacity")
	cmdDiableUDP = flag.Bool("disable-udp", false, "[S] disable UDP relay")
	cmdProxyPass = flag.String("proxy-pass", "", "[S] use goflyway as a reverse HTTP proxy")
	cmdWSCBClose = flag.Int64("wscb-timeout", 200, "[S] timeout for WebSocket callback")
	cmdAnswer    = flag.String("answer", "", "[S] answer client config setup")

	// Client flags
	cmdGlobal     = flag.Bool("g", false, "[C] global proxy")
	cmdUpstream   = flag.String("up", "", "[C] upstream server address")
	cmdPartial    = flag.Bool("partial", false, "[C] partially encrypt the tunnel traffic")
	cmdUDPonTCP   = flag.Int64("udp-tcp", 1, "[C] use N TCP connections to relay UDP")
	cmdWebConPort = flag.Int64("web-port", 65536, "[C] web console listening port, 0 to disable, 65536 to auto select")
	cmdDNSCache   = flag.Int64("dns-cache", 1024, "[C] DNS cache size")
	cmdMux        = flag.Int64("mux", 0, "[C] limit the total number of TCP connections, 0 means no limit")
	cmdVPN        = flag.Bool("vpn", false, "[C] vpn mode, used on Android only")
	cmdACL        = flag.String("acl", "chinalist.txt", "[C] load ACL file")
	cmdMITMDump   = flag.String("mitm-dump", "", "[C] dump HTTPS requests to file")
	cmdWSCB       = flag.Bool("wscb", false, "[C] enable WebSocket callback in MITM")
	cmdRemote     = flag.Bool("remote", false, "[C] get config setup from the upstream")

	// curl flags
	cmdVerbose    = flag.Bool("v", false, "[Cu] verbose output")
	cmdForm       = flag.String("F", "", "[Cu] post form")
	cmdHeaders    = flag.String("H", "", "[Cu] headers")
	cmdCookie     = flag.String("C", "", "[Cu] cookies")
	cmdMultipart  = flag.Bool("M", false, "[Cu] multipart")
	cmdPrettyJSON = flag.Bool("pj", false, "[Cu] JSON pretty output")

	// Shadowsocks compatible flags
	cmdLocal2 = flag.String("p", "", "server listening address")

	_ = flag.Bool("u", true, "placeholder")
	_ = flag.String("m", "", "placeholder")
	_ = flag.String("b", "", "placeholder")
	_ = flag.Bool("V", true, "placeholder")
	_ = flag.Bool("fast-open", true, "placeholder")
)

func loadConfig() {
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
		lib.Println("can't load config file:", err)
		return
	}

	if strings.Contains(path, "shadowsocks.conf") {
		cmds := make(map[string]interface{})
		if err := json.Unmarshal(buf, &cmds); err != nil {
			lib.Println("can't parse config file:", err)
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
		lib.Println("can't parse config file:", err)
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
		"wscb       ", cmdWSCB,
		"timeout    ", cmdTimeout,
		"mux        ", cmdMux,
		"proxypass  ", cmdProxyPass,
		"webconport ", cmdWebConPort,
		"dnscache   ", cmdDNSCache,
		"wscbtimeout", cmdWSCBClose,
		"loglevel   ", cmdLogLevel,
		"logfile    ", cmdLogFile,
		"throt      ", cmdThrot,
		"throtmax   ", cmdThrotMax,
	)
}

func main() {
	method, url := lib.ParseExtendedOSArgs()
	flag.Parse()
	lib.Slient = (method != "" && !*cmdVerbose)
	lib.Println("goflyway (build " + version + ")")
	loadConfig()

	if *cmdGenCA {
		lib.Println("generating CA...")

		cert, key, err := lib.GenCA("goflyway")
		if err != nil {
			lib.Println(err)
			return
		}

		err1, err2 := ioutil.WriteFile("ca.pem", cert, 0755), ioutil.WriteFile("key.pem", key, 0755)
		if err1 != nil || err2 != nil {
			lib.Println("error ca.pem:", err1)
			lib.Println("error key.pem:", err2)
			return
		}

		lib.Println("successfully generated ca.pem/key.pem, please leave them in the same directory with goflyway")
		lib.Println("goflyway will automatically read them when launched")
		return
	}

	if *cmdUpstream != "" {
		lib.Println("launched as client")
	} else {
		lib.Println("launched as server (aka upstream)")
	}

	if *cmdKey == "0123456789abcdef" {
		lib.Println("you are using the default password, it is recommended to change it: -k=<NEW PASSWORD>")
	}

	cipher := &proxy.Cipher{Partial: *cmdPartial}
	cipher.Init(*cmdKey)

	var cc *proxy.ClientConfig
	var sc *proxy.ServerConfig

	if *cmdMux > 0 {
		lib.Println("TCP multiplexer enabled, limit:", *cmdMux)
	}

	if *cmdUpstream != "" || *cmdDebug {
		acl, err := aclrouter.LoadACL(*cmdACL)
		if err != nil {
			lib.Println("failed to read ACL config (but it's fine, you can ignore this message)")
			lib.Println("  err:", err)
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
		parseUpstream(cc, *cmdUpstream)

		if *cmdGlobal {
			lib.Println("global proxy: goflyway will proxy everything except private IPs")
			cc.Policy.Set(proxy.PolicyGlobal)
		}

		if *cmdWSCB {
			cc.Policy.Set(proxy.PolicyWSCB)
		}

		if *cmdVPN {
			cc.Policy.Set(proxy.PolicyVPN)
		}

		if *cmdMITMDump != "" {
			cc.MITMDump, _ = os.Create(*cmdMITMDump)
		}
	}

	if *cmdUpstream == "" || *cmdDebug {
		sc = &proxy.ServerConfig{
			Cipher:        cipher,
			Throttling:    *cmdThrot,
			ThrottlingMax: *cmdThrotMax,
			ProxyPassAddr: *cmdProxyPass,
			DisableUDP:    *cmdDiableUDP,
			WSCBTimeout:   *cmdWSCBClose,
			ClientAnswer:  *cmdAnswer,
		}

		if *cmdAuth != "" {
			sc.Users = map[string]proxy.UserConfig{
				*cmdAuth: {},
			}
		}
	}

	if *cmdLogFile != "" {
		logg.Redirect(*cmdLogFile)
		lib.Println("redirect log to", *cmdLogFile)
	}

	logg.SetLevel(*cmdLogLevel)
	logg.Start()

	if *cmdDebug {
		lib.Println("debug mode on")

		cc.Upstream = "127.0.0.1:8101"
		client := proxy.NewClient(":8100", cc)
		go func() {
			logg.F(client.Start())
		}()

		server := proxy.NewServer(":8101", sc)
		logg.F(server.Start())
		return
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
			lib.Println("get config from the upstream")
			cm := client.GetRemoteConfig()
			if cm == "" {
				logg.F("can't get remote config")
			}

			parseUpstream(cc, cm)
			client = proxy.NewClient(localaddr, cc)
		}

		if method != "" {
			curl(client, method, url, nil)
		} else {
			if *cmdWebConPort != 0 {
				go func() {
					addr := fmt.Sprintf("127.0.0.1:%d", *cmdWebConPort)
					if *cmdWebConPort == 65536 {
						addr_, _ := net.ResolveTCPAddr("tcp", client.Localaddr)
						addr = fmt.Sprintf("127.0.0.1:%d", addr_.Port+10)
					}

					http.HandleFunc("/", lib.WebConsoleHTTPHandler(client))
					lib.Println("access client web console at [", addr, "]")
					logg.F(http.ListenAndServe(addr, nil))
				}()
			}

			lib.Println("proxy", client.Cipher.Alias, "started at [", client.Localaddr, "], upstream: [", client.Upstream, "]")
			logg.F(client.Start())
		}
	} else {
		server := proxy.NewServer(localaddr, sc)
		lib.Println("upstream", server.Cipher.Alias, "started at [", server.Localaddr, "]")
		if strings.HasPrefix(sc.ProxyPassAddr, "http") {
			lib.Println("alternatively act as a reverse proxy:", sc.ProxyPassAddr)
		} else if sc.ProxyPassAddr != "" {
			lib.Println("alternatively act as a file server:", sc.ProxyPassAddr)
		}
		logg.F(server.Start())
	}
}

func parseUpstream(cc *proxy.ClientConfig, upstream string) {
	if is := func(in string) bool { return strings.HasPrefix(upstream, in) }; is("https://") {
		cc.Connect2Auth, cc.Connect2, _, cc.Upstream = parseAuthURL(upstream)
		lib.Println("use HTTPS proxy [", cc.Connect2, "] as the frontend, proxy auth: [", cc.Connect2Auth, "]")

		if cc.Mux > 0 {
			logg.F("can't use an HTTPS proxy with TCP multiplexer")
		}

	} else if gfw, http, ws, cf, fwd, fwdws :=
		is("gfw://"), is("http://"), is("ws://"),
		is("cf://"), is("fwd://"), is("fwds://"); gfw || http || ws || cf || fwd || fwdws {

		cc.Connect2Auth, cc.Upstream, cc.URLHeader, cc.DummyDomain = parseAuthURL(upstream)

		switch true {
		case cf:
			lib.Println("connect to the upstream [", cc.Upstream, "] hosted on cloudflare")
			cc.DummyDomain = cc.Upstream
		case fwdws, fwd:
			if cc.URLHeader == "" {
				cc.URLHeader = "X-Forwarded-Url"
			}
			lib.Println("forward request to [", cc.Upstream, "], store the true URL in [",
				cc.URLHeader+": http://"+cc.DummyDomain+"/... ]")
		case cc.DummyDomain != "":
			lib.Println("use dummy host [", cc.DummyDomain, "] to connect [", cc.Upstream, "]")
		}

		switch true {
		case fwdws, cf, ws:
			cc.Policy.Set(proxy.PolicyWebSocket)
			lib.Println("use WebSocket protocol to transfer data")
		case fwd, http:
			cc.Policy.Set(proxy.PolicyManInTheMiddle)
			lib.Println("use MITM to intercept HTTPS (HTTP proxy mode only)")
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
		lib.Println("invalid upstream destination:", upstream, err)
		os.Exit(1)
	}

	return
}

func curl(client *proxy.ProxyClient, method string, url string, cookies []*http.Cookie) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		lib.Println("can't create the request:", err)
		return
	}

	if err := lib.ParseHeadersAndPostBody(*cmdHeaders, *cmdForm, *cmdMultipart, req); err != nil {
		lib.Println("invalid headers:", err)
		return
	}

	if len(cookies) > 0 {
		cs := make([]string, len(cookies))
		for i, cookie := range cookies {
			cs[i] = cookie.Name + "=" + cookie.Value
			lib.Println("cookie:", cookie.String())
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
		x := "\r* copy body: " + lib.PrettySize(totalBytes) + " / " + lib.PrettySize(length) + " "
		if len(x) < 36 {
			x += strings.Repeat(" ", 36-len(x))
		}
		lib.PrintInErr(x)
	})

	client.ServeHTTP(r, req)
	cookies = append(cookies, lib.ParseSetCookies(r.HeaderMap)...)

	if r.HeaderMap.Get("Content-Encoding") == "gzip" {
		lib.Println("decoding gzip content")
		r.Body, _ = gzip.NewReader(r.Body)
	}

	if r.Body == nil {
		lib.Println("empty body")
		r.Body = &lib.NullReader{}
	}

	defer r.Body.Close()

	if r.IsRedir() {
		location := r.Header().Get("Location")
		if location == "" {
			lib.Println("invalid redirection location")
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

		lib.Println("redirect:", location)
		curl(client, method, location, cookies)
	} else {
		respbuf, _ := httputil.DumpResponse(r.Result(), false)
		lib.Println(string(respbuf), "\n")

		lib.IOCopy(os.Stdout, r, *cmdPrettyJSON)

		if totalBytes > 0 {
			lib.PrintInErr("\n")
		}

		lib.PrintInErr("* completed in ",
			strconv.FormatFloat(float64(time.Now().UnixNano()-startTime)/1e9, 'f', 3, 64), "s\n")
	}
}
