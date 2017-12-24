package main

import (
	"net"
	"net/http"
	"os"

	"github.com/coyove/goflyway/cmd/goflyway/lib"
	"github.com/coyove/goflyway/pkg/config"
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/pkg/lru"
	"github.com/coyove/goflyway/proxy"

	"flag"
	"fmt"
	"io/ioutil"
	"runtime"
	"strings"
)

var version = "__devel__"

var (
	cmdConfig     = flag.String("c", "", "[SC] config file path")
	cmdLogLevel   = flag.String("lv", "log", "[SC] logging level: {dbg, log, warn, err, off}")
	cmdLogFile    = flag.String("lf", "", "[SC] log to file")
	cmdGenCA      = flag.Bool("gen-ca", false, "[C] generate certificate (ca.pem) and private key (key.pem)")
	cmdKey        = flag.String("k", "0123456789abcdef", "[SC] password, do not use the default one")
	cmdAuth       = flag.String("a", "", "[SC] proxy authentication, form: username:password (remember the colon)")
	cmdBasic      = flag.String("b", "iplist", "[C] proxy type: {none, iplist, iplist_l, global}")
	cmdUpstream   = flag.String("up", "", "[C] upstream server address")
	cmdLocal      = flag.String("l", ":8100", "[SC] local listening address")
	cmdLocal2     = flag.String("p", "", "[SC] local listening address, alias of -l")
	cmdUDPPort    = flag.Int64("udp", 0, "[SC] server UDP relay listening port, 0 to disable")
	cmdUDPonTCP   = flag.Int64("udp-tcp", 1, "[C] use N TCP connections to relay UDP")
	cmdDebug      = flag.Bool("debug", false, "[C] turn on debug mode")
	cmdProxyPass  = flag.String("proxy-pass", "", "[C] use goflyway as a reverse HTTP proxy")
	cmdWebConPort = flag.Int("web-port", 8101, "[C] web console listening port, 0 to disable")
	cmdPartial    = flag.Bool("partial", false, "[SC] partially encrypt the tunnel traffic")
	cmdDNSCache   = flag.Int("dns-cache", 1024, "[C] DNS cache size")
	cmdMux        = flag.Int("mux", 0, "[SC] limit the total number of TCP connections, no limit by default")
	cmdThrot      = flag.Int64("throt", 0, "[S] traffic throttling in bytes")
	cmdThrotMax   = flag.Int64("throt-max", 1024*1024, "[S] traffic throttling token bucket max capacity")

	cmdCloseConn  = flag.Int64("close-after", 20, "[SC] close connections when they go idle for at least N sec")
	cmdAggClosing = flag.Bool("200", false, "[C] close connections aggressively to keep its number under 200, use with caution")
)

func loadConfig() {
	flag.Parse()

	path := *cmdConfig
	if path == "" {
		return
	}

	buf, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("* cannot load config file:", err)
		return
	}

	cf, err := config.ParseConf(string(buf))
	if err != nil {
		fmt.Println("* cannot parse config file:", err)
		return
	}

	*cmdKey = cf.GetString("default", "password", *cmdKey)
	*cmdAuth = cf.GetString("default", "auth", *cmdAuth)
	*cmdLocal = cf.GetString("default", "listen", *cmdLocal)
	*cmdUpstream = cf.GetString("default", "upstream", *cmdUpstream)
	*cmdUDPPort = cf.GetInt("default", "udp", *cmdUDPPort)
	*cmdUDPonTCP = cf.GetInt("default", "udptcp", *cmdUDPonTCP)
	*cmdBasic = cf.GetString("default", "type", *cmdBasic)
	*cmdPartial = cf.GetBool("default", "partial", *cmdPartial)

	*cmdProxyPass = cf.GetString("misc", "proxypass", *cmdProxyPass)
	*cmdWebConPort = int(cf.GetInt("misc", "webconport", int64(*cmdWebConPort)))
	*cmdDNSCache = int(cf.GetInt("misc", "dnscache", int64(*cmdDNSCache)))
	*cmdMux = int(cf.GetInt("misc", "mux", int64(*cmdMux)))
	*cmdLogLevel = cf.GetString("misc", "loglevel", *cmdLogLevel)
	*cmdLogFile = cf.GetString("misc", "logfile", *cmdLogFile)
	*cmdThrot = cf.GetInt("misc", "throt", *cmdThrot)
	*cmdThrotMax = cf.GetInt("misc", "throtmax", *cmdThrotMax)

	*cmdCloseConn = cf.GetInt("misc", "closeconn", *cmdCloseConn)
	*cmdAggClosing = cf.GetBool("misc", "aggrclose", *cmdAggClosing)
}

func main() {
	fmt.Println("goflyway (build " + version + ")")

	loadConfig()

	if *cmdGenCA {
		fmt.Println("* generating CA...")

		cert, key, err := lib.GenCA("goflyway")
		if err != nil {
			fmt.Println(err)
			return
		}

		err1, err2 := ioutil.WriteFile("ca.pem", cert, 0755), ioutil.WriteFile("key.pem", key, 0755)
		if err1 != nil || err2 != nil {
			fmt.Println("* error ca.pem:", err1)
			fmt.Println("* error key.pem:", err2)
			return
		}

		fmt.Println("* successfully generated ca.pem/key.pem, please leave them in the same directory with goflyway")
		fmt.Println("* goflyway will automatically read them when launched")
		return
	}

	if *cmdUpstream != "" {
		fmt.Println("* launched as client")
	} else {
		fmt.Println("* launched as server (aka upstream)")
	}

	if *cmdKey == "0123456789abcdef" {
		fmt.Println("* you are using the default password, it is recommended to change it: -k=<NEW PASSWORD>")
	}

	cipher := &proxy.Cipher{Partial: *cmdPartial}
	cipher.Init(*cmdKey)

	var cc *proxy.ClientConfig
	var sc *proxy.ServerConfig

	if *cmdMux > 0 {
		fmt.Println("* TCP multiplexer enabled, limit:", *cmdMux)
		fmt.Println("* when using the multiplexer, you must directly connect to the upstream")
	}

	if *cmdUpstream != "" || *cmdDebug {
		if !lookup.LoadOrCreateChinaList("") {
			fmt.Println("* cannot read chinalist.txt (but it's fine, you can ignore this message)")
		}

		cc = &proxy.ClientConfig{
			UserAuth:       *cmdAuth,
			Upstream:       *cmdUpstream,
			UDPRelayPort:   int(*cmdUDPPort),
			UDPRelayCoconn: int(*cmdUDPonTCP),
			Cipher:         cipher,
			DNSCache:       lru.NewCache(*cmdDNSCache),
			CACache:        lru.NewCache(256),
			CA:             lib.TryLoadCert(),
			Mux:            *cmdMux,
		}

		if is := func(in string) bool { return strings.HasPrefix(*cmdUpstream, in) }; is("https://") {
			cc.Connect2Auth, cc.Connect2, _, cc.Upstream = parseAuthURL(*cmdUpstream)
			fmt.Println("* use HTTPS proxy [", cc.Connect2, "] as the frontend, proxy auth: [", cc.Connect2Auth, "]")
		} else if gfw, http, ws, cf, fwd, fwdws :=
			is("gfw://"), is("http://"), is("ws://"), is("cf://"), is("fwd://"), is("fwds://"); gfw || http || ws || cf || fwd || fwdws {

			cc.Connect2Auth, cc.Upstream, cc.URLHeader, cc.DummyDomain = parseAuthURL(*cmdUpstream)

			switch true {
			case cf:
				fmt.Println("* connect to the upstream [", cc.Upstream, "] hosted on cloudflare")
				cc.DummyDomain = cc.Upstream
			case fwdws, fwd:
				if cc.URLHeader == "" {
					cc.URLHeader = "X-Forwarded-Url"
				}
				fmt.Println("* forward request to [", cc.Upstream, "], store the true URL in [",
					cc.URLHeader+": http://"+cc.DummyDomain+"/... ]")
			case cc.DummyDomain != "":
				fmt.Println("* use dummy host [", cc.DummyDomain, "] to connect [", cc.Upstream, "]")
			}

			switch true {
			case fwdws, cf, ws:
				cc.Policy.Set(proxy.PolicyWebSocket)
				fmt.Println("* use WebSocket protocol to transfer data")
			case fwd, http:
				cc.Policy.Set(proxy.PolicyManInTheMiddle)
				fmt.Println("* use MITM to intercept HTTPS (HTTP proxy mode only)")
			}
		}

		switch *cmdBasic {
		case "none":
			cc.Policy.Set(proxy.PolicyDisabled)
		case "global":
			cc.Policy.Set(proxy.PolicyGlobal)
		case "iplist_l":
			cc.Policy.Set(proxy.PolicyTrustClientDNS)
		case "iplist":
			// do nothing, default policy
		default:
			fmt.Println("* invalid proxy type:", *cmdBasic)
		}

		if *cmdAggClosing {
			cc.Policy.Set(proxy.PolicyAggrClosing)
		}
	}

	if *cmdUpstream == "" || *cmdDebug {
		sc = &proxy.ServerConfig{
			Cipher:         cipher,
			UDPRelayListen: int(*cmdUDPPort),
			Throttling:     *cmdThrot,
			ThrottlingMax:  *cmdThrotMax,
			ProxyPassAddr:  *cmdProxyPass,
			Mux:            *cmdMux != 0,
		}

		if *cmdAuth != "" {
			sc.Users = map[string]proxy.UserConfig{
				*cmdAuth: {},
			}
		}
	}

	if *cmdLogFile != "" {
		logg.Redirect(*cmdLogFile)
		fmt.Println("* redirect log to", *cmdLogFile)
	}

	logg.SetLevel(*cmdLogLevel)
	logg.Start()

	if *cmdDebug {
		fmt.Println("* debug mode on")

		cc.Upstream = "127.0.0.1:8101"
		client := proxy.NewClient(":8100", cc)
		go func() {
			logg.F(client.Start())
		}()

		server := proxy.NewServer(":8101", sc)
		logg.F(server.Start())
		return
	}

	if *cmdCloseConn > 0 {
		cipher.IO.StartPurgeConns(int(*cmdCloseConn))
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

		if *cmdWebConPort != 0 {
			go func() {
				addr := fmt.Sprintf("127.0.0.1:%d", *cmdWebConPort)
				http.HandleFunc("/", lib.WebConsoleHTTPHandler(client))
				fmt.Println("* access client web console at [", addr, "]")
				logg.F(http.ListenAndServe(addr, nil))
			}()
		}

		fmt.Println("* proxy", client.Cipher.Alias, "started at [", client.Localaddr, "], upstream: [", client.Upstream, "]")
		logg.F(client.Start())
	} else {
		// save some space because server doesn't need lookup
		lookup.ChinaList = nil
		lookup.IPv4LookupTable = nil
		lookup.IPv4PrivateLookupTable = nil
		lookup.CHN_IP = ""

		// global variables are pain in the ass
		runtime.GC()
		server := proxy.NewServer(localaddr, sc)
		fmt.Println("* upstream", server.Cipher.Alias, "started at [", server.Localaddr, "]")
		if strings.HasPrefix(sc.ProxyPassAddr, "http") {
			fmt.Println("* alternatively act as a reverse proxy:", sc.ProxyPassAddr)
		} else if sc.ProxyPassAddr != "" {
			fmt.Println("* alternatively act as a file server:", sc.ProxyPassAddr)
		}
		logg.F(server.Start())
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
		fmt.Println("* invalid upstream destination:", upstream, err)
		os.Exit(1)
	}

	return
}
