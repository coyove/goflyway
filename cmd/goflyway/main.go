package main

import (
	"net/http"

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
	cmdBasic      = flag.String("b", "iplist", "[C] proxy type: {none, iplist, iplist_l, global, global_l}")
	cmdUpstream   = flag.String("up", "", "[C] upstream server address, form: [[username:password@]{https_proxy_ip:https_proxy_port,mitm}@]ip:port[;domain[?header]]")
	cmdLocal      = flag.String("l", ":8100", "[SC] local listening address")
	cmdLocal2     = flag.String("p", "", "[SC] local listening address, alias of -l")
	cmdUDPPort    = flag.Int64("udp", 0, "[SC] server UDP relay listening port, 0 to disable")
	cmdUDPonTCP   = flag.Int64("udp-tcp", 1, "[C] use N TCP connections to relay UDP")
	cmdDebug      = flag.Bool("debug", false, "[C] turn on debug mode")
	cmdProxyPass  = flag.String("proxy-pass", "", "[C] use goflyway as a reverse HTTP proxy")
	cmdWebConPort = flag.Int("web-port", 8101, "[C] web console listening port, 0 to disable")
	cmdPartial    = flag.Bool("partial", false, "[SC] partially encrypt the tunnel traffic")
	cmdDNSCache   = flag.Int("dns-cache", 1024, "[C] DNS cache size")
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

	if *cmdUpstream != "" || *cmdDebug {
		if !lookup.LoadOrCreateChinaList("") {
			fmt.Println("* cannot read chinalist.txt (but it's fine, you can ignore this message)")
		}

		cc = &proxy.ClientConfig{}
		cc.UserAuth = *cmdAuth
		cc.Upstream = *cmdUpstream
		cc.UDPRelayPort = int(*cmdUDPPort)
		cc.UDPRelayCoconn = int(*cmdUDPonTCP)
		cc.Cipher = cipher
		cc.DNSCache = lru.NewCache(*cmdDNSCache)
		cc.CACache = lru.NewCache(256)
		cc.CA = lib.TryLoadCert()

		if idx1, idx2 := strings.Index(*cmdUpstream, "@"), strings.LastIndex(*cmdUpstream, "@"); idx1 > -1 && idx2 > -1 {
			c2, c2a := (*cmdUpstream)[:idx2], ""
			if idx1 != idx2 {
				c2a = c2[:idx1]
				c2 = c2[idx1+1:]
			}

			if c2 == "mitm" {
				fmt.Println("* man-in-the-middle to intercept HTTPS")
				cc.Policy.Set(proxy.PolicyManInTheMiddle)
			} else {
				fmt.Println("* using HTTPS proxy as the frontend:", c2)
				cc.Connect2 = c2
				cc.Connect2Auth = c2a
			}

			if c2a != "" {
				fmt.Println("* ... and using proxy auth:", c2a)
			}

			up := (*cmdUpstream)[idx2+1:]
			if idx1 = strings.Index(up, ";"); idx1 > -1 {
				cc.DummyDomain = up[idx1+1:]
				up = up[:idx1]

				if idx1 = strings.Index(cc.DummyDomain, "?"); idx1 > -1 {
					cc.URLHeader = cc.DummyDomain[idx1+1:]
					cc.DummyDomain = cc.DummyDomain[:idx1]
					fmt.Println("* the true URL will be stored in:", cc.URLHeader)
				}

				fmt.Println("* all reqeusts sent out will have", cc.DummyDomain, "as the host name")
			}
			cc.Upstream = up
		}

		switch *cmdBasic {
		case "none":
			cc.Policy.Set(proxy.PolicyDisabled)

		case "global_l":
			cc.Policy.Set(proxy.PolicyTrustClientDNS)
			fallthrough
		case "global":
			cc.Policy.Set(proxy.PolicyGlobal)

		case "iplist_l":
			cc.Policy.Set(proxy.PolicyTrustClientDNS)
			fallthrough
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
		sc = &proxy.ServerConfig{}
		sc.Cipher = cipher
		sc.UDPRelayListen = int(*cmdUDPPort)
		sc.Throttling = *cmdThrot
		sc.ThrottlingMax = *cmdThrotMax
		sc.ProxyPassAddr = *cmdProxyPass

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

		fmt.Println("* proxy", client.Cipher.Alias, "started at [", client.Localaddr, "], upstream [", client.Upstream, "]")
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
		} else {
			fmt.Println("* alternatively act as a file server:", sc.ProxyPassAddr)
		}
		logg.F(server.Start())
	}
}
