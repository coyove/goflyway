package main

import (
	"strings"

	"github.com/coyove/goflyway/pkg/config"
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/proxy"

	"flag"
	"fmt"
	"io/ioutil"
	"runtime"
)

var (
	cmdConfig = flag.String("c", "", "config file path")
	cmdGenCA  = flag.Bool("gen-ca", false, "generate certificate / private key")

	cmdKey              = flag.String("k", "0123456789abcdef", "key, important")
	cmdAuth             = flag.String("a", "", "proxy authentication, form: username:password (remember the colon)")
	cmdBasic            = flag.String("b", "iplist", "proxy type, whose value can be: none, iplist, iplist_l, global, global_l")
	cmdUpstream         = flag.String("up", "", "upstream server address, form: [[username:password@]{https_proxy_ip:https_proxy_port,mitm}@]ip:port[;domain[?header]]")
	cmdLocal            = flag.String("l", ":8100", "local listening port (remember the colon)")
	cmdLocal2           = flag.String("p", "", "local listening port, alias of -l")
	cmdUDPPort          = flag.Int64("udp", 0, "server UDP relay listening port, 0 to disable")
	cmdUDPonTCP         = flag.Int64("udp-tcp", 1, "use N TCP connections to relay UDP")
	cmdLogLevel         = flag.String("lv", "log", "logging level, whose value can be: dbg, log, warn, err or off")
	cmdDebug            = flag.Bool("debug", false, "debug mode")
	cmdProxyPassAddr    = flag.String("proxy-pass", "", "use goflyway as a reverse proxy, HTTP only")
	cmdDisableConsole   = flag.Bool("disable-console", false, "disable the access to web console")
	cmdRecordLocalError = flag.Bool("local-error", false, "log all localhost errors")
	cmdPartialEncrypt   = flag.Bool("partial", false, "partially encrypt the tunnel traffic")
	cmdDNSCacheEntries  = flag.Int("dns-cache", 1024, "DNS cache size")
	cmdThrottling       = flag.Int64("throttling", 0, "traffic throttling, experimental")
	cmdThrottlingMax    = flag.Int64("throttling-max", 1024*1024, "traffic throttling token bucket max capacity")
)

func loadConfig() {
	flag.Parse()

	path := *cmdConfig

	if path != "" {
		buf, err := ioutil.ReadFile(path)
		if err != nil {
			logg.F(err)
		}

		cf, err := config.ParseConf(string(buf))
		if err != nil {
			logg.F(err)
		}

		*cmdKey = cf.GetString("default", "key", *cmdKey)
		*cmdAuth = cf.GetString("default", "auth", *cmdAuth)
		*cmdLocal = cf.GetString("default", "listen", *cmdLocal)
		*cmdUpstream = cf.GetString("default", "upstream", *cmdUpstream)
		*cmdUDPPort = cf.GetInt("default", "udp", *cmdUDPPort)
		*cmdUDPonTCP = cf.GetInt("default", "udptcp", *cmdUDPonTCP)
		*cmdLogLevel = cf.GetString("default", "loglevel", *cmdLogLevel)
		*cmdBasic = cf.GetString("default", "type", *cmdBasic)
		*cmdRecordLocalError = cf.GetBool("misc", "localerror", *cmdRecordLocalError)
		*cmdProxyPassAddr = cf.GetString("misc", "proxypass", *cmdProxyPassAddr)

		*cmdDisableConsole = cf.GetBool("misc", "disableconsole", *cmdDisableConsole)
		*cmdDNSCacheEntries = int(cf.GetInt("misc", "dnscache", int64(*cmdDNSCacheEntries)))
		*cmdPartialEncrypt = cf.GetBool("misc", "partial", *cmdPartialEncrypt)

		*cmdThrottling = cf.GetInt("experimental", "throttling", *cmdThrottling)
		*cmdThrottlingMax = cf.GetInt("experimental", "throttlingmax", *cmdThrottlingMax)
	}
}

func main() {
	logg.Start()
	fmt.Println(`     __//                   __ _
    /.__.\                 / _| |
    \ \/ /      __ _  ___ | |_| |_   ___      ____ _ _   _
 '__/    \     / _' |/ _ \|  _| | | | \ \ /\ / / _' | | | |
  \-      )   | (_| | (_) | | | | |_| |\ V  V / (_| | |_| |
   \_____/     \__, |\___/|_| |_|\__, | \_/\_/ \__,_|\__, |
 ____|_|____    __/ |             __/ |               __/ |
     " "  cf   |___/             |___/               |___/
 `)

	loadConfig()

	if *cmdGenCA {
		fmt.Println("generating CA...")

		cert, key, err := proxy.GenCA("goflyway")
		if err != nil {
			fmt.Println(err)
			return
		}

		err1, err2 := ioutil.WriteFile("ca.pem", cert, 0755), ioutil.WriteFile("key.pem", key, 0755)
		if err1 != nil || err2 != nil {
			fmt.Println("ca.pem:", err1)
			fmt.Println("key.pem:", err2)
			return
		}

		fmt.Println("done")
		fmt.Println("goflyway has generated ca.pem and key.pem, please leave them in the same directory with goflyway")
		return
	}

	logg.SetLevel(*cmdLogLevel)
	logg.RecordLocalhostError(*cmdRecordLocalError)

	if *cmdKey == "0123456789abcdef" {
		logg.W("you are using the default key, please change it by setting -k=KEY")
	}

	if *cmdUpstream != "" {
		if !lookup.LoadOrCreateChinaList("") {
			logg.W("cannot read chinalist.txt (but it's fine, you can ignore this msg)")
		}
	}

	cipher := &proxy.Cipher{
		KeyString: *cmdKey,
		Partial:   *cmdPartialEncrypt,
	}
	cipher.New()

	cc := &proxy.ClientConfig{
		DNSCacheSize:   *cmdDNSCacheEntries,
		DisableConsole: *cmdDisableConsole,
		UserAuth:       *cmdAuth,
		Upstream:       *cmdUpstream,
		UDPRelayPort:   int(*cmdUDPPort),
		UDPRelayCoconn: int(*cmdUDPonTCP),
		Cipher:         cipher,
	}

	if idx1, idx2 := strings.Index(*cmdUpstream, "@"), strings.LastIndex(*cmdUpstream, "@"); idx1 > -1 && idx2 > -1 {
		c2, c2a := (*cmdUpstream)[:idx2], ""
		if idx1 != idx2 {
			c2a = c2[:idx1]
			c2 = c2[idx1+1:]
		}

		if c2 == "mitm" {
			logg.L("man-in-the-middle to intercept HTTPS")
			cc.ManInTheMiddle = true
		} else {
			logg.L("using HTTPS proxy as the frontend: ", c2)
			cc.Connect2 = c2
			cc.Connect2Auth = c2a
		}

		if c2a != "" {
			logg.L("... proxy auth: ", c2a)
		}

		up := (*cmdUpstream)[idx2+1:]
		if idx1 = strings.Index(up, ";"); idx1 > -1 {
			cc.DummyDomain = up[idx1+1:]
			up = up[:idx1]

			if idx1 = strings.Index(cc.DummyDomain, "?"); idx1 > -1 {
				cc.URLHeader = cc.DummyDomain[idx1+1:]
				cc.DummyDomain = cc.DummyDomain[:idx1]
				logg.L("the true URL will be stored in: ", cc.URLHeader)
			}

			logg.L("dummy domain is: ", cc.DummyDomain, ", every HTTP reqeust sent out will have it as the host name")
		}
		cc.Upstream = up
	}

	switch *cmdBasic {
	case "none":
		cc.NoProxy = true

	case "global_l":
		cc.TrustLocalDNS = true
		fallthrough
	case "global":
		cc.NoProxy = false
		cc.GlobalProxy = true

	case "iplist_l":
		cc.TrustLocalDNS = true
		fallthrough
	case "iplist":
		cc.NoProxy = false
		cc.GlobalProxy = false
	default:
		logg.W("invalid proxy type: ", *cmdBasic)
	}

	sc := &proxy.ServerConfig{
		Cipher:         cipher,
		UDPRelayListen: int(*cmdUDPPort),
		Throttling:     *cmdThrottling,
		ThrottlingMax:  *cmdThrottlingMax,
		ProxyPassAddr:  *cmdProxyPassAddr,
	}

	if *cmdAuth != "" {
		sc.Users = map[string]proxy.UserConfig{
			*cmdAuth: {},
		}
	}

	var client *proxy.ProxyClient
	if *cmdDebug {
		logg.L("debug mode on, proxy listening port 8100")

		cc.Upstream = "127.0.0.1:8101"
		client = proxy.NewClient(":8100", cc)
		go func() {
			logg.F(client.Start())
		}()

		proxy.StartServer(":8101", sc)
		return
	}

	if *cmdUpstream != "" {
		if *cmdLocal2 != "" {
			// -p has higher priority than -l, for the sack of SS users
			client = proxy.NewClient(*cmdLocal2, cc)
		} else {
			client = proxy.NewClient(*cmdLocal, cc)
		}

		logg.L("Hi! ", client.Nickname, ", proxy is listening at ", client.Localaddr, ", upstream is ", client.Upstream)
		logg.F(client.Start())
	} else {
		// save some space because server doesn't need lookup
		lookup.ChinaList = nil
		lookup.IPv4LookupTable = nil
		lookup.IPv4PrivateLookupTable = nil
		lookup.CHN_IP = ""

		// global variables are pain in the ass
		runtime.GC()

		if *cmdLocal2 != "" {
			// -p has higher priority than -l, for the sack of SS users
			proxy.StartServer(*cmdLocal2, sc)
		} else {
			proxy.StartServer(*cmdLocal, sc)
		}
	}
}
