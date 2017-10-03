package main

import (
	"github.com/coyove/goflyway/pkg/config"
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/proxy"

	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"runtime"
)

var (
	G_Config = flag.String("c", "", "config file path")

	G_Key         = flag.String("k", "0123456789abcdef", "key, important")
	G_Auth        = flag.String("a", "", "proxy authentication, form: username:password (remember the colon)")
	G_Upstream    = flag.String("up", "", "upstream server address (e.g. 127.0.0.1:8100)")
	G_Local       = flag.String("l", ":8100", "local listening port (remember the colon)")
	G_Local2      = flag.String("p", "", "local listening port, alias of -l")
	G_UdpRelay    = flag.Int64("udp", 0, "UDP relay listening port, 0 to disable, not working yet")
	G_UdpTcp      = flag.Int64("udp-tcp", 1, "use N TCP connections to relay UDP")
	G_LogLevel    = flag.String("lv", "log", "logging level, whose value can be: dbg, log, warn, err or off")
	G_GlobalProxy = flag.Bool("g", false, "global proxy")

	G_Debug            = flag.Bool("debug", false, "debug mode")
	G_ProxyPassAddr    = flag.String("proxy-pass", "", "use goflyway as a reverse proxy, http only")
	G_DisableConsole   = flag.Bool("disable-console", false, "disable the console access")
	G_RecordLocalError = flag.Bool("local-error", false, "log all localhost errors")
	G_PartialEncrypt   = flag.Bool("partial", false, "partially encrypt the tunnel traffic")

	G_DNSCacheEntries = flag.Int("dns-cache", 1024, "DNS cache size")
	G_Throttling      = flag.Int64("throttling", 0, "traffic throttling, experimental")
	G_ThrottlingMax   = flag.Int64("throttling-max", 1024*1024, "traffic throttling token bucket max capacity")
)

func LoadConfig() {
	flag.Parse()

	path := *G_Config

	if path != "" {
		buf, err := ioutil.ReadFile(path)
		if err != nil {
			logg.F(err)
		}

		cf, err := config.ParseConf(string(buf))
		if err != nil {
			logg.F(err)
		}

		*G_Key = cf.GetString("default", "key", *G_Key)
		*G_Auth = cf.GetString("default", "auth", *G_Auth)
		*G_Local = cf.GetString("default", "listen", *G_Local)
		*G_Upstream = cf.GetString("default", "upstream", *G_Upstream)
		*G_UdpRelay = cf.GetInt("default", "udp", *G_UdpRelay)
		*G_UdpTcp = cf.GetInt("default", "udptcp", *G_UdpTcp)
		*G_LogLevel = cf.GetString("default", "loglevel", *G_LogLevel)
		*G_GlobalProxy = cf.GetBool("default", "global", *G_GlobalProxy)
		*G_RecordLocalError = cf.GetBool("misc", "localerror", *G_RecordLocalError)
		*G_ProxyPassAddr = cf.GetString("misc", "proxypass", *G_ProxyPassAddr)

		*G_DisableConsole = cf.GetBool("misc", "disableconsole", *G_DisableConsole)
		*G_DNSCacheEntries = int(cf.GetInt("misc", "dnscache", int64(*G_DNSCacheEntries)))
		*G_PartialEncrypt = cf.GetBool("misc", "partial", *G_PartialEncrypt)

		*G_Throttling = cf.GetInt("experimental", "throttling", *G_Throttling)
		*G_ThrottlingMax = cf.GetInt("experimental", "throttlingmax", *G_ThrottlingMax)
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

	LoadConfig()
	logg.SetLevel(*G_LogLevel)
	logg.RecordLocalhostError(*G_RecordLocalError)

	if *G_Key == "0123456789abcdef" {
		logg.W("you are using the default key, please change it by setting -k=KEY")
	}

	if *G_Upstream != "" {
		if !lookup.LoadOrCreateChinaList() {
			logg.W("cannot read chinalist.txt (but it's fine, you can ignore this msg)")
		}
	}

	cipher := &proxy.GCipher{
		KeyString: *G_Key,
		Partial:   *G_PartialEncrypt,
	}
	cipher.New()

	cc := &proxy.ClientConfig{
		DNSCacheSize:   *G_DNSCacheEntries,
		GlobalProxy:    *G_GlobalProxy,
		DisableConsole: *G_DisableConsole,
		UserAuth:       *G_Auth,
		Upstream:       *G_Upstream,
		UDPRelayPort:   int(*G_UdpRelay),
		UDPRelayCoconn: int(*G_UdpTcp),
		GCipher:        cipher,
	}

	sc := &proxy.ServerConfig{
		GCipher:        cipher,
		UDPRelayListen: int(*G_UdpRelay),
		Throttling:     *G_Throttling,
		ThrottlingMax:  *G_ThrottlingMax,
		ProxyPassAddr:  *G_ProxyPassAddr,
	}

	if *G_Auth != "" {
		sc.Users = map[string]proxy.UserConfig{
			*G_Auth: {},
		}
	}

	var client *proxy.ProxyClient
	if *G_Debug {
		logg.L("debug mode on, proxy listening port 8100")

		cc.Upstream = "127.0.0.1:8101"
		client = proxy.NewClient(":8100", cc)
		go logg.F(http.Serve(client.Listener, client))

		proxy.StartServer(":8101", sc)
		return
	}

	if *G_Upstream != "" {
		if *G_Local2 != "" {
			// -p has higher priority than -l, for the sack of SS users
			client = proxy.NewClient(*G_Local2, cc)
		} else {
			client = proxy.NewClient(*G_Local, cc)
		}

		logg.L("Hi! ", client.Nickname, ", proxy is listening at ", client.Localaddr, ", upstream is ", client.Upstream)
		logg.F(http.Serve(client.Listener, client))
	} else {
		// save some space because server doesn't need lookup
		lookup.ChinaList = nil
		lookup.IPv4LookupTable = nil
		lookup.IPv4PrivateLookupTable = nil
		lookup.CHN_IP = ""

		// global variables are pain in the ass
		runtime.GC()

		if *G_Local2 != "" {
			// -p has higher priority than -l, for the sack of SS users
			proxy.StartServer(*G_Local2, sc)
		} else {
			proxy.StartServer(*G_Local, sc)
		}
	}
}
