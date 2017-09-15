package main

import (
	"github.com/coyove/goflyway/pkg/config"
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/pkg/lru"
	"github.com/coyove/goflyway/proxy"

	"flag"
	"fmt"
	"io/ioutil"
	"runtime"
)

var (
	G_Config = flag.String("c", "", "config file path")

	G_Key        = flag.String("k", "0123456789abcdef", "key, important")
	G_Auth       = flag.String("a", "", "proxy authentication, form: username:password (remember the colon)")
	G_Upstream   = flag.String("up", "", "upstream server address (e.g. 127.0.0.1:8100)")
	G_Local      = flag.String("l", ":8100", "local listening port (remember the colon)")
	G_SocksProxy = flag.String("s", ":8101", "socks5 proxy listening port, -s=0 to disable it")
	G_LogLevel   = flag.String("lv", "all", "logging level, whose value can be: all, warn, err or off")

	G_Debug            = flag.Bool("debug", false, "debug mode")
	G_DisableShoco     = flag.Bool("disable-shoco", false, "disable shoco compression")
	G_DisableConsole   = flag.Bool("disable-console", false, "disable the console access")
	G_ProxyAllTraffic  = flag.Bool("proxy-all", false, "proxy Chinese websites")
	G_UseChinaList     = flag.Bool("china-list", true, "identify Chinese websites using china-list")
	G_HRCounter        = flag.Bool("hr-counter", true, "use high resolution counter")
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
		*G_SocksProxy = cf.GetString("default", "socks5", *G_SocksProxy)
		*G_LogLevel = cf.GetString("default", "loglevel", *G_LogLevel)
		*G_ProxyAllTraffic = cf.GetBool("default", "proxyall", *G_ProxyAllTraffic)
		*G_UseChinaList = cf.GetBool("default", "chinalist", *G_UseChinaList)

		*G_RecordLocalError = cf.GetBool("misc", "localerror", *G_RecordLocalError)
		*G_DisableShoco = cf.GetBool("misc", "disableshoco", *G_DisableShoco)
		*G_HRCounter = cf.GetBool("misc", "hirescounter", *G_HRCounter)
		*G_DisableConsole = cf.GetBool("misc", "disableconsole", *G_DisableConsole)
		*G_DNSCacheEntries = int(cf.GetInt("misc", "dnscache", int64(*G_DNSCacheEntries)))
		*G_PartialEncrypt = cf.GetBool("misc", "partial", *G_PartialEncrypt)

		*G_Throttling = cf.GetInt("experimental", "throttling", *G_Throttling)
		*G_ThrottlingMax = cf.GetInt("experimental", "throttlingmax", *G_ThrottlingMax)
	}
}

func main() {
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
		logg.W("[WARNING] you are using the default key, please change it by setting -k=KEY")
	}

	if *G_UseChinaList && *G_Upstream != "" {
		if !lookup.LoadOrCreateChinaList() {
			logg.W("cannot read chinalist.txt")
		}
	}

	cipher := &proxy.GCipher{
		KeyString: *G_Key,
		Hires:     *G_HRCounter,
		Partial:   *G_PartialEncrypt,
		Shoco:     !*G_DisableShoco,
	}
	cipher.New()

	cc := &proxy.ClientConfig{
		DNSCache:        lru.NewCache(*G_DNSCacheEntries),
		Dummies:         lru.NewCache(6),
		ProxyAllTraffic: *G_ProxyAllTraffic,
		UseChinaList:    *G_UseChinaList,
		DisableConsole:  *G_DisableConsole,
		UserAuth:        *G_Auth,
		Upstream:        *G_Upstream,
		GCipher:         cipher,
	}

	sc := &proxy.ServerConfig{
		GCipher:       cipher,
		Throttling:    *G_Throttling,
		ThrottlingMax: *G_ThrottlingMax,
	}

	if *G_Debug {
		logg.L("debug mode on, port 8100 for http proxy, port 8101 for socks5 proxy")

		cc.Upstream = "127.0.0.1:8102"
		go proxy.StartClient(":8100", ":8101", cc)
		proxy.StartServer(":8102", sc)
		return
	}

	if *G_Upstream != "" {
		proxy.StartClient(*G_Local, *G_SocksProxy, cc)
	} else {
		// save some space because server doesn't need lookup
		lookup.ChinaList = nil
		lookup.IPv4LookupTable = nil
		lookup.IPv4PrivateLookupTable = nil
		lookup.CHN_IP = ""

		// global variables are pain in the ass
		runtime.GC()

		proxy.StartServer(*G_Local, sc)
	}
}
