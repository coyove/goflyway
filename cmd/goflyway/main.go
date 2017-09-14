package main

import (
	"github.com/coyove/goflyway/pkg/config"
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/pkg/lru"
	"github.com/coyove/goflyway/pkg/proxy"

	"fmt"
	"runtime"
)

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

	config.LoadConfig()
	logg.SetLevel(*config.G_LogLevel)
	logg.RecordLocalhostError(*config.G_RecordLocalError)

	if *config.G_Key == "0123456789abcdef" {
		logg.W("[WARNING] you are using the default key, please change it by setting -k=KEY")
	}

	if *config.G_UseChinaList && *config.G_Upstream != "" {
		if !lookup.LoadOrCreateChinaList() {
			logg.W("cannot read chinalist.txt")
		}
	}

	cipher := &proxy.GCipher{
		KeyString: *config.G_Key,
		Hires:     *config.G_HRCounter,
		Partial:   *config.G_PartialEncrypt,
		Shoco:     !*config.G_DisableShoco,
	}
	cipher.New()

	cc := &proxy.ClientConfig{
		DNSCache:        lru.NewCache(*config.G_DNSCacheEntries),
		Dummies:         lru.NewCache(6),
		ProxyAllTraffic: *config.G_ProxyAllTraffic,
		UseChinaList:    *config.G_UseChinaList,
		DisableConsole:  *config.G_DisableConsole,
		UserAuth:        *config.G_Auth,
		Upstream:        *config.G_Upstream,
		GCipher:         cipher,
	}

	sc := &proxy.ServerConfig{
		GCipher:       cipher,
		Throttling:    *config.G_Throttling,
		ThrottlingMax: *config.G_ThrottlingMax,
	}

	if *config.G_Debug {
		logg.L("debug mode on, port 8100 for http proxy, port 8101 for socks5 proxy")

		cc.Upstream = "127.0.0.1:8102"
		go proxy.StartClient(":8100", ":8101", cc)
		proxy.StartServer(":8102", sc)
		return
	}

	if *config.G_Upstream != "" {
		proxy.StartClient(*config.G_Local, *config.G_SocksProxy, cc)
	} else {
		// save some space because server doesn't need lookup
		lookup.ChinaList = nil
		lookup.IPv4LookupTable = nil
		lookup.IPv4PrivateLookupTable = nil
		lookup.CHN_IP = ""

		// global variables are pain in the ass
		runtime.GC()

		proxy.StartServer(*config.G_Local, sc)
	}
}
