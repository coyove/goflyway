package main

import (
	. "./config"
	"./logg"
	"./lookup"
	"./lru"
	"./proxy"

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
