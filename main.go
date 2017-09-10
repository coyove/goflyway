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

	logg.RecordLocalhostError(*G_RecordLocalError)

	if *G_Key == "0123456789abcdef" {
		logg.W("[WARNING] you are using the default key, please change it by setting -k=KEY")
	}

	G_Cache, G_RequestDummies = lru.NewCache(*G_DNSCacheEntries), lru.NewCache(6)

	if *G_UseChinaList && *G_Upstream != "" {
		lookup.LoadOrCreateChinaList()
	}

	if *G_Debug {
		logg.L("debug mode on, port 8100 for local redirection, upstream on 8101")

		go proxy.StartClient(":8100", ":8101", "127.0.0.1:8102")
		proxy.StartServer(":8102")
		return
	}

	if *G_Upstream != "" {
		proxy.StartClient(*G_Local, *G_SocksProxy, *G_Upstream)
	} else {
		// save some space because server doesn't need lookup
		lookup.ChinaList = nil
		lookup.IPv4LookupTable = nil
		lookup.IPv4PrivateLookupTable = nil
		lookup.CHN_IP = ""

		// global variables are pain in the ass
		runtime.GC()

		proxy.StartServer(*G_Local)
	}
}
