package main

import (
	. "./config"
	"./logg"
	_ "./lookup"
	"./lru"
	"./proxy"

	"flag"
)

var G_Config = flag.String("c", "", "config file path")

func main() {
	flag.Parse()
	LoadConfig(*G_Config)

	if *G_Key == "0123456789" {
		logg.W("[WARNING] you are using the default key")
	}

	if !*G_NoPA && *G_Username == "username" && *G_Password == "password" {
		logg.W("[WARNING] you are using the default username and password")
	}

	G_Cache = lru.NewCache(*G_DNSCacheEntries)

	if *G_Debug {
		logg.L("debug mode on, port 8100 for local redirection, upstream on 8101")

		go proxy.Start(":8100", "127.0.0.1:8101")
		proxy.StartUpstream(":8101")
		return
	}

	if *G_Upstream != "" {
		proxy.Start(*G_Local, *G_Upstream)
	} else {
		proxy.StartUpstream(*G_Local)
	}
}
