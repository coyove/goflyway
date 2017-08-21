package main

import (
	. "./config"
	"./logg"
	_ "./lookup"
	"./lru"
	"./proxy"

	"flag"
	"time"
)

var G_Config = flag.String("c", "", "config file path")

func main() {
	flag.Parse()
	LoadConfig(*G_Config)

	if *G_Key == "0123456789" {
		logg.W("just a reminder: you leave the key unchanged, better to set a different one")
	}

	if !*G_NoPA && *G_Username == "username" && *G_Password == "password" {
		logg.W("you are using the default username and password for your proxy")
	}

	G_Cache = lru.NewCache(1024)
	if *G_Debug || *G_Upstream != "" {
		go func() {
			for {
				time.Sleep(10 * time.Minute)
				G_Cache.PrintTopInfo(10)
			}
		}()
	}

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
