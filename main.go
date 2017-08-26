package main

import (
	. "./config"
	"./logg"
	_ "./lookup"
	"./lru"
	"./proxy"

	"flag"
	"fmt"
)

var G_Config = flag.String("c", "", "config file path")

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

	flag.Parse()
	LoadConfig(*G_Config)

	if *G_Key == "0123456789" {
		logg.W("[WARNING] you are using the default key (-k key)")
	}

	if !*G_NoPA && *G_Username == "username" && *G_Password == "password" {
		logg.W("[WARNING] you are using the default username and password (-u user and -p pass)")
	}

	G_Cache = lru.NewCache(*G_DNSCacheEntries)

	if *G_Debug {
		logg.L("debug mode on, port 8100 for local redirection, upstream on 8101")

		go proxy.StartClient(":8100", "127.0.0.1:8101")
		proxy.StartServer(":8101")
		return
	}

	if *G_Upstream != "" {
		proxy.StartClient(*G_Local, *G_Upstream)
	} else {
		proxy.StartServer(*G_Local)
	}
}
