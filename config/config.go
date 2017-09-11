package config

import (
	"../logg"
	"../lru"

	"crypto/aes"
	"crypto/cipher"
	"flag"
	"io/ioutil"
)

var (
	G_KeyBytes       []byte
	G_KeyBlock       cipher.Block
	G_Cache          *lru.Cache
	G_RequestDummies *lru.Cache
)

var (
	G_Config = flag.String("c", "", "config file path")

	G_Key      = flag.String("k", "0123456789abcdef", "key, important")
	G_Auth     = flag.String("a", "", "proxy authentication, form: username:password (remember the colon)")
	G_Upstream = flag.String("up", "", "upstream server address (e.g. 127.0.0.1:8100)")
	G_Local    = flag.String("l", ":8100", "local listening")

	G_Debug            = flag.Bool("debug", false, "debug mode")
	G_DisableShoco     = flag.Bool("disable-shoco", false, "disable shoco compression")
	G_DisableConsole   = flag.Bool("disable-console", false, "disable the console access")
	G_ProxyAllTraffic  = flag.Bool("proxy-all", false, "proxy Chinese websites")
	G_UseChinaList     = flag.Bool("china-list", true, "identify Chinese websites using china-list")
	G_HRCounter        = flag.Bool("hr-counter", true, "use high resolution counter")
	G_RecordLocalError = flag.Bool("local-error", false, "log all localhost errors")
	G_PartialEncrypt   = flag.Bool("partial", false, "partially encrypt the tunnel traffic")

	G_DNSCacheEntries = flag.Int("dns-cache", 1024, "DNS cache size")
	G_Throttling      = flag.Int("throttling", 0, "traffic throttling, experimental")
	G_ThrottlingMax   = flag.Int("throttling-max", 1024*1024, "traffic throttling token bucket max capacity")
)

func LoadConfig() {
	flag.Parse()

	path := *G_Config

	if path != "" {
		buf, err := ioutil.ReadFile(path)
		if err != nil {
			logg.F(err)
		}

		cf, err := ParseConf(string(buf))
		if err != nil {
			logg.F(err)
		}

		*G_Key = /*     */ cf.GetString("default", "key", *G_Key)
		*G_Auth = /*    */ cf.GetString("default", "auth", *G_Auth)
		*G_Local = /*   */ cf.GetString("default", "listen", *G_Local)
		*G_Upstream = /**/ cf.GetString("default", "upstream", *G_Upstream)
		*G_ProxyAllTraffic = cf.GetBool("default", "proxyall", *G_ProxyAllTraffic)
		*G_UseChinaList = cf.GetBool("default", "chinalist", *G_UseChinaList)

		*G_RecordLocalError = cf.GetBool("misc", "localerror", *G_RecordLocalError)
		*G_DisableShoco = cf.GetBool("misc", "disableshoco", *G_DisableShoco)
		*G_HRCounter = cf.GetBool("misc", "hirescounter", *G_HRCounter)
		*G_DisableConsole = cf.GetBool("misc", "disableconsole", *G_DisableConsole)
		*G_DNSCacheEntries = int(cf.GetInt("misc", "dnscache", int64(*G_DNSCacheEntries)))
		*G_PartialEncrypt = cf.GetBool("misc", "partial", *G_PartialEncrypt)

		*G_Throttling = int(cf.GetInt("experimental", "throttling", int64(*G_Throttling)))
		*G_ThrottlingMax = int(cf.GetInt("experimental", "throttlingmax", int64(*G_ThrottlingMax)))
	}

	UpdateKey()
}

func UpdateKey() {
	G_KeyBytes = []byte(*G_Key)
	for len(G_KeyBytes) < 32 {
		G_KeyBytes = append(G_KeyBytes, G_KeyBytes...)
	}

	G_KeyBlock, _ = aes.NewCipher(G_KeyBytes[:32])
	if G_KeyBlock == nil {
		logg.F("cannot create aes cipher")
	}
}
