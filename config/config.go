package config

import (
	"../logg"
	"../lru"

	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
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
	G_Key      = flag.String("k", "0123456789abcdef", "key, important")
	G_Username = flag.String("u", "username", "proxy username")
	G_Password = flag.String("p", "password", "proxy password")
	G_Upstream = flag.String("up", "", "upstream server address (e.g. 127.0.0.1:8100)")
	G_Local    = flag.String("l", ":8100", "local listening")
	// G_Dummies  = flag.String("dummy", "china", "dummy hosts, separated by |")

	G_Debug            = flag.Bool("debug", false, "debug mode")
	G_NoAuthentication = flag.Bool("disable-pa", false, "disable proxy authentication")
	G_NoShoco          = flag.Bool("disable-shoco", false, "disable shoco compression")
	G_ProxyAllTraffic  = flag.Bool("proxy-all", false, "proxy Chinese websites")
	G_UseChinaList     = flag.Bool("china-list", true, "identify Chinese websites using china-list")
	G_HRCounter        = flag.Bool("hr-counter", true, "use high resolution counter")
	G_RecordLocalError = flag.Bool("local-error", false, "log all localhost errors")

	G_DNSCacheEntries = flag.Int("dns-cache", 1024, "DNS cache size")
)

func setString(k *string, v interface{}) {
	switch v.(type) {
	case string:
		if v.(string) != "" {
			*k = v.(string)
		}
	}
}

func setBool(k *bool, v interface{}) {
	switch v.(type) {
	case bool:
		*k = v.(bool)
	}
}

func setInt(k *int, v interface{}) {
	switch v.(type) {
	case int:
		*k = v.(int)
	}
}

func LoadConfig(path string) {
	if path != "" {
		buf, err := ioutil.ReadFile(path)
		if err != nil {
			logg.F(err)
		}

		m := make(map[string]interface{})
		err = json.Unmarshal(buf, &m)
		if err != nil {
			logg.F(err)
		}

		setString(G_Key, m["key"])
		setString(G_Username, m["username"])
		setString(G_Password, m["password"])
		setString(G_Local, m["listen"])
		setString(G_Upstream, m["upstream"])
		// setString(G_Dummies, m["dummies"])

		setBool(G_RecordLocalError, m["localerror"])
		setBool(G_NoAuthentication, m["disablepa"])
		setBool(G_NoShoco, m["disableshoco"])
		setBool(G_ProxyAllTraffic, m["proxyall"])
		setBool(G_UseChinaList, m["chinalist"])
		setBool(G_HRCounter, m["hrcounter"])

		setInt(G_DNSCacheEntries, m["dnscache"])

		if *G_Key == "." {
			// use username/password combination as the key
			*G_Key = *G_Username + *G_Password
		}
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
