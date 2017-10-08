package main

/*
typedef void (*g_callback)(unsigned long long, const char*);

static void invoke(g_callback f, unsigned long long ts, const char* msg) {
	if (f) f(ts, msg);
}
*/
import "C"

import (
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/proxy"
)

const (
	SVR_STARTED         = C.int(0)
	SVR_ALREADY_STARTED = C.int(1)

	SVR_ERROR_CODE   = C.int(1 << 15)
	SVR_ERROR_EXITED = C.int(1 << 1)
	SVR_ERROR_CREATE = C.int(1 << 2)

	SVR_GLOBAL = C.int(1<<16) + 0
	SVR_IPLIST = C.int(1<<16) + 1
	SVR_NONE   = C.int(1<<16) + 2
)

// client means "client" of goflyway, server means "server" of local proxy
// both words can be used here
var client *proxy.ProxyClient

//export GetNickname
func GetNickname() *C.char {
	if client == nil {
		return nil
	}

	return C.CString(client.Nickname)
}

//export StartServer
func StartServer(
	logLevel *C.char,
	chinaList *C.char,
	logCallback C.g_callback,
	errCallback C.g_callback,
	upstream *C.char,
	localaddr *C.char,
	auth *C.char,
	key *C.char,
	partial C.int,
	dnsSize C.int,
	udpPort C.int,
	udptcp C.int,
) C.int {

	if client != nil {
		return SVR_ALREADY_STARTED
	}

	logg.SetLevel(C.GoString(logLevel))
	logg.RecordLocalhostError(false)
	logg.TreatFatalAsError(true)
	logg.SetCallback(func(ts int64, msg string) {
		C.invoke(logCallback, C.ulonglong(ts), C.CString(msg))
	})

	logg.Start()

	lookup.LoadOrCreateChinaList(C.GoString(chinaList))

	cipher := &proxy.GCipher{
		KeyString: C.GoString(key),
		Partial:   int(partial) == 1,
	}
	cipher.New()

	cc := &proxy.ClientConfig{
		DNSCacheSize:   int(dnsSize),
		UserAuth:       C.GoString(auth),
		Upstream:       C.GoString(upstream),
		UDPRelayPort:   int(udpPort),
		UDPRelayCoconn: int(udptcp),
		GCipher:        cipher,
	}

	client = proxy.NewClient(C.GoString(localaddr), cc)
	if client == nil {
		return SVR_ERROR_CODE | SVR_ERROR_CREATE
	}

	go func() {
		if err := client.Start(); err != nil {
			client = nil
			C.invoke(errCallback, C.ulonglong(SVR_ERROR_CODE|SVR_ERROR_EXITED), C.CString(err.Error()))
		}
	}()

	return SVR_STARTED
}

//export StopServer
func StopServer() {
	if client != nil {
		client.Listener.Close()
		client = nil
	}
}

//export SwitchProxyType
func SwitchProxyType(t C.int) {
	if client == nil {
		return
	}

	switch t {
	case SVR_NONE:
		client.NoProxy = true

	case SVR_GLOBAL:
		client.NoProxy = false
		client.GlobalProxy = true

	case SVR_IPLIST:
		client.NoProxy = false
		client.GlobalProxy = false
	}
}

func main() {}
