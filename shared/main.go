package main

/*
typedef void (*g_callback)();

static void invoke(g_callback f) { f(); }
*/
import "C"

import (
	"github.com/coyove/goflyway/pkg/logg"
	"github.com/coyove/goflyway/pkg/lookup"
	"github.com/coyove/goflyway/proxy"

	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

const (
	SVR_STARTED         = C.int(0)
	SVR_ALREADY_STARTED = C.int(1)

	SVR_ERROR_CODE   = C.int(1 << 15)
	SVR_ERROR_EXITED = C.int(1 << 1)
	SVR_ERROR_CREATE = C.int(1 << 2)
	SVR_ERROR_PANIC  = C.int(1 << 3)

	SVR_GLOBAL = C.int(1<<16) + 0
	SVR_IPLIST = C.int(1<<16) + 1
	SVR_NONE   = C.int(1<<16) + 2

	CHAR_BUF_SIZE = 2048
)

type msg_t struct {
	ts  int64
	msg string
}

// client means "client" of goflyway, server means "server" of local proxy
// both words can be used here
var (
	client        *proxy.ProxyClient
	clientStarted bool
	stopMutex     sync.Mutex
	logMutex      sync.Mutex
	logs          []msg_t
)

func copyToBuf(pbuf *C.char, str string) {
	if len(str) >= CHAR_BUF_SIZE-1 {
		str = str[:CHAR_BUF_SIZE-1] // an extra '\0' for C style string
	}

	buf := (*[1 << 24]byte)(unsafe.Pointer(pbuf))
	copy(buf[:len(str)], []byte(str))
	buf[len(str)] = 0
}

//export GetNickname
func GetNickname(pbuf *C.char) {
	var name string
	if client != nil {
		name = client.Nickname
	}

	copyToBuf(pbuf, name)
}

//export ManInTheMiddle
func ManInTheMiddle(enabled C.int) {
	if client != nil {
		// if int(enabled) == 1 {
		// 	proxy.CA_CERT = []byte(C.GoString(cert))
		// 	proxy.CA_KEY = []byte(C.GoString(key))
		// 	proxy.CA, _ = tls.X509KeyPair(proxy.CA_CERT, proxy.CA_KEY)
		// }

		client.ManInTheMiddle = int(enabled) == 1
	}
}

//export GetLastestLogIndex
func GetLastestLogIndex() C.ulonglong {
	logMutex.Lock()
	defer logMutex.Unlock()

	if client == nil {
		return C.ulonglong(0xffffffffffffffff)
	}

	return C.ulonglong(len(logs))
}

//export ReadLog
func ReadLog(idx C.ulonglong, pbuf *C.char) C.ulonglong {
	// do not lock here
	if client == nil || int(idx) >= len(logs) {
		return C.ulonglong(0)
	}

	copyToBuf(pbuf, logs[idx].msg)
	return C.ulonglong(logs[idx].ts)
}

//export DeleteLogSince
func DeleteLogSince(idx C.ulonglong) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if client == nil || int(idx) >= len(logs) {
		return
	}

	logs = logs[idx+1:]
}

//export StartServer
func StartServer(
	created C.g_callback,
	logLevel *C.char, chinaList *C.char, upstream *C.char, localaddr *C.char, auth *C.char, key *C.char, domain *C.char,
	partial C.int, dnsSize C.int, udpPort C.int, udptcp C.int,
) C.int {
	runtime.LockOSThread()
	stopMutex.Lock()

	if clientStarted {
		stopMutex.Unlock()
		return SVR_ALREADY_STARTED
	}

	logg.SetLevel(C.GoString(logLevel))
	logg.RecordLocalhostError(false)
	logg.TreatFatalAsError(true)

	addLog := func(ts int64, msg string) {
		logMutex.Lock()
		logs = append(logs, msg_t{ts, msg})
		logMutex.Unlock()
	}
	logg.SetCallback(addLog)

	logg.Start()

	lookup.LoadOrCreateChinaList(C.GoString(chinaList))

	cipher := &proxy.GCipher{
		KeyString: C.GoString(key),
		Partial:   int(partial) == 1,
	}
	cipher.New()

	cc := &proxy.ClientConfig{
		DummyDomain:    C.GoString(domain),
		DNSCacheSize:   int(dnsSize),
		UserAuth:       C.GoString(auth),
		Upstream:       C.GoString(upstream),
		UDPRelayPort:   int(udpPort),
		UDPRelayCoconn: int(udptcp),
		GCipher:        cipher,
	}

	client = proxy.NewClient(C.GoString(localaddr), cc)
	if client == nil {
		stopMutex.Unlock()
		return SVR_ERROR_CODE | SVR_ERROR_CREATE
	}

	C.invoke(created)

	stopChan := make(chan bool, 1)
	ret := C.int(0)
	logs = make([]msg_t, 0)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				ret = SVR_ERROR_CODE | SVR_ERROR_PANIC
				addLog(time.Now().UnixNano(), fmt.Sprintf("%v", r))
				setClientNotStarted()
				stopChan <- true
			}
		}()

		clientStarted = true
		stopMutex.Unlock()

		if err := client.Start(); err != nil {
			ret = SVR_ERROR_CODE | SVR_ERROR_EXITED
			setClientNotStarted()
			stopChan <- true
		}
	}()

	select {
	case <-stopChan:
	}

	return ret
}

func setClientNotStarted() {
	stopMutex.Lock()
	clientStarted = false
	stopMutex.Unlock()
}

//export StopServer
func StopServer() {
	if clientStarted {
		client.Listener.Close()
		setClientNotStarted()
	}
}

//export SwitchProxyType
func SwitchProxyType(t C.int) C.int {
	stopMutex.Lock()
	defer stopMutex.Unlock()

	if client == nil {
		return C.int(0)
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

	return t
}

func main() {}
