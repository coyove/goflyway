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

	"fmt"
	"os"
	"runtime"
	_ "runtime/cgo"
	"sync"
	"syscall"
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
)

var (
	kernel32         = syscall.MustLoadDLL("kernel32.dll")
	procSetStdHandle = kernel32.MustFindProc("SetStdHandle")
)

func setStdHandle(stdhandle int32, handle syscall.Handle) error {
	r0, _, e1 := syscall.Syscall(procSetStdHandle.Addr(), 2, uintptr(stdhandle), uintptr(handle), 0)
	if r0 == 0 {
		if e1 != 0 {
			return error(e1)
		}
		return syscall.EINVAL
	}
	return nil
}

// redirectStderr to the file passed in
func redirectStderr(f *os.File) {
	setStdHandle(syscall.STD_ERROR_HANDLE, syscall.Handle(f.Fd()))
}

// client means "client" of goflyway, server means "server" of local proxy
// both words can be used here
var client *proxy.ProxyClient
var clientStarted bool
var stopMutex sync.Mutex

//export GetNickname
func GetNickname() *C.char {
	if !clientStarted {
		return C.CString("")
	}

	return C.CString(client.Nickname)
}

//export Unlock
func Unlock() {
	if clientStarted {
		client.PleaseUnlockMe()
	}
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
	stopMutex.Lock()

	if clientStarted {
		stopMutex.Unlock()
		return SVR_ALREADY_STARTED
	}

	ferr, _ := os.Create("error.txt")
	redirectStderr(ferr)

	logg.SetLevel(C.GoString(logLevel))
	logg.RecordLocalhostError(false)
	logg.TreatFatalAsError(true)
	logg.SetCallback(func(ts int64, msg string) {
		runtime.LockOSThread()
		C.invoke(logCallback, C.ulonglong(ts), C.CString(msg))
		runtime.UnlockOSThread()
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
		stopMutex.Unlock()
		return SVR_ERROR_CODE | SVR_ERROR_CREATE
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				runtime.LockOSThread()
				C.invoke(errCallback, C.ulonglong(SVR_ERROR_CODE|SVR_ERROR_PANIC), C.CString(fmt.Sprintf("%v", r)))
				runtime.UnlockOSThread()
			}
		}()

		client2 := client
		clientStarted = true
		stopMutex.Unlock()

		if err := client2.Start(); err != nil {
			setNil()
			runtime.LockOSThread()
			C.invoke(errCallback, C.ulonglong(SVR_ERROR_CODE|SVR_ERROR_EXITED), C.CString(err.Error()))
			runtime.UnlockOSThread()
		}
	}()

	return SVR_STARTED
}

func setNil() {
	stopMutex.Lock()
	// client = nil
	clientStarted = false
	stopMutex.Unlock()
}

//export StopServer
func StopServer() {
	if clientStarted {
		client.Listener.Close()
		setNil()
	}
}

//export SwitchProxyType
func SwitchProxyType(t C.int) {
	if !clientStarted {
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
