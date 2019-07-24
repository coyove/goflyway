package proxy

import (
	"net"

	"crypto/tls"
	"regexp"
	"strings"
	"time"
)

const (
	socksVersion5   = byte(0x05)
	socksAddrIPv4   = 1
	socksAddrDomain = 3
	socksAddrIPv6   = 4
)

const (
	doConnect       = 1 << iota // Establish TCP tunnel
	doHTTPReq                   // Forward plain HTTP request
	doWebSocket                 // Use Websocket protocol
	doMuxWS                     // Multiplexer over WS
	doDNS                       // DNS query request
	doPartialCipher             // Partial encryption
	doDisableCipher             // No encryption
	doUDPRelay                  // UDP relay request
	doLocalRP                   // Request to ctrl server

	// Currently we have 9 options, so in clientRequest.Marshal
	// we can use "uint16" to store. If more options to be added in the future,
	// code in clientRequest.Marshal must also be changed.
)

const (
	PolicyMITM = 1 << iota
	PolicyForward
	PolicyAgent
	PolicyGlobal
	PolicyVPN
	PolicyWebSocket
	PolicyHTTPS
	PolicyKCP
	PolicyDisableUDP
	PolicyDisableLRP
)

const (
	timeoutUDP          = 30 * time.Second
	timeoutTCP          = 60 * time.Second
	timeoutDial         = 60 * time.Second
	timeoutOp           = 60 * time.Second
	invalidRequestRetry = 10
	dnsRespHeader       = "ETag"
	errConnClosedMsg    = "use of closed network connection"
	fwdURLHeader        = "X-Forwarded-Url"
)

var (
	okHTTP         = []byte("HTTP/1.0 200 Connection Established\r\n\r\n")
	okSOCKS        = []byte{socksVersion5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	http101        = []byte("HTTP/1.1 101 Switching Protocols")
	http200        = []byte("HTTP/1.1 200 OK")
	http403        = []byte("HTTP/1.1 403 Forbidden")
	udpHeaderIPv4  = []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	udpHeaderIPv6  = []byte{0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	socksHandshake = []byte{socksVersion5, 1, 0}
	dummyHeaders   = []string{"Accept-Language", "Accept-Encoding", "Cache-Control", "Connection", "Referer", "User-Agent"}
	tlsSkip        = &tls.Config{InsecureSkipVerify: true}
	hasPort        = regexp.MustCompile(`:\d+$`)
	isHTTPSSchema  = regexp.MustCompile(`^https:\/\/`)
)

type Options uint32

func (o *Options) IsSet(option uint32) bool {
	return (uint32(*o) & option) != 0
}

func (o *Options) Set(options ...uint32) {
	for _, option := range options {
		*o = Options(uint32(*o) | option)
	}
}

func (o *Options) SetBool(b bool, option uint32) {
	if b {
		o.Set(option)
	}
}

func (o *Options) UnSet(options ...uint32) {
	for _, option := range options {
		*o = Options((uint32(*o) | option) - option)
	}
}

func isClosedConnErr(err error) bool {
	return strings.Contains(err.Error(), "use of closed")
}

func isTimeoutErr(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}

	return false
}
