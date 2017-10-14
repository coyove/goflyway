package proxy

import (
	"github.com/coyove/goflyway/pkg/logg"

	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type bufioConn struct {
	m io.Reader
	net.Conn
}

func (c *bufioConn) Read(buf []byte) (int, error) {
	return c.m.Read(buf)
}

func (proxy *ProxyClient) manInTheMiddle(client net.Conn, host, auth string, r *http.Request) {
	_host, _ := splitHostPort(host)
	// try self signing a cert of this host
	cert := sign(_host)
	if cert == nil {
		return
	}

	client.Write(OK_HTTP)

	go func() {
		// bufClient := bufio.NewReader(client)
		// bufioClient := &bufioConn{Conn: client, m: bufClient}

		// buf, err := bufClient.Peek(3)
		// if err == nil {
		// 	switch string(buf) {
		// 	case "GET", "POS" /*T*/, "HEA" /*D*/, "PUT", "DEL" /*ETE*/, "OPT" /*ION*/, "PAT" /*CH*/, "TRA" /*CE*/ :
		// 		// we are having http requests inside CONNECT command
		// 		// e.g. websocket
		// 		// TODO
		// 		// proxy.dialUpstreamAndBridge(bufioClient, host, auth, DO_HTTP|DO_DROP_INIT_REP)
		// 	default:
		// 	}
		// }

		tlsClient := tls.Server(client, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{*cert},
		})

		if err := tlsClient.Handshake(); err != nil {
			logg.E("handshake failed: ", r.Host, ", ", err)
			return
		}

		defer tlsClient.Close()
		bufTLSClient := bufio.NewReader(tlsClient)
		// isWebsocket := false

		for {
			var err error
			var rUrl string
			if _, err := bufTLSClient.Peek(1); err == io.EOF {
				break
			}

			req, err := http.ReadRequest(bufTLSClient)
			if err != nil {
				logg.E("cannot read request: ", err)
				return
			}

			logg.D("mitm: ", req.Method, " ", req.RequestURI, " ", r.RemoteAddr)
			req.RemoteAddr = r.RemoteAddr
			req.Header.Del("Proxy-Authorization")
			req.Header.Del("Proxy-Connection")

			if !isHttpsSchema.MatchString(req.URL.String()) {
				// we can ignore 443 since it's by default
				h := req.Host
				if strings.HasSuffix(h, ":443") {
					h = h[:len(h)-4]
				}

				req.URL, err = url.Parse("https://" + h + req.URL.String())
				rUrl = req.URL.String()
			}

			resp, rkeybuf, err := proxy.encryptAndTransport(req, auth)
			if err != nil {
				logg.E("mitm proxy pass: ", rUrl, ", ", err)
				return
			}

			defer tryClose(resp.Body)

			resp.Header.Del("Content-Length")
			resp.Header.Set("Transfer-Encoding", "chunked")

			if strings.ToLower(resp.Header.Get("Connection")) != "upgrade" {
				resp.Header.Set("Connection", "close")
				tlsClient.Write([]byte("HTTP/1.1 " + resp.Status))
			} else {
				// we don't support websocket
				tlsClient.Write([]byte("HTTP/1.1 403 Forbidden"))
				break
			}

			// buf, _ := httputil.DumpResponse(resp, true)
			_ = httputil.DumpResponse

			hdr := http.Header{}
			copyHeaders(hdr, resp.Header, proxy.GCipher, false)
			if err := hdr.Write(tlsClient); err != nil {
				logg.W("mitm write header: ", err)
				return
			}
			if _, err = io.WriteString(tlsClient, "\r\n"); err != nil {
				logg.W("mitm write header: ", err)
				return
			}

			iocc := proxy.GCipher.WrapIO(tlsClient, resp.Body, rkeybuf, &IOConfig{Chunked: true})
			iocc.Partial = false

			if nr, err := iocc.DoCopy(); err != nil {
				logg.E("mitm io.wrap ", nr, "bytes: ", err)
			}
		}

		logg.D("mitm close connection: ", host)
	}()
}
