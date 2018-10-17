package proxy

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type bufioConn struct {
	m io.Reader
	net.Conn
}

func (c *bufioConn) Read(buf []byte) (int, error) {
	return c.m.Read(buf)
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func (proxy *ProxyClient) sign(host string) *tls.Certificate {
	if cert, ok := proxy.CACache.Get(host); ok {
		return cert.(*tls.Certificate)
	}

	proxy.Logger.Dbgf("Self signing: %v", host)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		proxy.Logger.Errorf("MITM error: %v", err)
		return nil
	}

	x509ca, err := x509.ParseCertificate(proxy.CA.Certificate[0])
	if err != nil {
		return nil
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Issuer:       x509ca.Subject,
		Subject:      pkix.Name{Organization: []string{"goflyway"}},
		NotBefore:    time.Now().AddDate(0, 0, -1),
		NotAfter:     time.Now().AddDate(1, 0, 0),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	pubKey := publicKey(proxy.CA.PrivateKey)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, x509ca, pubKey, proxy.CA.PrivateKey)
	if err != nil {
		proxy.Logger.Errorf("Create certificate failed: %v", err)
		return nil
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes, proxy.CA.Certificate[0]},
		PrivateKey:  proxy.CA.PrivateKey,
	}

	proxy.CACache.Add(host, cert)
	return cert
}

var mitmSessionCounter int64

func (proxy *ProxyClient) manInTheMiddle(client net.Conn, host string) {
	_host, _ := splitHostPort(host)
	// try self signing a cert of this host
	cert := proxy.sign(_host)
	if cert == nil {
		return
	}

	client.Write(okHTTP)

	go func() {

		counter := atomic.AddInt64(&mitmSessionCounter, 1)

		tlsClient := tls.Server(client, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{*cert},
		})

		if err := tlsClient.Handshake(); err != nil {
			proxy.Logger.Errorf("TLS handshake failed: %v", err)
			return
		}

		bufTLSClient := bufio.NewReader(tlsClient)

		for {
			proxy.Cipher.IO.markActive(tlsClient, 0)

			var err error
			var rURL string
			var buf []byte
			if buf, err = bufTLSClient.Peek(3); err == io.EOF || len(buf) != 3 {
				break
			}

			req, err := http.ReadRequest(bufTLSClient)
			if err != nil {
				if !isClosedConnErr(err) && buf[0] != ')' {
					proxy.Logger.Errorf("Can't read request from TLS conn: %v", err)
				}
				break
			}

			if proxy.MITMDump != nil {
				buf, _ := httputil.DumpRequest(req, false)

				var b buffer
				b.WriteString(fmt.Sprintf("# %s <<<<<< request %d >>>>>>\n", timeStampMilli(), counter))
				b.Write(buf)

				proxy.MITMDump.Write(b.Bytes())
			}

			rURL = req.URL.Host
			req.Header.Del("Proxy-Authorization")
			req.Header.Del("Proxy-Connection")

			if !isHTTPSSchema.MatchString(req.URL.String()) {
				// we can ignore 443 since it's by default
				h := req.Host
				if strings.HasSuffix(h, ":443") {
					h = h[:len(h)-4]
				}

				req.URL, err = url.Parse("https://" + h + req.URL.String())
				rURL = req.URL.Host
			}

			var respBuf buffer
			var rkeybuf [ivLen]byte
			trans := proxy.tp

			if proxy.Policy.IsSet(PolicyAgent) {
				req = proxy.agentRequest(req)
				trans = proxy.tpd
			} else {
				cr := proxy.newRequest()
				cr.Opt.Set(doHTTPReq)
				rkeybuf = proxy.encryptRequest(req, cr)
				proxy.Logger.Dbgf("MITM - %s %s", req.Method, rURL)
			}

			if proxy.MITMDump != nil {
				req.Body = proxy.Cipher.IO.NewReadCloser(&dumpReadWriteWrapper{
					reader:  req.Body.(*IOReadCloserCipher).src,
					counter: counter,
					file:    proxy.MITMDump,
				}, rkeybuf)
			}

			resp, err := trans.RoundTrip(req)

			if err != nil {
				proxy.Logger.Errorf("Round trip %s: %v", rURL, err)
				tlsClient.Write(respBuf.Writes("HTTP/1.1 500 Internal Server Error\r\n\r\n", err.Error()).Bytes())
				break
			}

			resp.Header.Del("Content-Length")
			resp.Header.Set("Transfer-Encoding", "chunked")

			if strings.ToLower(resp.Header.Get("Connection")) != "upgrade" {
				resp.Header.Set("Connection", "close")
			} else {
				tlsClient.Write(respBuf.R().Writes("HTTP/1.1 403 Forbidden\r\n\r\n").Bytes())
				break
			}

			tlsClient.Write(respBuf.R().Writes("HTTP/1.1 ", resp.Status, "\r\n").Bytes())

			hdr := http.Header{}
			copyHeaders(hdr, resp.Header, proxy.Cipher, false, rkeybuf)
			if err := hdr.Write(tlsClient); err != nil {
				proxy.Logger.Warnf("MITM write error: %v", err)
				break
			}
			if _, err = io.WriteString(tlsClient, "\r\n"); err != nil {
				proxy.Logger.Warnf("MITM write error: %v", err)
				break
			}

			var clientWriter io.Writer = tlsClient

			if proxy.MITMDump != nil {
				buf, _ := httputil.DumpResponse(resp, false)

				var b buffer
				b.WriteString(fmt.Sprintf("# %s >>>>>> response %d <<<<<<\n", timeStampMilli(), counter))
				b.Write(buf)

				proxy.MITMDump.Write(b.Bytes())
				proxy.MITMDump.Sync()

				clientWriter = &dumpReadWriteWrapper{writer: tlsClient, counter: counter, file: proxy.MITMDump}
			}

			nr, err := proxy.Cipher.IO.Copy(clientWriter, resp.Body, rkeybuf, IOConfig{
				Mode:    FullCipher,
				Chunked: true,
				Role:    roleRecv,
			})
			if err != nil {
				proxy.Logger.Errorf("IO copy %d bytes: %v", nr, err)
			}

			tryClose(resp.Body)
		}

		tlsClient.Close()
	}()
}

func (proxy *ProxyClient) manInTheMiddleAgent(client net.Conn, host string) {
	_host, _ := splitHostPort(host)
	// try self signing a cert of this host
	cert := proxy.sign(_host)
	if cert == nil {
		return
	}

	client.Write(okHTTP)

	go func() {
		tlsClient := tls.Server(client, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{*cert},
		})

		if err := tlsClient.Handshake(); err != nil {
			proxy.Logger.Errorf("TLS handshake failed: %v", err)
			return
		}

		bufTLSClient := bufio.NewReader(tlsClient)

		for {
			proxy.Cipher.IO.markActive(tlsClient, 0)

			buf, err := bufTLSClient.Peek(3)
			if err == io.EOF || len(buf) != 3 {
				break
			}

			req, err := http.ReadRequest(bufTLSClient)
			if err != nil {
				if !isClosedConnErr(err) && buf[0] != ')' {
					proxy.Logger.Errorf("Can't read request from TLS conn: %v", err)
				}
				break
			}

			req.Header.Del("Proxy-Authorization")
			req.Header.Del("Proxy-Connection")

			if !isHTTPSSchema.MatchString(req.URL.String()) {
				// we can ignore 443 since it's by default
				h := req.Host
				if strings.HasSuffix(h, ":443") {
					h = h[:len(h)-4]
				}

				req.URL, err = url.Parse("https://" + h + req.URL.String())
			}

			if proxy.agentRoundTrip(tlsClient, req) != nil {
				break
			}
		}

		tlsClient.Close()
	}()
}

func (proxy *ProxyClient) agentRoundTrip(downstream net.Conn, req *http.Request) error {
	rURL := req.URL.Host
	req = proxy.agentRequest(req)
	resp, err := proxy.tpd.RoundTrip(req)

	if err != nil {
		proxy.Logger.Errorf("Round trip %s: %v", rURL, err)
		downstream.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n" + err.Error()))
		return err
	}

	nr, err := proxy.Cipher.IO.Copy(downstream, resp.Body, [ivLen]byte{}, IOConfig{
		Mode: FullCipher,
		Role: roleRecv,
	})
	if err != nil {
		proxy.Logger.Errorf("IO copy %d bytes: %v", nr, err)
	}

	tryClose(resp.Body)
	return nil
}

func (proxy *ProxyClient) agentUpstream() string {
	up, upport := splitHostPort(proxy.Upstream)
	if upport == ":443" {
		up = "https://" + up
	} else {
		up = "http://" + up
	}
	return up + "/index.php"
}

func (proxy *ProxyClient) agentRequest(req *http.Request) *http.Request {
	req.Header.Set("Connection", "close")
	buf, _ := httputil.DumpRequestOut(req, false)

	var rd io.Reader = bytes.NewReader(buf)
	if req.Body != nil {
		rd = io.MultiReader(rd, req.Body)
	}
	xreq, _ := http.NewRequest("GET", proxy.agentUpstream(), rd)

	host, hostport := req.URL.Host, "80"
	if req.URL.Scheme == "https" {
		host = "ssl://" + host
		hostport = "443"
	}

	if numport, err := strconv.Atoi(host[strings.LastIndex(host, ":")+1:]); err == nil {
		hostport = strconv.Itoa(numport)
	}

	xreq.Header.Add(fwdURLHeader, host+","+hostport)
	proxy.Logger.Dbgf("Agent - %s %s:%s", xreq.Method, host, hostport)
	return xreq
}
