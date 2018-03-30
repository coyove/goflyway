package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http/httputil"
	"sync/atomic"

	"github.com/coyove/goflyway/pkg/logg"

	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
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

	logg.D("self signing: ", host)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logg.E(err)
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
		logg.E("create certificate: ", err)
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
			logg.E("handshake failed: ", host, ", ", err)
			return
		}

		bufTLSClient := bufio.NewReader(tlsClient)

		var wsToken string
		var wsCallQueue *bytes.Buffer
		var wsLastSend int64

		for {
			proxy.Cipher.IO.markActive(tlsClient, 0)

			if wsToken != "" {
				tlsClient.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				frame, err := wsReadFrame(tlsClient)
				tlsClient.SetReadDeadline(time.Time{})

				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						// Since we are (almostly) reading from a local connection,
						// a timeout doesn't 100% mean we lost the client, we will keep
						// trying until other errors occurred.
						continue
					} else {
						if !isClosedConnErr(err) {
							logg.E(err)
						}
						break
					}
				}

				wsCallQueue.Write(frame)
				if time.Now().UnixNano()-wsLastSend > 1e9 && wsCallQueue.Len() > 0 {
					req, _ := http.NewRequest("GET", "http://"+proxy.Upstream, wsCallQueue)
					cr := proxy.newRequest()
					cr.Opt.Set(doForward)
					cr.WSCallback = 'c'
					cr.WSToken = wsToken
					proxy.encryptRequest(req, cr)
					if _, err = proxy.tp.RoundTrip(req); err != nil {
						logg.E(err)
						tlsClient.Write([]byte{0x88, 0}) // close frame
						break
					}

					wsCallQueue.Reset()
					wsLastSend = time.Now().UnixNano()
				}

				continue
			}

			var err error
			var rURL string
			var buf []byte
			if buf, err = bufTLSClient.Peek(3); err == io.EOF || len(buf) != 3 {
				break
			}

			req, err := http.ReadRequest(bufTLSClient)
			if err != nil {
				if !isClosedConnErr(err) && buf[0] != ')' {
					logg.E("cannot read request: ", err)
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

			logg.D(req.Method, "^ ", rURL)

			var respBuf buffer
			cr := proxy.newRequest()
			cr.Opt.Set(doForward)
			rkeybuf := proxy.encryptRequest(req, cr)

			if proxy.MITMDump != nil {
				req.Body = proxy.Cipher.IO.NewReadCloser(&dumpReadWriteWrapper{
					reader:  req.Body.(*IOReadCloserCipher).src,
					counter: counter,
					file:    proxy.MITMDump,
				}, rkeybuf)
			}

			resp, err := proxy.tp.RoundTrip(req)

			if err != nil {
				logg.E("proxy pass: ", rURL, ", ", err)
				tlsClient.Write(respBuf.Writes("HTTP/1.1 500 Internal Server Error\r\n\r\n", err.Error()).Bytes())
				break
			}

			resp.Header.Del("Content-Length")
			resp.Header.Set("Transfer-Encoding", "chunked")

			if strings.ToLower(resp.Header.Get("Connection")) != "upgrade" {
				resp.Header.Set("Connection", "close")
			} else if proxy.Policy.IsSet(PolicyWSCB) {
				wsToken = base64.StdEncoding.EncodeToString(rkeybuf[:])
				wsCallQueue = &bytes.Buffer{}
				wsLastSend = time.Now().UnixNano()

				go func() {
					// Now let's start a goroutine which will query the upstream in every 1 second
					// to see if there are any new WS frames sent from the host.
					// If yes, it sends frames back to the browser, if upstream returns code other than 200, it exits
					logg.D("WebSocket remote callback new token: ", wsToken)
					for {
						req, _ := http.NewRequest("GET", "http://"+proxy.Upstream, nil)
						cr := proxy.newRequest()
						cr.Opt.Set(doForward)
						cr.WSCallback = 'b'
						cr.WSToken = wsToken

						iv := proxy.encryptRequest(req, cr)
						resp, err := proxy.tp.RoundTrip(req)
						if err != nil {
							logg.E(err)
							break
						} else if resp.StatusCode != 200 {
							logg.L("remote callback exited with code: ", resp.StatusCode)
							break
						} else if _, err := proxy.Cipher.IO.Copy(tlsClient, resp.Body, iv, IOConfig{Role: roleRecv}); err != nil {
							if !isClosedConnErr(err) {
								logg.E(err)
							}
							break
						} else {
							tryClose(resp.Body)
						}

						time.Sleep(time.Second)
					}

					tlsClient.Write([]byte{0x88, 0})
					tlsClient.Close()
					logg.D("WebSocket remote callback finished: ", wsToken)
				}()
			} else {
				tlsClient.Write(respBuf.R().Writes("HTTP/1.1 403 Forbidden\r\n\r\n").Bytes())
				break
			}

			tlsClient.Write(respBuf.R().Writes("HTTP/1.1 ", resp.Status, "\r\n").Bytes())

			hdr := http.Header{}
			copyHeaders(hdr, resp.Header, proxy.Cipher, false, rkeybuf)
			if err := hdr.Write(tlsClient); err != nil {
				logg.W("write header: ", err)
				break
			}
			if _, err = io.WriteString(tlsClient, "\r\n"); err != nil {
				logg.W("write header: ", err)
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

			if wsToken == "" {
				// Chunked encoding will ruin the handshake of WS
				nr, err := proxy.Cipher.IO.Copy(clientWriter, resp.Body, rkeybuf, IOConfig{
					Partial: false,
					Chunked: true,
					Role:    roleRecv,
				})
				if err != nil {
					logg.E("copy ", nr, " bytes: ", err)
				}
			}

			tryClose(resp.Body)
		}

		tlsClient.Close()
	}()
}

func wsReadFrame(src io.Reader) (payload []byte, err error) {
	buf := make([]byte, 10)
	buflen := 2
	if _, err = io.ReadAtLeast(src, buf[:2], 2); err != nil {
		return
	}

	ln := int(buf[1] & 0x7f)
	switch ln {
	case 127:
		if _, err = io.ReadAtLeast(src, buf[2:10], 8); err != nil {
			return
		}
		ln = int(binary.BigEndian.Uint64(buf[2:10]))
		buflen = 10
	case 126:
		if _, err = io.ReadAtLeast(src, buf[2:4], 2); err != nil {
			return
		}
		ln = int(binary.BigEndian.Uint16(buf[2:4]))
		buflen = 4
	default:
		// <= 125 bytes
	}

	if (buf[1] & 0x80) > 0 {
		ln += 4
	}

	payload = make([]byte, buflen+ln)
	copy(payload[:buflen], buf[:buflen])
	_, err = io.ReadAtLeast(src, payload[buflen:], ln)
	return
}
