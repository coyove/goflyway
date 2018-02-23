package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"

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

func (proxy *ProxyClient) manInTheMiddle(client net.Conn, host string) {
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
			logg.E("handshake failed: ", host, ", ", err)
			return
		}

		bufTLSClient := bufio.NewReader(tlsClient)
		var wsToken *[ivLen]byte

		for {
			proxy.Cipher.IO.markActive(tlsClient, 0)

			if wsToken != nil {
				frame, err := wsReadFrame(bufTLSClient)
				if err != nil && err != io.EOF {
					logg.E(err)
					break
				}
				logg.L("read frame ", len(frame))
				req, _ := http.NewRequest("GET", "http://abc.com", bytes.NewReader(frame))
				//TODO
				req.Header.Add("Token", base64.StdEncoding.EncodeToString(wsToken[:]))
				if _, _, err = proxy.encryptAndTransport(req); err != nil {
					logg.E(err)
					tlsClient.Write([]byte{0x88, 0}) // close frame
					break
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

			rURL = req.URL.String()
			req.Header.Del("Proxy-Authorization")
			req.Header.Del("Proxy-Connection")

			if !isHTTPSSchema.MatchString(req.URL.String()) {
				// we can ignore 443 since it's by default
				h := req.Host
				if strings.HasSuffix(h, ":443") {
					h = h[:len(h)-4]
				}

				req.URL, err = url.Parse("https://" + h + req.URL.String())
				rURL = req.URL.String()
			}

			logg.D(req.Method, "^ ", rURL)
			var respBuf buffer

			resp, rkeybuf, err := proxy.encryptAndTransport(req)
			if err != nil {
				logg.E("proxy pass: ", rURL, ", ", err)
				tlsClient.Write(respBuf.Writes("HTTP/1.1 500 Internal Server Error\r\n\r\n", err.Error()).Bytes())
				break
			}

			resp.Header.Del("Content-Length")
			resp.Header.Set("Transfer-Encoding", "chunked")

			if strings.ToLower(resp.Header.Get("Connection")) != "upgrade" {
				resp.Header.Set("Connection", "close")
				tlsClient.Write(respBuf.R().Writes("HTTP/1.1 ", resp.Status, "\r\n").Bytes())
			} else {
				// we don't support upgrade in mitm
				// tlsClient.Write(respBuf.R().Writes("HTTP/1.1 403 Forbidden\r\n\r\n").Bytes())
				wsToken = rkeybuf
				logg.D("token: ", base64.StdEncoding.EncodeToString(wsToken[:]))

				go func() {
					for {
						req, _ := http.NewRequest("GET", "http://abc.com", nil)
						//TODO
						req.Header.Add("Token", base64.StdEncoding.EncodeToString(wsToken[:]))
						if resp, iv, err := proxy.encryptAndTransport(req, doWSCallback); err != nil {
							logg.E(err)
							tlsClient.Write([]byte{0x88, 0}) // close frame
							break
						} else if nr, err := proxy.Cipher.IO.Copy(tlsClient, resp.Body, iv, IOConfig{
							Partial: false,
							Role:    roleRecv,
						}); err != nil {
							logg.E("copy ", nr, " bytes: ", err)
							tlsClient.Write([]byte{0x88, 0})
							break
						} else {
							tryClose(resp.Body)
						}

						time.Sleep(time.Second)
					}
				}()
			}

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

			nr, err := proxy.Cipher.IO.Copy(tlsClient, resp.Body, rkeybuf, IOConfig{
				Partial: false,
				Chunked: true,
				Role:    roleRecv,
			})
			if err != nil {
				logg.E("copy ", nr, " bytes: ", err)
			}
			tryClose(resp.Body)
		}

		tlsClient.Close()
	}()
}

func wsReadFrame(src io.Reader) (payload []byte, err error) {
	buf := make([]byte, 4, 10)
	if _, err = io.ReadAtLeast(src, buf, 4); err != nil {
		return
	}

	ln := int(buf[1] & 0x7f)
	switch ln {
	case 127:
		buf = append(buf, 0, 0, 0, 0, 0, 0)
		if _, err = io.ReadAtLeast(src, buf[4:], 6); err != nil {
			return
		}
		ln = int(binary.BigEndian.Uint64(buf[2:10]))
	case 126:
		ln = int(binary.BigEndian.Uint16(buf[2:4]))
	default:
		// <= 125 bytes
	}

	payload = make([]byte, ln)
	_, err = io.ReadAtLeast(src, payload, ln)
	payload = append(buf, payload...)
	return
}
