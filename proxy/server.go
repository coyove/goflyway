package proxy

import (
	. "../config"
	"../logg"
	"../lookup"

	"net"
	"net/http"
)

type ProxyUpstreamHttpServer struct {
	Tr *http.Transport
}

func (proxy *ProxyUpstreamHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if dh := r.Header.Get(dnsHeader); r.Method == "GET" && dh != "" {
		if x := DecryptHost(dh, '!'); x != "" {
			w.Write([]byte(lookup.LookupIP(x)))
			return
		}
	}

	if host, mark := TryDecryptHost(r.Host); mark == '*' || mark == '$' {
		// dig tunnel
		hij, ok := w.(http.Hijacker)
		if !ok {
			XorWrite(w, r, []byte("webserver doesn't support hijacking"), http.StatusInternalServerError)
			return
		}

		downstreamConn, _, err := hij.Hijack()
		if err != nil {
			XorWrite(w, r, []byte(err.Error()), http.StatusInternalServerError)
			return
		}

		// we are outside GFW and should pass data to the real target
		targetSiteConn, err := net.Dial("tcp", host)
		if err != nil {
			logg.E("[HOST] - ", err)
			return
		}

		// response HTTP 200 OK to downstream, and it will not be xored in IOCopyCipher
		if mark == '*' {
			downstreamConn.Write(OK_HTTP)
		} else {
			downstreamConn.Write(OK_SOCKS)
		}

		if *G_Throttling > 0 {
			TwoWayBridge(targetSiteConn, downstreamConn, r.Header.Get(rkeyHeader), DO_THROTTLING)
		} else {
			TwoWayBridge(targetSiteConn, downstreamConn, r.Header.Get(rkeyHeader), DO_NOTHING)
		}
	} else {
		// normal http requests
		if !r.URL.IsAbs() {
			XorWrite(w, r, []byte("abspath only"), http.StatusInternalServerError)
			return
		}

		// decrypt req from inside GFW
		rkey := DecryptRequest(r)

		r.Header.Del("Proxy-Authorization")
		r.Header.Del("Proxy-Connection")

		resp, err := proxy.Tr.RoundTrip(r)
		if err != nil {
			logg.E("[HTTP] - ", r.URL, " - ", err)
			XorWrite(w, r, []byte(err.Error()), http.StatusInternalServerError)
			return
		}

		origBody := resp.Body
		defer origBody.Close()

		if resp.StatusCode >= 400 {
			logg.L("[", resp.Status, "] - ", r.URL)
		}

		if origBody != resp.Body {
			resp.Header.Del("Content-Length")
		}

		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)

		iocc := getIOCipherSimple(w, resp.Body, rkey, *G_Throttling > 0)
		iocc.Partial = false // HTTP must be fully encrypted

		nr, err := iocc.DoCopy()
		tryClose(resp.Body)

		if err != nil {
			logg.E("[COPYS] ", err, " - bytes: ", nr)
		}
	}
}

func StartServer(addr string) {
	proxy := &ProxyUpstreamHttpServer{
		Tr: &http.Transport{TLSClientConfig: tlsSkip},
	}

	logg.L("listening on ", addr)
	logg.F(http.ListenAndServe(addr, proxy))
}
