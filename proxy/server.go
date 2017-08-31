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
	if r.Method == "GET" && r.Header.Get("X-Host-Lookup") != "" {
		if Skip32DecodeString(G_KeyBytes, r.Header.Get(dnsHeaderID)) == *G_Key {
			w.Write([]byte(lookup.LookupIP(r.Header.Get(dnsHeader))))
			return
		}
	}

	if r.Method == "CONNECT" {
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
		host := DecryptHost(r.Header.Get("X-Forwarded-Host"))
		rkey := r.Header.Get(rkeyHeader)

		targetSiteConn, err := net.Dial("tcp", host)
		if err != nil {
			logg.E("[HOST] - ", err)
			return
		}

		// response HTTP 200 OK to downstream, and it will not be xored in IOCopyCipher
		downstreamConn.Write(OK200)
		TwoWayBridge(targetSiteConn, downstreamConn, rkey)
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

		if *G_UnsafeHttp {
			rkey = ""
		}

		nr, err := (&IOCopyCipher{Dst: w, Src: resp.Body, Key: ReverseRandomKey(rkey)}).DoCopy()
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
