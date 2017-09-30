package proxy

import (
	"github.com/coyove/goflyway/pkg/lru"

	"encoding/base64"
	"fmt"
	"net/http"
	"text/template"
	"time"
)

var webConsoleHTML, _ = template.New("console").Parse(`
	<style>
		* { 
			font-family: Arial, Helvetica, sans-serif;
			font-size: 12px;
		}

		table.dns {
			font-size: 12px;
			border-collapse: collapse;
			width: 100%;
			max-width: 100%;
		}

		table.dns td, table.dns th {
			border: solid 1px rgba(0, 0, 0, 0.1);
			padding: 4px 8px;
		}

		table.dns td.ip {
			font-family: "Lucida Console", Monaco, monospace;
		}

		table.dns tr:nth-child(odd) {
		   background-color: #e3e4e5;
		}

		.i {
			width: 100%;
		}

		span.r {
			display: inline-block;
			margin-right: 6px;
			line-height: 20px;
		}

		span.r + input {
			float: right;
		}

		h3 {
			font-size: 14px;
			margin: 0.25em 0 0.2em;
		}
	</style>

	<form id=panel method='POST'>
	<table>
		<tr><td colspan=2><h3>Basic</h3></td></tr>
		<tr><td>Key:</td><td><input class=i name='key' value='{{.Key}}'/></td></tr>
		<tr><td>Auth:</td><td><input class=i name='auth' value='{{.Auth}}' placeholder='<empty>'/></td></tr>
		<tr><td colspan=2><input type='checkbox' name='proxyall' {{if .ProxyAll}}checked{{end}}/><label>Global proxy</label></td></tr>
		<tr><td colspan=2><input type='submit' name='proxy' value='Update'/></td></tr>
		<tr><td colspan=2><h3>Misc</h3></td></tr>
		<tr><td colspan=2><span class=r>Clear goflyway's local DNS cache:</span><input type='submit' name='clearc' value='Clear'/></td></tr>
		<tr><td colspan=2><span class=r>If you got blacklisted by the server, try:</span><input type='submit' name='unlock' value='Unlock Me'></td></tr>
	</table>
	</form>
`)

func handleWebConsole(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Write([]byte(`<html><title>goflyway web console</title>`))

		webConsoleHTML.Execute(w, struct {
			ProxyAll bool
			Key      string
			Auth     string
		}{
			GClientProxy.GlobalProxy,
			GClientProxy.GCipher.KeyString,
			GClientProxy.UserAuth,
		})

		w.Write([]byte(`<table class=dns><tr><th>Host</th><th>IP</th><th>Hits</th></tr>`))

		flag := false
		GClientProxy.dnsCache.Info(func(k lru.Key, v interface{}, h int64) {
			flag = true
			w.Write([]byte(fmt.Sprintf("<tr><td>%v</td><td class=ip>%v</td><td align=right>%d</td></tr>", k, v, h)))
		})

		if !flag {
			w.Write([]byte("<tr><td>n/a</td><td>n/a</td><td align=right>n/a</td></tr>"))
		}

		w.Write([]byte("</table></html>"))
	} else if r.Method == "POST" {
		if r.FormValue("clearc") != "" {
			GClientProxy.dnsCache.Clear()
		}

		if r.FormValue("proxy") != "" {
			GClientProxy.GlobalProxy = r.FormValue("proxyall") == "on"
			GClientProxy.GCipher.KeyString = r.FormValue("key")
			GClientProxy.UserAuth = r.FormValue("auth")
			GClientProxy.GCipher.New()
		}

		if r.FormValue("unlock") != "" {
			upConn := GClientProxy.dialUpstream()
			if upConn != nil {
				token := base64.StdEncoding.EncodeToString(GClientProxy.Encrypt(genTrustedToken("unlock", GClientProxy.GCipher)))

				upConn.SetWriteDeadline(time.Now().Add(time.Second))
				upConn.Write([]byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: www.baidu.com\r\n%s: %s\r\n\r\n", GClientProxy.rkeyHeader, token)))
				upConn.Close()
			}
		}

		http.Redirect(w, r, "/?goflyway-console", 301)
	}
}
