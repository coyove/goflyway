package proxy

import (
	"github.com/coyove/goflyway/pkg/lru"

	"fmt"
	"net/http"
	"text/template"
)

var webConsoleHTML, _ = template.New("console").Parse(`
	<style>
		* { font-family: Arial, Helvetica, sans-serif }

		table {
			font-size: 12px;
			border-collapse: collapse;
			width: 100%;
			max-width: 100%;
		}

		td, th {
			border: solid 1px rgba(0, 0, 0, 0.1);
			padding: 4px 8px;
		}

		td.ip {
			font-family: "Lucida Console", Monaco, monospace;
		}

		tr:nth-child(odd) {
		   background-color: #e3e4e5;
		}

		#logo {
			float: left;
			padding: 8px;
			font-size: 60px;
		}

		#logo span {
			color: white;
			text-shadow: -1px -1px 0 #000, 1px -1px 0 #000, -1px 1px 0 #000, 1px 1px 0 #000;
		}

		#panel {
			float: right;
		}
	</style>

	<div id=logo>
		g<span>o</span>f<span>ly</span>w<span>ay</span> console
	</div>

	<form id=panel method='POST'>
		<input type='checkbox' disabled checked>Change key: <input name='key' value='{{.Key}}' style='border:none;padding:0;font:inherit;font-style:italic'/><br>
		<input type='checkbox' name='proxyall' {{if .ProxyAll}}checked{{end}}/><label>Proxy all traffic including Chinese websites</label><br>
		<input type='checkbox' name='proxyc' {{if .ProxyChina}}checked{{end}}/><label>Identify Chinese websites using china-list</label><br><br>
		<input type='submit' name='proxy' value='Update Settings'/>
		<input type='submit' name='clearc' value='Clear DNS Cache'/>
	</form>
`)

func handleWebConsole(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Write([]byte(`<html><title>goflyway web console</title>`))

		webConsoleHTML.Execute(w, struct {
			ProxyAll   bool
			ProxyChina bool
			Key        string
		}{
			GClientProxy.ProxyAllTraffic,
			GClientProxy.UseChinaList,
			GClientProxy.GCipher.KeyString,
		})

		w.Write([]byte(`<table><tr><th>Host</th><th>IP</th><th>Hits</th></tr>`))

		flag := false
		GClientProxy.DNSCache.Info(func(k lru.Key, v interface{}, h int64) {
			flag = true
			w.Write([]byte(fmt.Sprintf("<tr><td>%v</td><td class=ip>%v</td><td align=right>%d</td></tr>", k, v, h)))
		})

		if !flag {
			w.Write([]byte("<tr><td>n/a</td><td>n/a</td><td align=right>n/a</td></tr>"))
		}

		w.Write([]byte("</table></html>"))
	} else if r.Method == "POST" {
		if r.FormValue("clearc") != "" {
			GClientProxy.DNSCache.Clear()
		}

		if r.FormValue("proxy") != "" {
			GClientProxy.ProxyAllTraffic = r.FormValue("proxyall") == "on"
			GClientProxy.UseChinaList = r.FormValue("proxyc") == "on"
			GClientProxy.GCipher.KeyString = r.FormValue("key")
			GClientProxy.GCipher.New()
		}

		http.Redirect(w, r, "/?goflyway-console", 301)
	}
}
