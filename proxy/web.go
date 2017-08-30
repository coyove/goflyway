package proxy

import (
	. "../config"
	"../lru"

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
	</style>
	
	<form method='POST'>
		<input type='checkbox' name='proxyall' {{if .ProxyAll}}checked{{end}}/><label>Proxy all traffic including chinese websites</label><br>
		<input type='checkbox' name='proxyc' {{if .ProxyChina}}checked{{end}}/><label>Identify chinese websites using china-list</label><br>
		<input type='checkbox' name='nopa' {{if .NoPA}}checked{{end}}/><label>Disable proxy authentication</label><br><br>
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
			NoPA       bool
		}{
			*G_ProxyAll,
			*G_ProxyChina,
			*G_NoPA,
		})

		w.Write([]byte(`<table><tr><th>Host</th><th>IP</th><th>Hits</th></tr>`))

		flag := false
		G_Cache.Info(func(k lru.Key, v interface{}, h int64) {
			flag = true
			w.Write([]byte(fmt.Sprintf("<tr><td>%v</td><td class=ip>%v</td><td align=right>%d</td></tr>", k, v, h)))
		})

		if !flag {
			w.Write([]byte("<tr><td>n/a</td><td>n/a</td><td align=right>n/a</td></tr>"))
		}

		w.Write([]byte("</table></html>"))
	} else if r.Method == "POST" {
		if r.FormValue("clearc") != "" {
			G_Cache.Clear()
		}

		if r.FormValue("proxy") != "" {
			*G_ProxyAll = r.FormValue("proxyall") == "on"
			*G_ProxyChina = r.FormValue("proxyc") == "on"
			*G_NoPA = r.FormValue("nopa") == "on"
		}

		http.Redirect(w, r, "/?goflyway-console", 301)
	}
}
