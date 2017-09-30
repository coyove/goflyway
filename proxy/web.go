package proxy

import (
	"github.com/coyove/goflyway/pkg/lru"

	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"text/template"
	"time"
)

var webConsoleHTML, _ = template.New("console").Parse(`
	<html><title>{{.I18N.Title}}</title>
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
			margin: 0.25em 0;
		}

		hr {
			border: dashed 1px #cacbcc;
		}
	</style>

	<form id=panel method='POST'>
	<table>
		<tr><td colspan=2><h3>{{.I18N.Basic}}</h3></td></tr>
		<tr><td>{{.I18N.Key}}:</td><td><input class=i name='key' value='{{.Key}}'/></td></tr>
		<tr><td>{{.I18N.Auth}}:</td><td><input class=i name='auth' value='{{.Auth}}' placeholder='<empty>'/></td></tr>
		<tr><td colspan=2><input type='checkbox' name='proxyall' {{if .ProxyAll}}checked{{end}}/><label>{{.I18N.Global}}</label></td></tr>
		<tr><td colspan=2><input type='submit' name='proxy' value='{{.I18N.Update}}'/></td></tr>
		<tr><td colspan=2><hr></td></tr>
		<tr><td colspan=2><h3>{{.I18N.Misc}}</h3></td></tr>
		<tr><td colspan=2><span class=r>{{.I18N.ClearDNS}}:</span><input type='submit' name='clearc' value='{{.I18N.Clear}}'/></td></tr>
		<tr><td colspan=2><span class=r>{{.I18N.UnlockMeText}}:</span><input type='submit' name='unlock' value='{{.I18N.UnlockMe}}'></td></tr>
	</table>
	</form>

	<table class=dns><tr><th>{{.I18N.Host}}</th><th>IP</th><th>{{.I18N.Hits}}</th></tr>
`)

var _i18n = map[string]map[string]string{
	"en": map[string]string{
		"Title":        "goflyway web console",
		"Basic":        "Basic",
		"Key":          "Key",
		"Auth":         "Auth",
		"Global":       "Global proxy",
		"Update":       "Update",
		"Misc":         "Misc",
		"ClearDNS":     "Clear goflyway's local DNS cache",
		"UnlockMeText": "If you got blacklisted by the server, try",
		"Host":         "Host",
		"Hits":         "Hits",
		"Clear":        "Clear",
		"UnlockMe":     "UnlockMe",
	},
	"zh": map[string]string{
		"Title":        "goflyway 控制台",
		"Basic":        "基本设置",
		"Key":          "密钥",
		"Auth":         "用户认证",
		"Global":       "全局代理",
		"Update":       "确定",
		"Misc":         "杂项",
		"ClearDNS":     "清除goflyway本地DNS缓存",
		"UnlockMeText": "如果您被服务器ban了，可以尝试",
		"Host":         "域名",
		"Hits":         "访问次数",
		"Clear":        "清除",
		"UnlockMe":     "解锁",
	},
}

func handleWebConsole(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		payload := struct {
			ProxyAll bool
			Key      string
			Auth     string
			I18N     map[string]string
		}{
			GClientProxy.GlobalProxy,
			GClientProxy.GCipher.KeyString,
			GClientProxy.UserAuth,
			nil,
		}

		if strings.Contains(r.Header.Get("Accept-Language"), "zh") && r.FormValue("en") != "1" { // use en=1 to force english display
			payload.I18N = _i18n["zh"]
		} else {
			payload.I18N = _i18n["en"]
		}

		webConsoleHTML.Execute(w, payload)

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
