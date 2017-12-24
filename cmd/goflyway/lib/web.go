package lib

import (
	"github.com/coyove/goflyway/pkg/lru"
	pp "github.com/coyove/goflyway/proxy"

	"bytes"
	"fmt"
	"net/http"
	"strings"
	"text/template"
	"time"
)

var webConsoleHTML, _ = template.New("console").Parse(`
    <html><title>{{.I18N.Title}}</title>
    <link rel='icon' type='image/png' href='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4HsAAAAP1BMVEVHcEwLCw1mZXVnZ3ZnZXZnZXZmZndmZnpnZ3pmZndmZndmZnYTEhZoZHZnZ3dnZXdmZXZnZXU7O0VmZnVnZncczGBuAAAAFHRSTlMAG1AllNfJGQ2Ga+QuRzBxmmqTddMDS9kAAAC7SURBVHhe7dbbCsMgDIDh1GOiPW3z/Z91MMg0ZezCTmbB/zbw3bRGIZ3s18AABrB6mc4j7WXrR8CDDPMIQeabAQuVCUARt3wBKJUJwCSOWgP2XR1ggcOrAsm9etQCnPkToAynJHAY+U4Pk0aZL2yU6T5W2gAGUPEr74kjRF1xmOQ+aAYoU7QfgRhCiGduJgcAtjFwc1ysA3LhqsBmuXj6K/QHKKIbAGy1jyxRK2CepnuS5ZFs7m2lDWAAT8eKCjJEdYTQAAAAAElFTkSuQmCC'>

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
			display: none;
			margin: 4px 0;
        }

        table.dns td, table.dns th {
            border: solid 1px rgba(0, 0, 0, 0.1);
            padding: 4px 8px;
        }

        table.dns td.ip {
            font-family: "Lucida Console", Monaco, monospace;
        }

		table.dns tr:first-child {
			cursor: pointer;
		}

        table.dns tr:nth-child(odd) {
           background-color: #e3e4e5;
        }

        .i {
            width: 100%;
        }

        #panel{
            float: left;
            margin-left: 8px;
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

        #logo {
            image-rendering: optimizeSpeed;
            image-rendering: -moz-crisp-edges;
            image-rendering: -o-crisp-edges;
            image-rendering: -webkit-optimize-contrast;
            image-rendering: pixelated;
            image-rendering: optimize-contrast;
            -ms-interpolation-mode: nearest-neighbor;
            display: none;
            float: left;
		}
		
		.folder {
			width: 100%;
			max-width: 100%;
			clear: both;
			margin: 4px 0;
		}

		.folder button[fold=false]::before {
			content: '+ ';
			font-family: monospace;
		}

		.folder button[fold=true]::before {
			content: '- ';
			font-family: monospace;
		}
	</style>
	
	<script>
	function unfold(el) {
		if (el.getAttribute("fold") === "false") {
			el.setAttribute("fold", "true");
			el.nextSibling.style.display = "block";
		} else {
			el.setAttribute("fold", "false");
			el.nextSibling.style.display = "none";
		}
	}
	</script>

    <img id=logo src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATBAMAAACAfiv/AAAAD1BMVEVjY2dmZXZnZndnZnZnZnd4CqQOAAAABHRSTlMC/vz7NKZ17gAAAEtJREFUeF5jcIEBBxSmo6AgGAOZAgxgDGYCRQREBMBMIAYyIKIGLgKKCihq8ZoLhDC1jhATFEVcBAQEIKIsMKYAUIuAAoyJ11wEEwAgDCYCrylKywAAAABJRU5ErkJggg==">

    <form id=panel method='POST'>
    <table>
        <tr><td colspan=2><h3>{{.I18N.Basic}}</h3></td></tr>
        <tr><td>{{.I18N.Key}}:</td><td><input class=i name='key' value='{{.Key}}'/></td></tr>
        <tr><td>{{.I18N.Auth}}:</td><td><input class=i name='auth' value='{{.Auth}}' placeholder='<empty>'/></td></tr>
        <tr><td colspan=2><input type='checkbox' name='gproxy' {{if .ProxyAll}}checked{{end}}/><label>{{.I18N.Global}}</label></td></tr>
        <tr><td colspan=2><input type='checkbox' name='mitm' {{if .MITM}}checked{{end}}/><label>{{.I18N.MITM}}</label></td></tr>
        <tr><td colspan=2><input type='submit' name='update' value='{{.I18N.Update}}'/></td></tr>
        <tr><td colspan=2><hr></td></tr>
        <tr><td colspan=2><h3>{{.I18N.Misc}}</h3></td></tr>
        <tr><td colspan=2><span class=r>{{.I18N.ClearDNS}}:</span><input type='submit' name='cleardns' value='{{.I18N.Clear}}'/></td></tr>
        <tr style='display:none'><td colspan=2><span class=r>{{.I18N.UnlockMeText}}:</span><input type='submit' name='unlock' value='{{.I18N.UnlockMe}}'></td></tr>
    </table>
    </form>

    <script>
    var width = window.innerWidth || document.documentElement.clientWidth || document.body.clientWidth;
    if (width > 600) {
        var el = document.getElementById("logo");
        el.style.display = "block";
        el.style.width = el.style.height = document.getElementById("panel").clientHeight + "px";
    }
    </script>

	<div class=folder><button onclick=unfold(this) fold=false>{{.I18N.DNSCache}}</button><table class=dns>
		<tr onclick=fold(this)><th>{{.I18N.Host}}</th><th>IP</th><th>{{.I18N.Hits}}</th></tr>
		{{.DNS}}
	</table></div>

	<div class=folder><button onclick=unfold(this) fold=false>{{.I18N.CertCache}}</button><table class=dns>
		<tr><th>{{.I18N.HostCert}}</th><th>{{.I18N.Hits}}</th></tr>
		{{.Cert}}
	</table></div>

	<div class=folder><button onclick=unfold(this) fold=false>{{.I18N.UDPCache}}</button><table class=dns>
		<tr><th>{{.I18N.UDPRelay}}</th><th>{{.I18N.Age}}</th><th>{{.I18N.Hits}}</th></tr>
		{{.UDP}}
	</table></div>
`)

var _i18n = map[string]map[string]string{
	"en": {
		"Title":        "goflyway web console",
		"Basic":        "Basic",
		"Key":          "Key",
		"Auth":         "Auth",
		"Global":       "Global proxy",
		"MITM":         "Man-in-the-middle proxy (HTTP only)",
		"Update":       "Update",
		"Misc":         "Misc",
		"ClearDNS":     "Clear goflyway's local DNS cache",
		"UnlockMeText": "If you got blacklisted by the server, try",
		"Host":         "Host",
		"HostCert":     "Certificate",
		"Hits":         "Hits",
		"Clear":        "Clear",
		"UnlockMe":     "UnlockMe",
		"Age":          "Age",
		"UDPRelay":     "UDP Relay",
		"DNSCache":     "DNS Cache",
		"CertCache":    "Certificates Cache",
		"UDPCache":     "UDP-TCP Cache",
	},
	"zh": {
		"Title":        "goflyway 控制台",
		"Basic":        "基本设置",
		"Key":          "密钥",
		"Auth":         "用户认证",
		"Global":       "全局代理",
		"MITM":         "中间人代理模式（仅限HTTP）",
		"Update":       "确定",
		"Misc":         "杂项",
		"ClearDNS":     "清除goflyway本地DNS缓存",
		"UnlockMeText": "如果您被服务器ban了，可以尝试",
		"Host":         "域名",
		"HostCert":     "证书",
		"Hits":         "访问次数",
		"Clear":        "清除",
		"UnlockMe":     "解锁",
		"Age":          "生存时间",
		"UDPRelay":     "UDP Relay",
		"DNSCache":     "DNS缓存",
		"CertCache":    "证书缓存",
		"UDPCache":     "UDP-TCP缓存",
	},
}

func WebConsoleHTTPHandler(proxy *pp.ProxyClient) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			payload := struct {
				ProxyAll bool
				MITM     bool
				Key      string
				Auth     string
				DNS      string
				UDP      string
				Cert     string
				I18N     map[string]string
			}{}
			flag := false
			buf := &bytes.Buffer{}

			proxy.DNSCache.Info(func(k lru.Key, v interface{}, h int64) {
				flag = true
				buf.WriteString(fmt.Sprintf("<tr><td>%v</td><td class=ip>%v</td><td align=right>%d</td></tr>", k, v, h))
			})
			if !flag {
				buf.WriteString("<tr><td>n/a</td><td>n/a</td><td align=right>n/a</td></tr>")
			}
			payload.DNS = buf.String()

			flag = false
			buf.Reset()
			proxy.CACache.Info(func(k lru.Key, v interface{}, h int64) {
				flag = true
				buf.WriteString(fmt.Sprintf("<tr><td>%v</td><td align=right>%d</td></tr>", k, h))
			})
			if !flag {
				buf.WriteString("<tr><td>n/a</td><td align=right>n/a</td></tr>")
			}
			payload.Cert = buf.String()

			buf.Reset()
			proxy.UDP.Lock()
			if len(proxy.UDP.Conns) == 0 {
				buf.WriteString("<tr><td>n/a</td><td>n/a</td><td align=right>n/a</td></tr>")
			} else {
				now := time.Now().UnixNano()
				for tok, t := range proxy.UDP.Conns {
					buf.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d ms</td><td align=right>%d</td></tr>",
						tok, (now-t.Born)/1e6, t.Hits))
				}
			}
			proxy.UDP.Unlock()
			payload.UDP = buf.String()

			payload.ProxyAll = proxy.Policy.IsSet(pp.PolicyGlobal)
			payload.MITM = proxy.Policy.IsSet(pp.PolicyManInTheMiddle)
			payload.Key = proxy.Cipher.KeyString
			payload.Auth = proxy.UserAuth

			// use lang=en to force english display
			if strings.Contains(r.Header.Get("Accept-Language"), "zh") && r.FormValue("lang") != "en" {
				payload.I18N = _i18n["zh"]
			} else {
				payload.I18N = _i18n["en"]
			}

			webConsoleHTML.Execute(w, payload)
		} else if r.Method == "POST" {
			if r.FormValue("cleardns") != "" {
				proxy.DNSCache.Clear()
			}

			if r.FormValue("update") != "" {
				if r.FormValue("gproxy") == "on" {
					proxy.Policy.Set(pp.PolicyGlobal)
				} else {
					proxy.Policy.UnSet(pp.PolicyGlobal)
				}

				if r.FormValue("mitm") == "on" {
					proxy.Policy.Set(pp.PolicyManInTheMiddle)
				} else {
					proxy.Policy.UnSet(pp.PolicyManInTheMiddle)
				}

				proxy.UserAuth = r.FormValue("auth")
				proxy.UpdateKey(r.FormValue("key"))
			}

			if r.FormValue("ping") != "" {
				w.WriteHeader(200)
				w.Write([]byte("pong"))
				return
			}

			http.Redirect(w, r, "/", 301)
		}
	}
}
