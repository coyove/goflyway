package lib

import (
	"github.com/coyove/goflyway/pkg/lru"
	pp "github.com/coyove/goflyway/proxy"

	"bytes"
	"fmt"
	"net/http"
	"strings"
	"text/template"
)

var webConsoleHTML, _ = template.New("console").Parse(`
    <html><title>{{.I18N.Title}}</title>
    <link rel='icon' type='image/png' href='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4HsAAAAP1BMVEVHcEwLCw1mZXVnZ3ZnZXZnZXZmZndmZnpnZ3pmZndmZndmZnYTEhZoZHZnZ3dnZXdmZXZnZXU7O0VmZnVnZncczGBuAAAAFHRSTlMAG1AllNfJGQ2Ga+QuRzBxmmqTddMDS9kAAAC7SURBVHhe7dbbCsMgDIDh1GOiPW3z/Z91MMg0ZezCTmbB/zbw3bRGIZ3s18AABrB6mc4j7WXrR8CDDPMIQeabAQuVCUARt3wBKJUJwCSOWgP2XR1ggcOrAsm9etQCnPkToAynJHAY+U4Pk0aZL2yU6T5W2gAGUPEr74kjRF1xmOQ+aAYoU7QfgRhCiGduJgcAtjFwc1ysA3LhqsBmuXj6K/QHKKIbAGy1jyxRK2CepnuS5ZFs7m2lDWAAT8eKCjJEdYTQAAAAAElFTkSuQmCC'>

    <style>
        * { 
            font-family: Arial, Helvetica, sans-serif;
            font-size: 12px;
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
        
        table.dns td.rule span {
            display: block;
            margin: -4px -8px;
            height: 100%;
            width: 100%;
            padding: 4px 8px;
            text-align: center;
        }

        table.dns                           { border-collapse: collapse; margin: 4px 0; }
        table.dns td, table.dns th          { border: solid 1px rgba(0, 0, 0, 0.1); padding: 4px 8px; }
        table.dns td.ip, table.dns td.rule 	{ font-family: "Lucida Console", Monaco, monospace; }
        table.dns td.rule span.Block 		{ background: red; color:white; }
        table.dns td.rule span.Private 		{ background: #5D4037; color:white; }
        table.dns td.rule span.MatchedPass 	{ background: #00796B; color:white; }
        table.dns td.rule span.Pass 		{ background: #00796B; color:white; }
        table.dns td.rule span.MatchedProxy { background: #FBC02D; }
        table.dns td.rule span.Proxy 		{ background: #FBC02D; }
        table.dns td.rule span.IPv6 		{ background: #7B1FA2; color:white; }
        table.dns td.rule span.Unknown 		{ background: #512DA8; color:white; }
        table.dns tr:nth-child(odd) 		{ background-color: #e3e4e5; }
        
        #panel 			{ float: left; margin-left: 8px; }
        span.r 			{ display: inline-block; margin-right: 6px; line-height: 20px; }
        span.r + input 	{ float: right; }
        
        .folder { width: 100%; max-width: 100%; clear: both; margin: 4px 0; }
        .folder button[fold=true]::before   { content: '+ '; font-family: monospace; }
        .folder button[fold=true] + *       { display: none; }
        .folder button[fold=false]::before  { content: '- '; font-family: monospace; }
        .folder button[fold=false] + *      { display: block; }
    </style>
    
    <img id=logo src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATBAMAAACAfiv/AAAAD1BMVEVjY2dmZXZnZndnZnZnZnd4CqQOAAAABHRSTlMC/vz7NKZ17gAAAEtJREFUeF5jcIEBBxSmo6AgGAOZAgxgDGYCRQREBMBMIAYyIKIGLgKKCihq8ZoLhDC1jhATFEVcBAQEIKIsMKYAUIuAAoyJ11wEEwAgDCYCrylKywAAAABJRU5ErkJggg==">

    <form id=panel method='POST'>
    <table>
        <tr><td><h3 style='font-size: 14px; margin: 0.25em 0'>{{.I18N.Basic}}</h3></td></tr>
        <tr><td><span class=r>{{.I18N.EnableGlobal}}:</span>
        <input type='submit' name='proxy' value='{{if .ProxyAll}}{{.I18N.GlobalOff}}{{else}}{{.I18N.GlobalOn}}{{end}}'/></td></tr>
        <tr><td><span class=r>{{.I18N.ClearDNS}}:</span>
        <input type='submit' name='cleardns' value='{{.I18N.Clear}}'/></td></tr>
    </table>
    </form>

    <script>
        var width = window.innerWidth || document.documentElement.clientWidth || document.body.clientWidth;
        if (width > 600) {
            var el = document.getElementById("logo");
            el.style.display = "block";
            el.style.width = el.style.height = document.getElementById("panel").clientHeight + "px";
        }
        function unfold(el) { el.setAttribute("fold", el.getAttribute("fold") === "false" ? "true" : "false"); }
    </script>

    <div class=folder><button onclick=unfold(this) fold=false>{{.I18N.DNSCache}}</button><table class=dns>
        <tr><th>{{.I18N.Host}}</th><th>IP</th><th>{{.I18N.Hits}}</th><th>{{.I18N.Rule}}</th></tr>
        {{.DNS}}
    </table></div>

    <div class=folder><button onclick=unfold(this) fold=true>{{.I18N.CertCache}}</button><table class=dns>
        <tr><th>{{.I18N.HostCert}}</th><th>{{.I18N.Hits}}</th></tr>
        {{.Cert}}
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
		"ClearDNS":     "Clear local DNS cache",
		"EnableGlobal": "Enable/Disable global proxy",
		"Host":         "Host",
		"HostCert":     "Certificate",
		"Hits":         "Hits",
		"Clear":        "Clear",
		"GlobalOn":     "Turn On",
		"GlobalOff":    "Turn Off",
		"Age":          "Age",
		"UDPRelay":     "UDP Relay",
		"DNSCache":     "DNS Cache",
		"CertCache":    "Certificates Cache",
		"UDPCache":     "UDP-TCP Cache",
		"Rule":         "Rule",
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
		"ClearDNS":     "清除本地DNS缓存",
		"EnableGlobal": "切换全局代理模式",
		"Host":         "域名",
		"HostCert":     "证书",
		"Hits":         "访问次数",
		"Clear":        "清除",
		"GlobalOn":     "开启全局",
		"GlobalOff":    "关闭全局",
		"Age":          "生存时间",
		"UDPRelay":     "UDP Relay",
		"DNSCache":     "DNS缓存",
		"CertCache":    "证书缓存",
		"UDPCache":     "UDP-TCP缓存",
		"Rule":         "规则",
	},
}

var ruleMapping = []string{
	"<span class=Block>Block</span>",
	"<span class=Private>Private</span>",
	"<span class=MatchedPass>M-Pass</span>",
	"<span class=Pass>Pass</span>",
	"<span class=MatchedProxy>M-Proxy</span>",
	"<span class=Proxy>Proxy</span>",
	"<span class=IPv6>IPv6</span>",
	"<span class=Unknown>Unknown</span>",
}

func WebConsoleHTTPHandler(proxy *pp.ProxyClient) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			payload := struct {
				ProxyAll bool
				DNS      string
				Cert     string
				I18N     map[string]string
			}{}
			flag := false
			buf := &bytes.Buffer{}

			proxy.DNSCache.Info(func(k lru.Key, v interface{}, h int64) {
				flag = true
				buf.WriteString(fmt.Sprintf("<tr><td>%v</td><td class=ip>%v</td><td align=right>%d</td><td class=rule>%s</td></tr>",
					k, v.(*pp.Rule).IP, h, ruleMapping[v.(*pp.Rule).R]))
			})
			if !flag {
				buf.WriteString("<tr><td>n/a</td><td>n/a</td><td>n/a</td><td align=right>n/a</td></tr>")
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

			payload.ProxyAll = proxy.Policy.IsSet(pp.PolicyGlobal)

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

			if r.FormValue("proxy") != "" {
				if proxy.Policy.IsSet(pp.PolicyGlobal) {
					proxy.Policy.UnSet(pp.PolicyGlobal)
				} else {
					proxy.Policy.Set(pp.PolicyGlobal)
				}
			}

			http.Redirect(w, r, "/", 301)
		}
	}
}
