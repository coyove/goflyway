package lib

import (
	"github.com/coyove/goflyway/pkg/lru"
	pp "github.com/coyove/goflyway/proxy"
	"strconv"

	"bytes"
	"fmt"
	"net/http"
	"strings"
	"text/template"
)

var webConsoleHTML, _ = template.New("console").Parse(`
    <html><title>{{.I18N.Title}}</title>
    <link rel='icon' type='image/png' href='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATAQMAAABInqSPAAAABlBMVEVjY2dnZnfjOvMHAAAAAXRSTlMCrui5SgAAACxJREFUCNdj+P//ARw/ePCA4f27BwwvgPjdOzAfVf4dUP7VA4aHryD0e1R5ANSVNLhGFgwkAAAAAElFTkSuQmCC'>

    <style>
        *                                   { font-family: Arial, Helvetica, sans-serif; font-size: 12px; }
        svg                                 { height: 80px; width: 80px; background: #676677; fill: #fff; }
        table#panel                         { border-collapse: collapse; height: 80px; }
        table#panel td                      { padding-right: 4px; }
        table#dns                           { border-collapse: collapse; margin: 4px 0; }
        table#dns td, table#dns th          { border: solid 1px rgba(0,0,0,0.1); padding: 4px 8px; white-space: nowrap; width: 1px; }
        table#dns td.ip 	                { font-family: "Lucida Console", Monaco, monospace; }
        table#dns td.rule                   { text-align: center; }
        table#dns td.rule.Block 		    { background: red; color:white; }
        table#dns td.rule.Private 		    { background: #5D4037; color:white; }
        table#dns td.rule.MatchedPass 	    { background: #00796B; color:white; }
        table#dns td.rule.Pass 		        { background: #00796B; color:white; }
        table#dns td.rule.MatchedProxy      { background: #FBC02D; }
        table#dns td.rule.Proxy 		    { background: #FBC02D; }
        table#dns td.rule.IPv6 		        { background: #7B1FA2; color:white; }
        table#dns td.rule.Unknown 		    { background: #512DA8; color:white; }
        table#dns tr:nth-child(odd) 		{ background-color: #e3e4e5; }
    </style>

    <form method='POST'><table id=panel>
    <tr>
        <td rowspan=3>
        <svg viewBox="0 0 19 19"><path d="M3 3h13v13h-13v-5h5v1h-4v1h3v1h-3v2h7v-5h1v4h1v-3h1v3h1v-4h1v-3h-5v-4h1v3h3v-3h-4v-1h-3v1h-4v3h3v-1h-2v-1h3v3h-5v-5"/></svg>
        </td>
        <td colspan=2><h3 style='font-size: 14px; margin: 0.25em 0'>{{.I18N.Basic}}</h3></td>
    </tr>
    <tr>
        <td>{{.I18N.EnableGlobal}}:</td>
        <td><input type='submit' name='proxy' value='{{if .Global}}{{.I18N.GlobalOff}}{{else}}{{.I18N.GlobalOn}}{{end}}'/></td>
    </tr>
    <tr>
        <td>{{.I18N.ClearDNS}}:</td>
        <td><input type='submit' name='cleardns' value='{{.I18N.Clear}}'/></td>
    </tr>
    </table></form>

    <script>
    function search(e) {
        try {
            var v = e.value.toLowerCase(), special = ["@block", "@private", "@m-pass", "@pass", "@m-proxy", "@proxy", "@ipv6", "@unknown"].indexOf(v) > -1;
            var items = document.getElementById("dns").querySelectorAll(".item"), re = new RegExp(v || ".*");
            for (var i = 0; i < items.length; i++)
                if (special)
                    items[i].style.display = ("@" + items[i].childNodes[items[i].childNodes.length-1].innerHTML.toLowerCase()) == v ? "" : "none";
                else
                    items[i].style.display = items[i].childNodes[0].innerHTML.match(re) ? "" : "none";
        } catch (ex) {}
    }
    </script>

    <input onkeyup="search(this)" style="min-width: 100px" placeholder="{{.I18N.Filter}}"/>
    <table id=dns>
        <tr><th>{{.I18N.Host}} ({{.Entries}}, {{.EntriesRatio}}%)</th><th>IP</th>
        <th>{{.I18N.Hits}}</th><th>{{.I18N.CertCache}}</th><th>{{.I18N.Rule}}</th></tr>
        {{.DNS}}
    </table>
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
		"GlobalOn":     "Enable",
		"GlobalOff":    "Disable",
		"Age":          "Age",
		"Filter":       "Filter string",
		"DNSCache":     "DNS Cache",
		"CertCache":    "Cert Cache",
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
		"Filter":       "过滤",
		"DNSCache":     "DNS缓存",
		"CertCache":    "证书缓存",
		"Rule":         "规则",
	},
}

var ruleMapping = []string{
	"<td class='rule Block'>Block</td>",
	"<td class='rule Private'>Private</td>",
	"<td class='rule MatchedPass'>M-Pass</td>",
	"<td class='rule Pass'>Pass</td>",
	"<td class='rule MatchedProxy'>M-Proxy</td>",
	"<td class='rule Proxy'>Proxy</td>",
	"<td class='rule IPv6'>IPv6</td>",
	"<td class='rule Unknown'>Unknown</td>",
}

func WebConsoleHTTPHandler(proxy *pp.ProxyClient) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			payload := struct {
				Global       bool
				Entries      int
				EntriesRatio int
				DNS          string
				I18N         map[string]string
			}{}

			buf, count := &bytes.Buffer{}, 0

			proxy.DNSCache.Info(func(k lru.Key, v interface{}, h int64) {
				count++
				cert := "-"
				if _, ok := proxy.CACache.Get(k); ok {
					hits, _ := proxy.CACache.GetHits(k)
					cert = strconv.Itoa(int(hits))
				}

				buf.WriteString(fmt.Sprintf("<tr class=item><td>%v</td><td class=ip>%v</td><td align=right>%d</td><td align=right>%s</td>%s</tr>",
					k, v.(*pp.Rule).IP, h, cert, ruleMapping[v.(*pp.Rule).R]))
			})

			if count == 0 {
				buf.WriteString("<tr><td>-</td><td>-</td><td align=right>-</td><td align=right>-</td><td>-</td></tr>")
			}

			payload.DNS = buf.String()
			payload.Global = proxy.Policy.IsSet(pp.PolicyGlobal)
			payload.Entries = count
			payload.EntriesRatio = count * 100 / proxy.DNSCache.MaxEntries

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
