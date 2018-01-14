package lib

import (
	"strconv"

	"github.com/coyove/goflyway/pkg/aclrouter"

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
    <link rel='icon' type='image/png' href='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATAQMAAABInqSPAAAABlBMVEVjY2dnZnfjOvMHAAAAAXRSTlMCrui5SgAAACxJREFUCNdj+P//ARw/ePCA4f27BwwvgPjdOzAfVf4dUP7VA4aHryD0e1R5ANSVNLhGFgwkAAAAAElFTkSuQmCC'>

    <style>
        *                                   { font-family: Arial, Helvetica, sans-serif; font-size: 12px; box-sizing: border-box; }
        svg                                 { height: 80px; width: 80px; background: #676677; fill: #fff; }
        table#panel                         { border-collapse: collapse; height: 80px; }
        table#panel td                      { padding-right: 4px; }
        table#dns                           { border-collapse: collapse; margin: 4px 0; }
		table#dns td, table#dns th          { border: solid 1px rgba(0,0,0,0.1); padding: 4px 8px; }
		table#dns td.fit, table#dns th.fit  { white-space: nowrap; width: 1px; }
		table#dns td.ip, table#dns td.ip *  { font-family: "Lucida Console", Monaco, monospace; }
		table#dns td.ip a 	                { text-decoration: none; color: black; }
		table#dns td.ip a:hover             { text-decoration: underline; }
        table#dns td.rule                   { text-align: center; padding: 0; }
        table#dns td.rule.Block 		    { background: #F44336; color:white; }
        table#dns td.rule.Private 		    { background: #5D4037; color:white; }
        table#dns td.rule.MatchedPass 	    { background: #00796B; color:white; }
        table#dns td.rule.Pass 		        { background: #00796B; color:white; }
        table#dns td.rule.MatchedProxy      { background: #FBC02D; }
        table#dns td.rule.Proxy 		    { background: #FBC02D; }
        table#dns td.rule.IPv6 		        { background: #7B1FA2; color:white; }
		table#dns td.rule.Unknown 		    { background: #512DA8; color:white; }
		table#dns td.side-rule     		    { width: 5px; min-width: 5px; max-width: 5px; padding: 0; cursor: pointer }
		table#dns td.side-rule.Pass		    { background: #0EAB99; }
		table#dns td.side-rule.Proxy	    { background: #FDD97F; }
		table#dns td.side-rule.Block	    { background: #EB918A; }
		table#dns td.side-rule.Pass:hover   { background: #00796B; }
		table#dns td.side-rule.Proxy:hover  { background: #FBC02D; }
		table#dns td.side-rule.Block:hover  { background: #F44336; }
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
                    items[i].style.display = ("@" + items[i].querySelector("td.rule").innerHTML.toLowerCase()) == v ? "" : "none";
                else
                    items[i].style.display = items[i].childNodes[0].innerHTML.match(re) ? "" : "none";
        } catch (ex) {}
	}
	
	function update(el) {
		var rule = el.className.replace("r side-rule ", ""),
			tdr = el.parentNode.querySelectorAll("td.r"),
			http = new XMLHttpRequest();
		http.open("POST", "", true);
		http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
		http.onreadystatechange = function() {
			if (["Proxy", "Pass", "Block"].indexOf(http.responseText) == -1) return;
			var setter = function(e,c,o,h) { e.setAttribute("colspan", c); e.setAttribute("onclick", o); e.innerHTML = h;}
			for (var i = 0 ; i < 3; i++) {
				tdr[i].className = "r side-rule " + ["Proxy", "Pass", "Block"][i];
				setter(tdr[i], "1", "update(this)", "");
			}
			el.className = el.className.replace("side-", "");
			setter(el, "11", "", rule);
			el.parentNode.querySelector(".old").innerHTML = http.responseText;
		}
		http.send("target=" + el.parentNode.childNodes[0].innerHTML + "&update=" + rule);
	}
    </script>

    <input onkeyup="search(this)" style="min-width: 100px" placeholder="{{.I18N.Filter}}"/>
    <table id=dns>
		<tr>
			<th class=fit>{{.I18N.Host}} ({{.Entries}}, {{.EntriesRatio}}%)</th>
			<th class=fit>IP</th>
			<th class=fit>{{.I18N.OldRule}}</th>
			<th class=fit>{{.I18N.Hits}}</th>
			<th class=fit>{{.I18N.CertCache}}</th>
			<th colspan=13 class=fit>{{.I18N.Rule}}</th>
		</tr>
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
		"OldRule":      "Old Rule",
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
		"OldRule":      "旧规则",
	},
}

var ruleMappingLeft = []string{
	"<td onclick=update(this) class='r side-rule Proxy'></td>",
	"",
	"<td onclick=update(this) class='r side-rule Proxy'></td>",
	"<td onclick=update(this) class='r side-rule Proxy'></td>",
	"<td colspan=11 class='r rule MatchedProxy'>M-Proxy</td>",
	"<td colspan=11 class='r rule Proxy'>Proxy</td>",
	"<td colspan=11 class='r rule IPv6'>IPv6</td>",
	"<td colspan=11 class='r rule Unknown'>Unknown</td>",
}

var ruleMapping = []string{
	"<td onclick=update(this) class='r side-rule Pass'></td>",
	"<td colspan=13 class='r rule Private'>Private</td>",
	"<td colspan=11 class='r rule MatchedPass'>M-Pass</td>",
	"<td colspan=11 class='r rule Pass'>Pass</td>",
	"<td onclick=update(this) class='r side-rule Pass'></td>",
	"<td onclick=update(this) class='r side-rule Pass'></td>",
	"<td onclick=update(this) class='r side-rule Pass'></td>",
	"<td onclick=update(this) class='r side-rule Pass'></td>",
}

var ruleMappingRight = []string{
	"<td colspan=11 class='r rule Block'>Block</td>",
	"",
	"<td onclick=update(this) class='r side-rule Block'></td>",
	"<td onclick=update(this) class='r side-rule Block'></td>",
	"<td onclick=update(this) class='r side-rule Block'></td>",
	"<td onclick=update(this) class='r side-rule Block'></td>",
	"<td onclick=update(this) class='r side-rule Block'></td>",
	"<td onclick=update(this) class='r side-rule Block'></td>",
}

func toString(ans byte) string {
	return []string{"Proxy", "Pass", "Block"}[ans]
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
				cert, old := "-", "-"
				rule := v.(*pp.Rule)
				ip, r := rule.IP, rule.R

				if rule.Ans != rule.OldAns {
					old = toString(rule.OldAns)
				}

				if aclrouter.IPv4ToInt(ip) > 0 {
					ip = fmt.Sprintf("<a href='http://freeapi.ipip.net/%v' target=_blank>%v</a>", ip, ip)
				}

				if _, ok := proxy.CACache.Get(k); ok {
					hits, _ := proxy.CACache.GetHits(k)
					cert = strconv.Itoa(int(hits))
				}

				buf.WriteString(fmt.Sprintf(`<tr class=item><td class=fit>%v</td>
					<td class="fit ip">%s</td>
					<td class="fit old">%s</td>
					<td class=fit align=right>%d</td>
					<td class=fit align=right>%s</td>
					%s%s%s
					</tr>`,
					k, ip, old, h, cert, ruleMappingLeft[r], ruleMapping[r], ruleMappingRight[r]))
			})

			if count == 0 {
				buf.WriteString("<tr><td>-</td><td>-</td><td align=right>-</td><td align=right>-</td><td colspan=13>-</td></tr>")
			}
			buf.WriteString(fmt.Sprintf("<tr style=visibility:hidden><td></td><td></td><td></td><td></td><td></td>%s</tr>", strings.Repeat("<td class=side-rule></td>", 13)))

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

			if rule := r.FormValue("update"); rule != "" {
				target := r.FormValue("target")
				if v, ok := proxy.DNSCache.Get(target); ok {
					oldRule := v.(*pp.Rule)
					old := oldRule.OldAns
					switch rule {
					case "Proxy":
						oldRule.Ans = 0
						oldRule.R = aclrouter.RuleProxy
					case "Pass":
						oldRule.Ans = 1
						oldRule.R = aclrouter.RulePass
					case "Block":
						oldRule.Ans = 2
						oldRule.R = aclrouter.RuleBlock
					}
					proxy.DNSCache.Add(target, oldRule)
					w.Write([]byte(toString(old)))
				} else {
					w.Write([]byte("error"))
				}
				return
			}

			http.Redirect(w, r, "/", 301)
		}
	}
}
