package lib

import (
	"github.com/coyove/goflyway/pkg/aclrouter"

	"github.com/coyove/common/lru"
	pp "github.com/coyove/goflyway/proxy"

	"bytes"
	"fmt"
	"net/http"
	"strings"
	"text/template"
)

var webConsoleHTML, _ = template.New("console").Parse(`<!DOCTYPE html>
    <html><title>{{.I18N.Title}}</title>
    <link rel='icon' type='image/png' href='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFoAAABaAQMAAAACZtNBAAAABlBMVEVycYL///9g0YTYAAAANUlEQVQ4y2MYBMD+/x8Q8f//wHE+MP8HEQPFgbgERAwQZ1AAoEvgAUJ/zmBJiQwDwxk06QAA91Y8PCo+T/8AAAAASUVORK5CYII='>

    <style>
        * { font-family: Arial, Helvetica, sans-serif; box-sizing: border-box; font-size: 14px; }
		a {
			text-decoration: none;
		}
		#traffic {
			overflow: hidden; 
			height: 100px; 
			width: auto; 
			cursor: pointer; 
		}
		#dns { 
			margin: 4px auto; 
			width: 100%;
			white-space:pre-wrap; 
			line-height: 2em;
			font-family: monospace;
		}
	</style>

    <body>
    <a href="https://github.com/coyove/goflyway/wiki" target="_blank">
    <svg viewBox="0 0 9 9" width=100 height=100><path fill="#667" d="M0 5h4v1H3v1H2v1H1V5h5v1h1V5h1v3H5V2h1v1h1V2H2v1h1V2h1v2H1V1h2v1h2V1h3v3H5v1H0v4h9V0H0"/></svg>
    </a>

    <script>
    function post(data, callback) {
        var http = new XMLHttpRequest();
        http.open("POST", "", true);
        http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        http.onreadystatechange = function () { callback(http) };
        http.send(data);
    }
  
    function toggle(t) {
        post(t + "=" + t, function() { location.reload(); });
    }

	function rule(url, el) {
		post("update=" + el.innerHTML + "&target=" + url, function() { location.reload(); });
	}
    </script>

	<img id="traffic" src="" log=0 onclick="switchSVG(this)"/>
	<div style="padding: 4px 0">
		<button onclick="toggle('proxy')">{{if .Global}}{{.I18N.GlobalOff}}{{else}}{{.I18N.GlobalOn}}{{end}}</button>
        <button onclick="toggle('cleardns')">{{.I18N.ClearDNS}}</button>
	</div>
    <p id=dns>{{.DNS}}</p>

    <script>
    function switchSVG(el) {
        if (el) el.setAttribute("log", Math.abs(el.getAttribute("log") - 1));
        
        var log = document.getElementById('traffic').getAttribute("log") == 1;
        document.getElementById('traffic').src = "/stat?traffic=1&" + (log ? "log=1&c=" : "c=") + (new Date().getTime());
        document.cookie = "log=" + (log ? "1" : "0") + "; expires=Sat, 1 Jan 2050 00:00:00 GMT; path=/";
    }

    document.getElementById('traffic').setAttribute("log", (/log[^;]+/.exec(document.cookie)||"").toString() == "log=1" ? 1 : 0);
    switchSVG();
    setInterval(switchSVG, 5000);
    </script>
    </body>
`)

var _i18n = map[string]map[string]string{
	"en": {
		"Title":     "goflyway web console",
		"Basic":     "Basic",
		"ClearDNS":  "Clear rules cache",
		"Host":      "Host(s)",
		"Hits":      "Hits",
		"Clear":     "Clear",
		"Filter":    "Filter string",
		"Show":      "Show",
		"CertCache": "Cert Cache",
		"Rule":      "Rule",
		"OldRule":   "Old Rule",
		"GlobalOn":  "Enable global proxy",
		"GlobalOff": "Disable global proxy",
		"Reset":     "Reset changed rules",
	},
	"zh": {
		"Title":     "goflyway 控制台",
		"Basic":     "基本设置",
		"ClearDNS":  "清除规则缓存",
		"Host":      "域名",
		"Hits":      "访问次数",
		"Clear":     "清除",
		"Filter":    "过滤",
		"Show":      "显示",
		"CertCache": "证书缓存",
		"Rule":      "规则",
		"OldRule":   "旧规则",
		"GlobalOn":  "打开全局代理",
		"GlobalOff": "关闭全局代理",
		"Reset":     "重置规则",
	},
}

func internalRuletoString(ans byte) string {
	return "ProxyPass Block"[ans*5 : ans*5+5]
}

func aclRuletoString(ans byte) string {
	return "Block  PrivateMPass  Pass   MProxy Proxy  IPv6   Unknown"[ans*7 : ans*7+7]
}

func aclRuletoInternalRule(ans byte) byte {
	switch ans {
	case aclrouter.RuleBlock:
		return 2
	case aclrouter.RuleIPv6, aclrouter.RuleMatchedProxy, aclrouter.RuleProxy, aclrouter.RuleUnknown:
		return 0
	case aclrouter.RulePass, aclrouter.RuleMatchedPass, aclrouter.RulePrivate:
		return 1
	default:
		panic("?")
	}
}

func padRight50(str string) string {
	if len(str) <= 50 {
		return str + "                                                 "[:50-len(str)]
	}
	return str[:47] + "..."
}

func ServeWebConsole(w http.ResponseWriter, r *http.Request, proxy *pp.ProxyClient) {
	if r.Method == "GET" {
		if r.FormValue("traffic") == "1" {
			w.Header().Add("Content-Type", "image/svg+xml")
			w.Write(proxy.IO.Tr.SVG(300, 50, r.FormValue("log") == "1").Bytes())
			return
		}

		payload := struct {
			Global       bool
			Entries      int
			EntriesRatio int
			DNS          string
			I18N         map[string]string
		}{}

		buf, count := &bytes.Buffer{}, 0

		proxy.DNSCache.Info(func(k lru.Key, v interface{}, h int64, w int64) {
			count++
			rule := v.(*pp.Rule)
			ip, r := rule.IP, rule.R

			if aclrouter.IPv4ToInt(ip) > 0 {
				ip = fmt.Sprintf("<a href='http://freeapi.ipip.net/%v' target=_blank>%v</a>", ip, ip)
			} else {
				ip = "0.0.0.0"
			}

			ir := aclRuletoInternalRule(r)
			a, b := "Pass", "Block"
			if ir == 1 {
				a = "Proxy"
			} else if ir == 2 {
				a, b = "Proxy", "Pass"
			}

			buf.WriteString(fmt.Sprintf("%v (%d)\t%s\t%s -> %s  <button onclick='rule(\"%v\",this)'>%s</button> <button onclick='rule(\"%v\",this)'>%s</button>\n",
				padRight50(k.(string)), h, ip, aclRuletoString(r), internalRuletoString(ir), k, a, k, b))
		})

		payload.DNS = buf.String()
		payload.Global = proxy.Policy.IsSet(pp.PolicyGlobal)
		payload.Entries = count
		payload.EntriesRatio = count * 100 / int(proxy.DNSCache.MaxWeight())

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
			w.WriteHeader(200)
			return
		}

		if r.FormValue("proxy") != "" {
			if proxy.Policy.IsSet(pp.PolicyGlobal) {
				proxy.Policy.UnSet(pp.PolicyGlobal)
			} else {
				proxy.Policy.Set(pp.PolicyGlobal)
			}
			w.WriteHeader(200)
			return
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
				w.Write([]byte(internalRuletoString(old)))
			} else {
				w.Write([]byte("error"))
			}
			return
		}

		w.Write([]byte("error"))
	}
}
