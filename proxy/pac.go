package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/coyove/goflyway/pkg/lookup"
)

func (proxy *ProxyClient) PACFile(w http.ResponseWriter, r *http.Request) {
	if lookup.ChinaList == nil || len(lookup.ChinaList) == 0 {
		w.Write([]byte("the list is empty"))
		return
	}

	table, _ := json.Marshal(lookup.ChinaList)

	t := "SOCKS5"
	if proxy.Policy.IsSet(PolicyManInTheMiddle) {
		t = "PROXY"
	}

	pac := &bytes.Buffer{}
	pac.WriteString("var table = ")
	pac.Write(table)
	pac.WriteString(fmt.Sprintf(`;
		function isInTable(host) {
			var cands = host.split('.');
			if (cands.length <= 1)
				return false;
		
			var _table = table;
			for (var i = cands.length - 1; i >= 0; i--) {
				var cand = cands[i];
				if (!(cand in _table))
					return false;
		
				if (_table[cand] === 0)
					return true;
				
				_table = _table[cand];
			}

			return true;
		}
		
		function FindProxyForURL(url, host) {
			if (isPlainHostName(host) ||
				shExpMatch(host, "*.local") ||
				isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
				isInNet(dnsResolve(host), "172.16.0.0",  "255.240.0.0") ||
				isInNet(dnsResolve(host), "192.168.0.0",  "255.255.0.0") ||
				isInNet(dnsResolve(host), "127.0.0.0", "255.255.255.0") ||
				isInTable(host))
				return "DIRECT";
			
			return "%s %s";
		}`, t, r.Host))

	w.Write(pac.Bytes())
}
