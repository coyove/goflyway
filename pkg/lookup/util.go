package lookup

import (
	"strconv"
	"strings"
)

func linesToRange(lines string) []ipRange {
	l := strings.Split(lines, "\n")
	ret := make([]ipRange, 0, len(l))

	for _, iprange := range l {
		s, e := tryParseIPRange(iprange)
		ret = append(ret, ipRange{s, e})
	}

	return ret
}

func fillLookupTable(table *[]ipRange, iplist []ipRange) {
	init := true
	lastIPStart, lastIPEnd := uint32(0), uint32(0)

	for _, iprange := range iplist {
		ipstart, ipend := iprange.start, iprange.end

		if init {
			init = false
			lastIPStart, lastIPEnd = ipstart, ipend
			continue
		}

		if ipstart != lastIPEnd+1 {
			*table = append(*table, ipRange{lastIPStart, lastIPEnd})
			lastIPStart = ipstart
		}

		lastIPEnd = ipend
	}

	if lastIPStart > 0 && lastIPEnd >= lastIPStart {
		*table = append(*table, ipRange{lastIPStart, lastIPEnd})
	}
}

func tryParseIPRange(iprange string) (uint32, uint32) {
	p := strings.Split(iprange, " ")
	if len(p) >= 2 {
		// form: "0.0.0.0 1.2.3.4"
		ipstart, ipend := IPv4ToInt(p[0]), IPv4ToInt(p[1])
		if ipstart > 0 && ipend > 0 {
			return ipstart, ipend
		}
	}

	p = strings.Split(iprange, "/")
	if len(p) >= 2 {
		// form: "1.2.3.4/12"
		ipstart := IPv4ToInt(p[0])
		mask, _ := strconv.Atoi(p[1])

		if mask >= 0 && mask < 32 { // could be 32
			ipend := ipstart + (1<<(32-uint(mask)) - 1)
			return ipstart, ipend
		}
	}

	return 0, 0
}

func (lk *lookup) tryAddACLSingleRule(r string) {
	r = strings.Replace(r, "\\.", ".", -1)
	if strings.HasPrefix(r, "(^|.)") && strings.HasSuffix(r, "$") {
		subs := strings.Split(strings.Trim(r[5:len(r)-1], "\r "), ".")

		fast := lk.DomainFastMatch
		for i := len(subs) - 1; i >= 0; i-- {
			if fast[subs[i]] == nil {
				fast[subs[i]] = make(matchTree)
			}

			if i == 0 {
				// end
				fast[subs[0]] = 0
			} else {
				fast = fast[subs[i]].(matchTree)
			}
		}

		return
	}

	if idx := strings.Index(r, "/"); idx > -1 {
		if _, err := strconv.Atoi(r[idx+1:]); err == nil {

		}
	}
}

func (lk *lookup) isDomainMatched(domain string) bool {
	slowMatch := func() bool {
		for _, r := range lk.DomainSlowMatch {
			if r.MatchString(domain) {
				return true
			}
		}

		return false
	}

	top := lk.DomainFastMatch
	if top == nil {
		return slowMatch()
	}

	subs := strings.Split(domain, ".")
	if len(subs) <= 1 {
		return slowMatch()
	}

	for i := len(subs) - 1; i >= 0; i-- {
		sub := subs[i]
		if top[sub] == nil {
			return slowMatch()
		}

		switch top[sub].(type) {
		case matchTree:
			top = top[sub].(matchTree)
		case int:
			return top[sub].(int) == 0
		default:
			return slowMatch()
		}
	}

	return true
}
