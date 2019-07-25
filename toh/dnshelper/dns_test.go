package dnshelper

import "testing"

func TestDNS(t *testing.T) {
	t.Log(LookupIPv4("google.com", true))
	t.Log(LookupIPv4("google.com", false))
}
