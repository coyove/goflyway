package goflyway

import (
	"net"

	"github.com/coyove/goflyway/pkg/trafficmon"
)

func vpnDial(address string) (net.Conn, error) {
	panic("not on Windows")
}

func sendTrafficStats(stat *trafficmon.Survey) error {
	return nil
}
