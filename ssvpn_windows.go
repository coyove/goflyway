package goflyway

import (
	"net"
)

func vpnDial(address string) (net.Conn, error) {
	panic("not on Windows")
}

func sendTrafficStats(recv, send int64) error {
	return nil
}
