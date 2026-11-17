//go:build !linux

package main

import (
	"errors"
	"net"
	"net/netip"
)

func sysOriginalDst(net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("transparent mode needs Linux")
}
