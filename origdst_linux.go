//go:build linux

package main

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// SO_ORIGINAL_DST from linux/netfilter_ipv4.h
const soOriginalDst = 80

// sysOriginalDst asks the kernel where a redirected connection was going
// before nftables changed its destination. The answer comes from connection
// tracking, so it only exists for connections that went through a redirect.
func sysOriginalDst(c net.Conn) (netip.AddrPort, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, errors.New("not a TCP connection")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var mreq *syscall.IPv6Mreq
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		// The kernel answers with a sockaddr_in (16 bytes). The standard library
		// has no call for that, GetsockoptIPv6Mreq is the one that reads enough bytes.
		mreq, sockErr = syscall.GetsockoptIPv6Mreq(int(fd), syscall.SOL_IP, soOriginalDst)
	})
	if err == nil {
		err = sockErr
	}
	if err != nil {
		return netip.AddrPort{}, err
	}
	// sockaddr_in: family (2 bytes), port (2 bytes, big endian), address (4 bytes)
	b := mreq.Multiaddr
	port := uint16(b[2])<<8 | uint16(b[3])
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), port), nil
}
