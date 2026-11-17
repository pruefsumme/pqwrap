package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Transparent mode is for devices that can't be pointed at a tunnel entry:
// fixed firmware, a server address that is built in. pqwrap runs on the
// gateway next to them and a firewall rule redirects their connections to one
// listener (see `pqwrap client rules`):
//
//	device ──TLS to 192.168.1.20:8883──▶ gateway: nftables redirect ──▶ pqwrap ══PQ-TLS══▶ exit
//
// The device dials its server as always. pqwrap asks the kernel where the
// connection was going, picks the route with that address as intercept and
// carries it through the tunnel like any other. The exit needs no change,
// every route already leads to exactly one exit and one service behind it.
//
// A connection without a matching route is closed, never passed on in the
// clear: what the firewall hands to pqwrap either goes through a tunnel or
// nowhere.

// transparentKey marks the transparent listener among the route listeners
const transparentKey = "transparent "

// originalDst is swapped out in tests
var originalDst = sysOriginalDst

// openTransparent starts the listener for redirected connections.
// Called with p.mu held.
func (p *proxy) openTransparent(st *state, key string) error {
	// tcp4: SO_ORIGINAL_DST is asked for on an IPv4 socket, IPv6 is not supported yet
	l, err := net.Listen("tcp4", st.transparent)
	if err != nil {
		return err
	}
	p.log.Warn("transparent listener", "listen", st.transparent,
		"warning", "the hop from the device to pqwrap stays classical, run pqwrap on the gateway right next to the devices")
	for _, r := range st.all {
		if r.listen == "" { // routes with a listener were already checked there
			p.warnWithoutOwnCA(r)
		}
	}
	p.listeners[key] = l
	go p.serveTransparent(l)
	return nil
}

// serveTransparent accepts redirected connections. Like serveRoute it looks
// the route up for every connection, so a reload applies to new connections.
func (p *proxy) serveTransparent(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			st := p.state.Load()
			client := c.RemoteAddr().String()

			dst, err := originalDst(c)
			if err != nil {
				p.log.Warn("not a redirected connection", "client", client, "error", err.Error())
				return
			}
			// Without a redirect the kernel reports the listener itself
			if dst.String() == c.LocalAddr().String() {
				p.log.Warn("not a redirected connection", "client", client,
					"error", "connected to the transparent listener directly")
				return
			}
			r := st.intercepts[dst.String()]
			if r == nil {
				p.log.Warn("no route for destination", "client", client, "original_dst", dst.String(),
					"warning", "connection closed, add a route with this address as intercept or narrow the firewall rule")
				return
			}
			p.tunnel(c, st, r, "original_dst", dst.String())
		}()
	}
}

// nftRules prints the nftables rules that hand the intercepted destinations
// to the transparent listener. On a gateway they go into the prerouting hook
// and catch what the devices behind it send. With local they go into the
// output hook and catch the connections of apps on this machine, which makes
// the /etc/hosts lines unnecessary there.
func nftRules(cfg Config, local bool) (string, error) {
	if cfg.Mode != "client" || cfg.Transparent == "" {
		return "", fmt.Errorf("transparent mode is off, set transparent: \":9040\" in mode client")
	}
	_, port, err := net.SplitHostPort(cfg.Transparent)
	if err != nil {
		return "", fmt.Errorf("transparent %q: %w", cfg.Transparent, err)
	}
	hook, chain := "prerouting", "prerouting"
	if local {
		hook, chain = "output", "output"
	}

	var rules strings.Builder
	for _, r := range cfg.Routes {
		if r.Intercept == "" {
			continue
		}
		dst, err := netip.ParseAddrPort(r.Intercept)
		if err != nil {
			return "", fmt.Errorf("route %q: intercept %q: %w", r.Name, r.Intercept, err)
		}
		fmt.Fprintf(&rules, "\t\tip daddr %s tcp dport %d redirect to :%s comment \"%s\"\n",
			dst.Addr(), dst.Port(), port, r.Name)
	}
	if rules.Len() == 0 {
		return "", fmt.Errorf("no route has intercept set")
	}

	// The first two lines make the file safe to load again: the table is
	// created if missing, dropped, and then written fresh
	return "table ip pqwrap\ndelete table ip pqwrap\n\n" +
		"table ip pqwrap {\n" +
		"\tchain " + chain + " {\n" +
		"\t\ttype nat hook " + hook + " priority dstnat;\n" +
		rules.String() +
		"\t}\n}\n", nil
}
