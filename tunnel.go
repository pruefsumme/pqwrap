package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// A tunnel needs two pqwraps and leaves the connection inside untouched:
//
//	legacy client ──TLS──▶ pqwrap (mode client) ══PQ-TLS══▶ pqwrap (mode server) ──TLS──▶ legacy server
//
// The client side takes plain TCP, usually the legacy client's own TLS, and
// sends it through post-quantum TLS. The server side is a normal pqwrap with
// backend.tls: false, it unwraps and passes the bytes on. The inner TLS stays
// between client and server, pqwrap never sees the plaintext.
//
// One client-side pqwrap can protect several services, one route each:
// a local address the apps connect to and the pqwrap that leads to the service.

// syncListeners opens a listener for each new route and closes the ones whose
// route is gone, so routes can be added and removed with a reload.
func (p *proxy) syncListeners(st *state) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listeners == nil {
		p.listeners = make(map[string]net.Listener)
	}
	var errs []error
	for addr, r := range st.routes {
		if _, ok := p.listeners[addr]; ok {
			continue
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("route %q: %w", r.name, err))
			continue
		}
		if !onLoopback(addr) {
			p.log.Warn("route not on loopback", "route", r.name, "listen", addr,
				"warning", "the hop from the app to pqwrap stays classical, run pqwrap on the same host as the app")
		}
		if !r.ownCA {
			// The tunnel only keeps a substituted certificate out if nobody else can issue one for the exit
			p.log.Warn("route without own CA", "route", r.name, "remote", r.remote,
				"warning", "the exit is checked against the system trust store, any public CA could issue a certificate for it, set remote.ca")
		}
		p.listeners[addr] = l
		go p.serveRoute(l, addr)
	}
	for addr, l := range p.listeners {
		if _, ok := st.routes[addr]; !ok {
			l.Close()
			delete(p.listeners, addr)
		}
	}
	return errors.Join(errs...)
}

// serveRoute accepts connections for one route. The route is looked up for
// every connection, so a reload changes it for new connections.
func (p *proxy) serveRoute(l net.Listener, addr string) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			st := p.state.Load()
			if r := st.routes[addr]; r != nil {
				p.tunnel(c, st, r)
			}
		}()
	}
}

func onLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// tunnel handles one connection on the client side.
func (p *proxy) tunnel(c net.Conn, st *state, r *tunnelRoute) {
	attrs := []any{
		"mode", "client",
		"route", r.name,
		"client", c.RemoteAddr().String(),
		"profile", st.profile,
		"remote", r.remote,
	}

	// Dial and handshake separately, so handshake_ms is comparable to the server side
	raw, err := (&net.Dialer{Timeout: dialTimeout}).Dial("tcp", r.remote)
	if err != nil {
		p.log.Error("remote unreachable", append(attrs, "error", err.Error())...)
		return
	}
	defer raw.Close()

	start := time.Now()
	remote := tls.Client(raw, r.tls)
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err = remote.HandshakeContext(ctx)
	cancel()
	if err != nil {
		p.log.Error("remote rejected", append(attrs, "error", err.Error())...)
		return
	}
	cs := remote.ConnectionState()
	attrs = append(attrs, tlsAttrs(cs, time.Since(start))...)

	in, out := pipe(c, remote)
	p.logConnection(cs, append(attrs, "bytes_in", in, "bytes_out", out, "duration_ms", ms(time.Since(start))))
}
