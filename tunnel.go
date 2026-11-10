package main

import (
	"context"
	"crypto/tls"
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

// tunnel handles one connection on the client side.
func (p *proxy) tunnel(c net.Conn, st *state, r *route) {
	attrs := []any{
		"mode", "client",
		"route", r.name,
		"client", c.RemoteAddr().String(),
		"profile", st.profile,
		"remote", r.remote,
	}

	// Dial and handshake separately, so handshake_ms is comparable to the server side
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", r.remote)
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
	attrs = append(attrs,
		"tls", tls.VersionName(cs.Version),
		"group", groupName(cs.CurveID),
		"group_id", fmt.Sprintf("0x%04x", uint16(cs.CurveID)),
		"pq", isPQ(cs.CurveID),
		"hrr", cs.HelloRetryRequest,
		"cipher", tls.CipherSuiteName(cs.CipherSuite),
		"handshake_ms", ms(time.Since(start)),
	)

	in, out := pipe(c, remote)
	attrs = append(attrs, "bytes_in", in, "bytes_out", out, "duration_ms", ms(time.Since(start)))

	if isPQ(cs.CurveID) {
		p.log.Info("connection", attrs...)
	} else {
		p.log.Warn("connection", append(attrs, "warning", "classical key exchange, not quantum-safe")...)
	}
}
