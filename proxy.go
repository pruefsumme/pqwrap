package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

const handshakeTimeout = 10 * time.Second

type proxy struct {
	state atomic.Pointer[state]
	log   *slog.Logger
}

func (p *proxy) serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go p.handle(c)
	}
}

// handle takes care of one connection: terminate TLS from the client,
// connect to the backend, copy data both ways and log one line at the end.
func (p *proxy) handle(c net.Conn) {
	defer c.Close()
	st := p.state.Load()
	start := time.Now()

	// GetConfigForClient is only used to record which groups the client offers
	var offered []tls.CurveID
	tc := tls.Server(c, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			offered = hello.SupportedCurves
			return st.server, nil
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err := tc.HandshakeContext(ctx)
	cancel()
	handshake := time.Since(start)

	attrs := []any{
		"client", c.RemoteAddr().String(),
		"profile", st.profile,
		"offered", groupNames(offered),
	}
	if err != nil {
		p.log.Warn("rejected", append(attrs, "error", err.Error())...)
		return
	}

	cs := tc.ConnectionState()
	attrs = append(attrs,
		"tls", tls.VersionName(cs.Version),
		"group", groupName(cs.CurveID),
		"group_id", fmt.Sprintf("0x%04x", uint16(cs.CurveID)),
		"pq", isPQ(cs.CurveID),
		"hrr", cs.HelloRetryRequest,
		"cipher", tls.CipherSuiteName(cs.CipherSuite),
		"handshake_ms", ms(handshake),
	)

	backend, err := p.dialBackend(st)
	if err != nil {
		p.log.Error("backend unreachable", append(attrs, "error", err.Error())...)
		return
	}
	defer backend.Close()
	attrs = append(attrs, "backend", st.backend.Address)
	if bc, ok := backend.(*tls.Conn); ok {
		attrs = append(attrs, "backend_group", groupName(bc.ConnectionState().CurveID))
	} else {
		attrs = append(attrs, "backend_group", "plaintext")
	}

	in, out := pipe(tc, backend)
	attrs = append(attrs, "bytes_in", in, "bytes_out", out, "duration_ms", ms(time.Since(start)))

	if isPQ(cs.CurveID) {
		p.log.Info("connection", attrs...)
	} else {
		p.log.Warn("connection", append(attrs, "warning", "classical key exchange, not quantum-safe")...)
	}
}

func (p *proxy) dialBackend(st *state) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	if st.backendTLS == nil {
		return d.Dial("tcp", st.backend.Address)
	}
	td := &tls.Dialer{NetDialer: d, Config: st.backendTLS}
	return td.Dial("tcp", st.backend.Address)
}

// pipe copies both ways until both sides are done.
// When one direction ends, the other side gets told via CloseWrite.
func pipe(client, backend net.Conn) (in, out int64) {
	done := make(chan int64)
	go func() {
		n, _ := io.Copy(backend, client)
		closeWrite(backend)
		done <- n
	}()
	out, _ = io.Copy(client, backend)
	closeWrite(client)
	in = <-done
	return in, out
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		c.Close()
	}
}

func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}
