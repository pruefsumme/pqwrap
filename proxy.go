package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dialTimeout      = 5 * time.Second
	handshakeTimeout = 10 * time.Second
)

type proxy struct {
	state atomic.Pointer[state]
	log   *slog.Logger

	mu        sync.Mutex
	listeners map[string]net.Listener // mode client, by route listen address
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

// handle takes care of one connection in server mode: terminate TLS from the
// client, connect to the backend, copy data both ways and log one line at the end.
func (p *proxy) handle(c net.Conn) {
	defer c.Close()
	st := p.state.Load()
	start := time.Now()

	// GetConfigForClient is only used to record which groups the client offers
	var offered []tls.CurveID
	clientTLS := tls.Server(c, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			offered = hello.SupportedCurves
			return st.server, nil
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err := clientTLS.HandshakeContext(ctx)
	cancel()

	attrs := []any{
		"client", c.RemoteAddr().String(),
		"profile", st.profile,
		"offered", groupNames(offered),
	}
	if err != nil {
		p.log.Warn("rejected", append(attrs, "error", err.Error())...)
		return
	}
	cs := clientTLS.ConnectionState()
	attrs = append(attrs, tlsAttrs(cs, time.Since(start))...)

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
		// Bytes are passed on as they are: plaintext, or the client's own TLS in a tunnel
		attrs = append(attrs, "backend_group", "none")
	}

	in, out := pipe(clientTLS, backend)
	p.logConnection(cs, append(attrs, "bytes_in", in, "bytes_out", out, "duration_ms", ms(time.Since(start))))
}

func (p *proxy) dialBackend(st *state) (net.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout}
	if st.backendTLS == nil {
		return d.Dial("tcp", st.backend.Address)
	}
	td := &tls.Dialer{NetDialer: d, Config: st.backendTLS}
	return td.Dial("tcp", st.backend.Address)
}

// tlsAttrs are the log fields for the post-quantum side of a connection,
// the same in server and client mode so both can be evaluated together.
func tlsAttrs(cs tls.ConnectionState, handshake time.Duration) []any {
	return []any{
		"tls", tls.VersionName(cs.Version),
		"group", groupName(cs.CurveID),
		"group_id", fmt.Sprintf("0x%04x", uint16(cs.CurveID)),
		"pq", isPQ(cs.CurveID),
		"hrr", cs.HelloRetryRequest,
		"cipher", tls.CipherSuiteName(cs.CipherSuite),
		"handshake_ms", ms(handshake),
	}
}

// logConnection writes the line at the end of a connection, a warning if the
// key exchange wasn't quantum-safe.
func (p *proxy) logConnection(cs tls.ConnectionState, attrs []any) {
	if isPQ(cs.CurveID) {
		p.log.Info("connection", attrs...)
	} else {
		p.log.Warn("connection", append(attrs, "warning", "classical key exchange, not quantum-safe")...)
	}
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
