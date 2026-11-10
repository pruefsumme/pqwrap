package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const handshakeTimeout = 10 * time.Second

type proxy struct {
	state atomic.Pointer[state]
	log   *slog.Logger

	mu        sync.Mutex
	listeners map[string]net.Listener // client mode, by route listen address
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

// serveRoute accepts connections for one route in client mode. The route is
// looked up for every connection, so a reload changes it for new connections.
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
		// Bytes are passed on as they are: plaintext, or the client's own TLS in a tunnel
		attrs = append(attrs, "backend_group", "none")
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
