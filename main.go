// pqwrap puts post-quantum TLS in front of a service that can't be changed.
// Clients connect with TLS 1.3 and a hybrid key exchange (ML-KEM), pqwrap
// forwards the connection to the existing backend. For clients that can't do
// ML-KEM either, two pqwraps form a tunnel (mode: client, see tunnel.go).
//
//	go run . -config config/pqwrap.yaml
//	kill -HUP <pid>   reload the config, e.g. after switching profiles
//	pqwrap client add|list|remove ...   manage the routes in client mode, see cli.go
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "client" {
		os.Exit(clientCmd(os.Args[2:]))
	}

	path := flag.String("config", "config/pqwrap.yaml", "config file")
	flag.Parse()

	p := &proxy{log: slog.New(slog.NewJSONHandler(os.Stdout, nil))}
	cfg, err := loadConfig(*path)
	if err != nil {
		p.log.Error("config", "error", err.Error())
		os.Exit(1)
	}
	st, err := newState(cfg)
	if err != nil {
		p.log.Error("config", "error", err.Error())
		os.Exit(1)
	}
	p.state.Store(st)
	go p.reloadOnHUP(*path)

	if st.client {
		err = p.runClient(st)
	} else {
		err = p.runServer(st, cfg.Listen)
	}
	p.log.Error("stopped", "error", err.Error())
	os.Exit(1)
}

// runServer has one fixed listener, the listen address can't change on reload
func (p *proxy) runServer(st *state, listen string) error {
	l, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	p.logState("started", st, "listen", listen)
	p.warnOpenExit(st)
	return p.serve(l)
}

// runClient has one listener per route, a reload opens and closes them
func (p *proxy) runClient(st *state) error {
	if err := p.syncListeners(st); err != nil {
		return err
	}
	p.logState("started", st)
	select {}
}

// reloadOnHUP switches profiles and routes without a restart.
// The mode stays as it was at the start.
func (p *proxy) reloadOnHUP(path string) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	for range hup {
		cfg, err := loadConfig(path)
		var next *state
		if err == nil {
			next, err = newState(cfg)
		}
		if err == nil && next.client != p.state.Load().client {
			err = fmt.Errorf("changing the mode needs a restart")
		}
		if err != nil {
			p.log.Error("reload failed, keeping old config", "error", err.Error())
			continue
		}
		p.state.Store(next)
		if next.client {
			if err := p.syncListeners(next); err != nil {
				p.log.Error("listen", "error", err.Error())
			}
		}
		p.logState("reloaded", next)
		p.warnOpenExit(next)
	}
}

func (p *proxy) logState(msg string, st *state, extra ...any) {
	var attrs []any
	if st.client {
		attrs = []any{"mode", "client", "profile", st.profile, "groups", groupNames(st.groups), "routes", routeList(st)}
	} else {
		attrs = []any{"mode", "server", "profile", st.profile, "groups", groupNames(st.groups),
			"backend", st.backend.Address, "backend_tls", st.backendTLS != nil}
	}
	attrs = append(attrs, extra...)
	if st.hint != "" {
		p.log.Warn(msg, append(attrs, "warning", st.hint)...)
	} else {
		p.log.Info(msg, attrs...)
	}
}

// warnOpenExit points out a tunnel exit that lets anyone through: with plain
// TCP to the backend and no client certificates, whoever reaches pqwrap
// reaches the backend.
func (p *proxy) warnOpenExit(st *state) {
	if !st.client && st.backendTLS == nil && !st.clientAuth {
		p.log.Warn("no client authentication", "backend", st.backend.Address,
			"warning", "anyone who reaches pqwrap can use the backend, set client_ca so only tunnel entries with a certificate get through")
	}
}

// routeList shows the routes in the start and reload log lines
func routeList(st *state) []string {
	list := make([]string, 0, len(st.routes))
	for _, r := range st.routes {
		list = append(list, fmt.Sprintf("%s %s -> %s", r.name, r.listen, r.remote))
	}
	sort.Strings(list)
	return list
}
