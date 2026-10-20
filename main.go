// pqwrap puts post-quantum TLS in front of a service that can't be changed.
// Clients connect with TLS 1.3 and a hybrid key exchange (ML-KEM), pqwrap
// forwards the connection to the existing backend.
//
//	go run . -config config/pqwrap.yaml
//	kill -HUP <pid>   reload the config, e.g. after switching profiles
package main

import (
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	path := flag.String("config", "config/pqwrap.yaml", "config file")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	p := &proxy{log: log}

	cfg, err := loadConfig(*path)
	if err != nil {
		log.Error("config", "error", err.Error())
		os.Exit(1)
	}
	st, err := newState(cfg)
	if err != nil {
		log.Error("config", "error", err.Error())
		os.Exit(1)
	}
	p.state.Store(st)

	l, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Error("listen", "error", err.Error())
		os.Exit(1)
	}
	p.logState("started", st, "listen", cfg.Listen)

	// Switch profiles without a restart, the listen address stays the same
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			var st *state
			cfg, err := loadConfig(*path)
			if err == nil {
				st, err = newState(cfg)
			}
			if err != nil {
				log.Error("reload failed, keeping old config", "error", err.Error())
				continue
			}
			p.state.Store(st)
			p.logState("reloaded", st)
		}
	}()

	if err := p.serve(l); err != nil {
		log.Error("serve", "error", err.Error())
		os.Exit(1)
	}
}

func (p *proxy) logState(msg string, st *state, extra ...any) {
	attrs := append([]any{
		"profile", st.profile,
		"groups", groupNames(st.groups),
		"backend", st.backend.Address,
		"backend_tls", st.backendTLS != nil,
	}, extra...)
	if st.hint != "" {
		p.log.Warn(msg, append(attrs, "warning", st.hint)...)
	} else {
		p.log.Info(msg, attrs...)
	}
}
