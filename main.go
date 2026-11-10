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

	// Server mode has one fixed listener, client mode one per route
	var l net.Listener
	if st.client {
		err = p.syncListeners(st)
	} else {
		l, err = net.Listen("tcp", cfg.Listen)
	}
	if err != nil {
		log.Error("listen", "error", err.Error())
		os.Exit(1)
	}
	if st.client {
		p.logState("started", st)
	} else {
		p.logState("started", st, "listen", cfg.Listen)
	}

	// Switch profiles and routes without a restart. The mode and, in server
	// mode, the listen address stay as they were at the start.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			var next *state
			cfg, err := loadConfig(*path)
			if err == nil {
				next, err = newState(cfg)
			}
			if err == nil && next.client != st.client {
				err = fmt.Errorf("changing the mode needs a restart")
			}
			if err != nil {
				log.Error("reload failed, keeping old config", "error", err.Error())
				continue
			}
			p.state.Store(next)
			if next.client {
				if err := p.syncListeners(next); err != nil {
					log.Error("listen", "error", err.Error())
				}
			}
			p.logState("reloaded", next)
		}
	}()

	if st.client {
		select {}
	}
	if err := p.serve(l); err != nil {
		log.Error("serve", "error", err.Error())
		os.Exit(1)
	}
}

func (p *proxy) logState(msg string, st *state, extra ...any) {
	attrs := []any{"profile", st.profile, "groups", groupNames(st.groups)}
	if st.client {
		attrs = append([]any{"mode", "client"}, append(attrs, "routes", routeList(st))...)
	} else {
		attrs = append([]any{"mode", "server"}, append(attrs,
			"backend", st.backend.Address,
			"backend_tls", st.backendTLS != nil)...)
	}
	attrs = append(attrs, extra...)
	if st.hint != "" {
		p.log.Warn(msg, append(attrs, "warning", st.hint)...)
	} else {
		p.log.Info(msg, attrs...)
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
