package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
)

// state is everything built from the config.
// On SIGHUP a new state is built and swapped in.
type state struct {
	client  bool // mode client: tunnel entries, see tunnel.go
	profile string
	hint    string
	groups  []tls.CurveID

	// mode server
	server     *tls.Config
	backend    Backend
	backendTLS *tls.Config // nil = plain TCP to the backend

	// mode client
	routes map[string]*tunnelRoute // by listen address
}

// tunnelRoute is a Route from the config, ready to use
type tunnelRoute struct {
	name   string
	listen string
	remote string
	tls    *tls.Config
	ownCA  bool // the exit is checked against remote.ca, not the system trust store
}

func newState(cfg Config) (*state, error) {
	prof, ok := profiles[cfg.Profile]
	if !ok {
		names := make([]string, 0, len(profiles))
		for name := range profiles {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("unknown profile %q, available: %s", cfg.Profile, strings.Join(names, ", "))
	}

	s := &state{
		profile: cfg.Profile,
		hint:    prof.hint,
		groups:  slices.Clone(prof.groups),
	}

	switch cfg.Mode {
	case "", "server":
		if len(cfg.Routes) > 0 {
			return nil, errors.New("routes are only used in mode client")
		}
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("load certificate: %w", err)
		}
		s.server = &tls.Config{
			Certificates:     []tls.Certificate{cert},
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: prof.groups,
		}
		s.backend = cfg.Backend
		if cfg.Backend.TLS {
			s.backendTLS, err = verifyingConfig(cfg.Backend.Name, cfg.Backend.CA)
			if err != nil {
				return nil, err
			}
		}

	case "client":
		if cfg.Backend.Address != "" {
			return nil, errors.New("mode client uses routes, backend is only for mode server")
		}
		s.client = true
		s.routes = make(map[string]*tunnelRoute, len(cfg.Routes))
		for _, r := range cfg.Routes {
			rt, err := newRoute(r, prof.groups)
			if err != nil {
				return nil, err
			}
			if _, dup := s.routes[rt.listen]; dup {
				return nil, fmt.Errorf("two routes listen on %s", rt.listen)
			}
			s.routes[rt.listen] = rt
		}

	default:
		return nil, fmt.Errorf("unknown mode %q, available: server, client", cfg.Mode)
	}
	return s, nil
}

func newRoute(r Route, groups []tls.CurveID) (*tunnelRoute, error) {
	if r.Listen == "" || r.Remote.Address == "" {
		return nil, fmt.Errorf("route %q: listen and remote.address are required", r.Name)
	}
	name := r.Remote.Name
	if name == "" {
		host, _, err := net.SplitHostPort(r.Remote.Address)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", r.Name, err)
		}
		name = host
	}
	cfg, err := verifyingConfig(name, r.Remote.CA)
	if err != nil {
		return nil, fmt.Errorf("route %q: %w", r.Name, err)
	}
	// The hop to the other pqwrap is the post-quantum one, so it gets the profile's groups
	cfg.MinVersion = tls.VersionTLS13
	cfg.CurvePreferences = groups
	return &tunnelRoute{name: r.Name, listen: r.Listen, remote: r.Remote.Address, tls: cfg, ownCA: r.Remote.CA != ""}, nil
}

// verifyingConfig is the TLS config for connecting to name. The certificate
// is always verified, there is no switch to turn that off.
func verifyingConfig(name, caFile string) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: name}
	if caFile == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", caFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}
