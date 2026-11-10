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

// A profile decides which key exchange groups clients may use.
// Order doesn't matter, Go prefers the hybrid groups anyway.
type profile struct {
	groups []tls.CurveID
	hint   string // logged as a warning on start
}

var profiles = map[string]profile{
	"hybrid": {
		groups: []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768},
	},
	"high": {
		groups: []tls.CurveID{tls.SecP384r1MLKEM1024},
	},
	"compat": {
		groups: []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.X25519, tls.CurveP256},
		hint:   "classical clients allowed, their connections are not quantum-safe and get logged as warnings",
	},
	"pq": {
		groups: []tls.CurveID{tls.MLKEM1024},
		hint:   "ML-KEM only without a classical part, not allowed by some guidelines (e.g. BSI, ANSSI)",
	},
	"classic": {
		groups: []tls.CurveID{tls.X25519, tls.CurveP256},
		hint:   "no post-quantum key exchange, meant for baseline measurements only",
	},
}

func isPQ(id tls.CurveID) bool {
	switch id {
	case tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.MLKEM1024:
		return true
	}
	return false
}

// Groups Go doesn't support but clients still offer
var otherGroups = map[tls.CurveID]string{
	30:  "X448",
	256: "ffdhe2048",
	257: "ffdhe3072",
	258: "ffdhe4096",
	512: "MLKEM512",
	513: "MLKEM768",
}

func groupName(id tls.CurveID) string {
	if name, ok := otherGroups[id]; ok {
		return name
	}
	return id.String()
}

func groupNames(ids []tls.CurveID) []string {
	names := make([]string, len(ids))
	for i, id := range ids {
		names[i] = groupName(id)
	}
	return names
}

// state is everything built from the config.
// On SIGHUP a new state is built and swapped in.
type state struct {
	client     bool // tunnel entry, see tunnel.go
	profile    string
	hint       string
	groups     []tls.CurveID
	server     *tls.Config
	backend    Backend
	backendTLS *tls.Config       // nil = plain TCP to the backend
	routes     map[string]*route // client mode, by listen address
}

// route is a Route ready to use, see tunnel.go
type route struct {
	name   string
	listen string
	remote string
	tls    *tls.Config
	ownCA  bool // the exit is checked against remote.ca, not the system trust store
}

func newState(cfg Config) (*state, error) {
	p, ok := profiles[cfg.Profile]
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
		hint:    p.hint,
		groups:  slices.Clone(p.groups),
		backend: cfg.Backend,
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
			CurvePreferences: p.groups,
		}
	case "client":
		s.client = true
		routes := cfg.Routes
		if len(routes) == 0 && cfg.Backend.Address != "" {
			// A single tunnel from listen and backend, as before there were routes
			if !cfg.Backend.TLS {
				return nil, errors.New("mode client needs backend.tls: true")
			}
			b := cfg.Backend
			routes = []Route{{Listen: cfg.Listen, Remote: Remote{Address: b.Address, Name: b.Name, CA: b.CA}}}
		}
		s.routes = make(map[string]*route, len(routes))
		for _, r := range routes {
			rt, err := newRoute(r, p.groups)
			if err != nil {
				return nil, err
			}
			if _, dup := s.routes[rt.listen]; dup {
				return nil, fmt.Errorf("two routes listen on %s", rt.listen)
			}
			s.routes[rt.listen] = rt
		}
		return s, nil
	default:
		return nil, fmt.Errorf("unknown mode %q, available: server, client", cfg.Mode)
	}

	if cfg.Backend.TLS {
		var err error
		s.backendTLS, err = verifyingConfig(cfg.Backend.Name, cfg.Backend.CA)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func newRoute(r Route, groups []tls.CurveID) (*route, error) {
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
	return &route{name: r.Name, listen: r.Listen, remote: r.Remote.Address, tls: cfg, ownCA: r.Remote.CA != ""}, nil
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
