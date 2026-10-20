package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
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
	profile    string
	hint       string
	groups     []tls.CurveID
	server     *tls.Config
	backend    Backend
	backendTLS *tls.Config // nil = plain TCP to the backend
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

	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}

	s := &state{
		profile: cfg.Profile,
		hint:    p.hint,
		groups:  slices.Clone(p.groups),
		backend: cfg.Backend,
		server: &tls.Config{
			Certificates:     []tls.Certificate{cert},
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: p.groups,
		},
	}

	if cfg.Backend.TLS {
		// The backend certificate is always verified, there is no switch to turn that off
		s.backendTLS = &tls.Config{ServerName: cfg.Backend.Name}
		if cfg.Backend.CA != "" {
			pem, err := os.ReadFile(cfg.Backend.CA)
			if err != nil {
				return nil, fmt.Errorf("load backend CA: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("no certificates in %s", cfg.Backend.CA)
			}
			s.backendTLS.RootCAs = pool
		}
	}
	return s, nil
}
