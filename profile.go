package main

import "crypto/tls"

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
		hint:   "ML-KEM only without a classical part, against the recommendation of BSI (TR-02102-1, 2.1/2.2) and ANSSI to use it hybrid",
	},
	"classic": {
		groups: []tls.CurveID{tls.X25519, tls.CurveP256},
		hint:   "no post-quantum key exchange, meant for baseline measurements only (X25519 is not among the groups BSI TR-02102-2 recommends)",
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
