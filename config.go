package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config mirrors pqwrap.yaml.
type Config struct {
	Mode    string  `yaml:"mode"`
	Listen  string  `yaml:"listen"`
	Profile string  `yaml:"profile"`
	Cert    string  `yaml:"cert"`
	Key     string  `yaml:"key"`
	Backend Backend `yaml:"backend"`
	Routes  []Route `yaml:"routes"` // mode client: one tunnel entry per protected service
}

type Backend struct {
	Address string `yaml:"address"`
	TLS     bool   `yaml:"tls"`  // false = plain TCP to the backend
	Name    string `yaml:"name"` // name in the backend certificate
	CA      string `yaml:"ca"`   // CA used to verify the backend
}

// Route is one protected service in client mode: apps reach Name at Listen,
// pqwrap carries the connection to the pqwrap in server mode at Remote.
type Route struct {
	Name   string `yaml:"name"`   // host name the apps use, see `pqwrap client add`
	Listen string `yaml:"listen"` // local address, e.g. 127.0.0.2:443
	Remote Remote `yaml:"remote"`
}

// Remote is the pqwrap in server mode at the other end of a tunnel.
// The connection to it always uses post-quantum TLS.
type Remote struct {
	Address string `yaml:"address"`
	Name    string `yaml:"name,omitempty"` // name in its certificate, default: host of address
	CA      string `yaml:"ca,omitempty"`   // CA used to verify it, default: system trust store
}

func loadConfig(path string) (Config, error) {
	cfg := Config{Mode: "server", Listen: ":443", Profile: "hybrid", Backend: Backend{TLS: true}}

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // don't silently ignore typos
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	// In client mode the routes take the place of the backend, and none is fine too
	if cfg.Mode != "client" && cfg.Backend.Address == "" {
		return cfg, errors.New("backend.address is missing")
	}
	return cfg, nil
}
