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
	Listen  string  `yaml:"listen"`
	Profile string  `yaml:"profile"`
	Cert    string  `yaml:"cert"`
	Key     string  `yaml:"key"`
	Backend Backend `yaml:"backend"`
}

type Backend struct {
	Address string `yaml:"address"`
	TLS     bool   `yaml:"tls"`  // false = plain TCP to the backend
	Name    string `yaml:"name"` // name in the backend certificate
	CA      string `yaml:"ca"`   // CA used to verify the backend
}

func loadConfig(path string) (Config, error) {
	cfg := Config{Listen: ":443", Profile: "hybrid", Backend: Backend{TLS: true}}

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // don't silently ignore typos
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Backend.Address == "" {
		return cfg, errors.New("backend.address is missing")
	}
	return cfg, nil
}
