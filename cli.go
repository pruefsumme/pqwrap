package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// The client subcommands manage the routes of a pqwrap in client mode and the
// matching /etc/hosts lines, so apps reach a protected service under its
// usual name without being changed:
//
//	pqwrap client add barkasse.intern:443 --via pqgw.example:8443 [--ca ca.crt]
//	pqwrap client list
//	pqwrap client remove barkasse.intern
//
// Every service gets its own loopback address (127.0.0.2, 127.0.0.3, ...), so
// several services can use the same port. A running pqwrap picks up the
// change on SIGHUP.

var hostsFile = "/etc/hosts"

const hostsMarker = "# pqwrap"

const clientUsage = `usage:
  pqwrap client add <name:port> --via <host:port> [--via-name <name>] [--ca <file>] [--cert <file> --key <file>] [-config <file>]
  pqwrap client list [-config <file>]
  pqwrap client remove <name> [-config <file>]`

func clientCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, clientUsage)
		return 2
	}
	fs := flag.NewFlagSet("client "+args[0], flag.ContinueOnError)
	path := fs.String("config", "config/pqwrap.yaml", "config file")
	via := fs.String("via", "", "address of the pqwrap in server mode")
	viaName := fs.String("via-name", "", "name in its certificate, default: host of --via")
	ca := fs.String("ca", "", "CA to verify it, default: system trust store")
	cert := fs.String("cert", "", "client certificate for an exit with client_ca")
	key := fs.String("key", "", "key of the client certificate")

	// Go's flag package stops at the first argument that isn't a flag, so the
	// name in "add <name:port> --via ..." is taken off before parsing
	rest := args[1:]
	var arg string
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		arg, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}

	var err error
	switch args[0] {
	case "add":
		err = addRoute(*path, arg, Remote{Address: *via, Name: *viaName, CA: *ca, Cert: *cert, Key: *key})
	case "remove":
		err = removeRoute(*path, arg)
	case "list":
		err = listRoutes(*path)
	default:
		fmt.Fprintln(os.Stderr, clientUsage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqwrap client "+args[0]+":", err)
		return 1
	}
	return 0
}

func addRoute(path, target string, remote Remote) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("%q: want name:port, e.g. barkasse.intern:443", target)
	}
	if remote.Address == "" {
		return errors.New("--via is missing")
	}
	if _, _, err := net.SplitHostPort(remote.Address); err != nil {
		return fmt.Errorf("--via %q: want host:port", remote.Address)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if cfg.Mode != "client" {
		return fmt.Errorf("%s is not in mode client", path)
	}
	for _, r := range cfg.Routes {
		if r.Name == host {
			return fmt.Errorf("%s is already protected (listen %s)", host, r.Listen)
		}
	}
	ip, err := freeLoopback(cfg.Routes)
	if err != nil {
		return err
	}

	r := Route{Name: host, Listen: net.JoinHostPort(ip, port), Remote: remote}
	err = editRoutes(path, func(seq *yaml.Node) error {
		var item yaml.Node
		if err := item.Encode(r); err != nil {
			return err
		}
		seq.Content = append(seq.Content, &item)
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s now goes through %s (listen %s)\n", host, remote.Address, r.Listen)
	return setHosts(ip, host)
}

func removeRoute(path, name string) error {
	if name == "" {
		return errors.New("name is missing")
	}
	err := editRoutes(path, func(seq *yaml.Node) error {
		for i, item := range seq.Content {
			var r Route
			if item.Decode(&r) == nil && r.Name == name {
				seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("no route for %s", name)
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s removed\n", name)
	return setHosts("", name)
}

func listRoutes(path string) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if len(cfg.Routes) == 0 {
		fmt.Println("no routes, add one with: pqwrap client add <name:port> --via <host:port>")
		return nil
	}
	hosts := hostsEntries()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tLISTEN\tVIA\tHOSTS")
	for _, r := range cfg.Routes {
		ip, _, _ := net.SplitHostPort(r.Listen)
		status := "ok"
		if hosts[r.Name] != ip {
			status = "missing"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Name, r.Listen, r.Remote.Address, status)
	}
	return w.Flush()
}

// freeLoopback picks the first loopback address from 127.0.0.2 on that no
// route uses yet, so every service can keep its usual port.
func freeLoopback(routes []Route) (string, error) {
	used := map[string]bool{}
	for _, r := range routes {
		ip, _, _ := net.SplitHostPort(r.Listen)
		used[ip] = true
	}
	for n := 2; n < 255; n++ {
		if ip := fmt.Sprintf("127.0.0.%d", n); !used[ip] {
			return ip, nil
		}
	}
	return "", errors.New("no free loopback address left")
}

// editRoutes changes the routes list in the config file. It goes through the
// YAML node tree, so comments and the other settings stay as they are.
func editRoutes(path string, edit func(seq *yaml.Node) error) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: not a YAML mapping", path)
	}
	if err := edit(routesNode(doc.Content[0])); err != nil {
		return err
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	enc.Close()

	// Check the result before overwriting the old config
	tmp := path + ".new"
	if err := os.WriteFile(tmp, buf.Bytes(), info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := loadConfig(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("edited config is invalid: %w", err)
	}
	return os.Rename(tmp, path)
}

// routesNode returns the "routes" list of the top-level mapping and adds an
// empty one if there is none yet.
func routesNode(root *yaml.Node) *yaml.Node {
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "routes" {
			continue
		}
		seq := root.Content[i+1]
		if seq.Kind != yaml.SequenceNode {
			// "routes:" without entries comes in as null
			*seq = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", HeadComment: seq.HeadComment, LineComment: seq.LineComment}
		}
		return seq
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "routes"}, seq)
	return seq
}

// setHosts maps name to ip in /etc/hosts, or removes the mapping when ip is
// empty. Only lines that pqwrap wrote itself (with the marker) are touched.
func setHosts(ip, name string) error {
	data, err := os.ReadFile(hostsFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var lines []string
	if len(data) > 0 {
		lines = strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	}
	var kept []string
	for _, line := range lines {
		if f := strings.Fields(line); strings.HasSuffix(line, hostsMarker) && len(f) >= 2 && f[1] == name {
			continue
		}
		kept = append(kept, line)
	}
	entry := ip + "\t" + name + "\t" + hostsMarker
	if ip != "" {
		kept = append(kept, entry)
	}
	out := strings.Join(kept, "\n") + "\n"
	if err := os.WriteFile(hostsFile, []byte(out), 0o644); err != nil {
		if ip != "" {
			return fmt.Errorf("can't change %s (%w), run with sudo or add this line yourself:\n  %s", hostsFile, err, entry)
		}
		return fmt.Errorf("can't change %s (%w), run with sudo or remove the %s line yourself", hostsFile, err, name)
	}
	return nil
}

// hostsEntries returns the name -> ip lines pqwrap wrote to /etc/hosts
func hostsEntries() map[string]string {
	entries := map[string]string{}
	data, _ := os.ReadFile(hostsFile)
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); strings.HasSuffix(line, hostsMarker) && len(f) >= 2 {
			entries[f[1]] = f[0]
		}
	}
	return entries
}
