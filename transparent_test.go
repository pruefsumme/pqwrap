package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeOriginalDst stands in for the kernel: every connection to the
// transparent listener looks as if it had been redirected from dst.
func fakeOriginalDst(t *testing.T, dst string, err error) {
	t.Helper()
	originalDst = func(net.Conn) (netip.AddrPort, error) {
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.MustParseAddrPort(dst), nil
	}
	t.Cleanup(func() { originalDst = sysOriginalDst })
}

// transparentEntry is a tunnel entry with one intercept route to a legacy echo server
func transparentEntry(t *testing.T, listen, intercept string) (*proxy, *logBuffer, *testPKI) {
	t.Helper()
	pki := newTestPKI(t)
	legacy := echoServer(t, pki.serverConfig("legacy"))
	exit, _ := startProxy(t, pki, "hybrid", Backend{Address: legacy, TLS: false})
	p, logs := startClient(t, Config{Mode: "client", Profile: "hybrid", Transparent: listen, Routes: []Route{{
		Name: "broker", Intercept: intercept, Remote: Remote{Address: exit, Name: "backend", CA: pki.caFile}}}})
	return p, logs, pki
}

// A redirected connection goes through the tunnel of the route with its
// original destination, the device's own TLS stays untouched
func TestTransparent(t *testing.T) {
	fakeOriginalDst(t, "10.1.2.3:8883", nil)
	p, logs, pki := transparentEntry(t, "127.0.0.1:0", "10.1.2.3:8883")
	logs.waitFor(t, `"msg":"transparent listener"`)

	cfg := pki.clientConfig([]tls.CurveID{tls.X25519})
	cfg.ServerName = "legacy"
	cfg.MaxVersion = tls.VersionTLS12
	conn, err := tls.Dial("tcp", p.addr(t, transparentKey+"127.0.0.1:0"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, conn)
	conn.Close()

	line := logs.waitFor(t, `"msg":"connection"`)
	for _, part := range []string{`"route":"broker"`, `"original_dst":"10.1.2.3:8883"`, `"group":"X25519MLKEM768"`, `"pq":true`} {
		if !strings.Contains(line, part) {
			t.Errorf("%s missing in %s", part, line)
		}
	}
}

// What has no route is closed, not passed on in the clear
func TestTransparentNoRoute(t *testing.T) {
	fakeOriginalDst(t, "10.9.9.9:443", nil)
	p, logs, _ := transparentEntry(t, "127.0.0.1:0", "10.1.2.3:8883")

	conn, err := net.Dial("tcp", p.addr(t, transparentKey+"127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("connection without a route stayed open")
	}
	if line := logs.waitFor(t, `"msg":"no route for destination"`); !strings.Contains(line, `"original_dst":"10.9.9.9:443"`) {
		t.Errorf("unexpected log line: %s", line)
	}
}

// Connecting to the transparent listener directly must not end up in a tunnel
func TestTransparentDirect(t *testing.T) {
	for name, kernel := range map[string]func(c net.Conn) (netip.AddrPort, error){
		"kernel has no entry": func(net.Conn) (netip.AddrPort, error) {
			return netip.AddrPort{}, errors.New("no such entry")
		},
		"kernel reports the listener": func(c net.Conn) (netip.AddrPort, error) {
			return netip.ParseAddrPort(c.LocalAddr().String())
		},
	} {
		t.Run(name, func(t *testing.T) {
			originalDst = kernel
			t.Cleanup(func() { originalDst = sysOriginalDst })
			p, logs, _ := transparentEntry(t, "127.0.0.1:0", "10.1.2.3:8883")
			conn, err := net.Dial("tcp", p.addr(t, transparentKey+"127.0.0.1:0"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Error("direct connection stayed open")
			}
			logs.waitFor(t, `"msg":"not a redirected connection"`)
		})
	}
}

func TestTransparentConfig(t *testing.T) {
	remote := Remote{Address: "gw:443"}
	for name, cfg := range map[string]Config{
		"intercept without listener": {Mode: "client", Profile: "hybrid",
			Routes: []Route{{Name: "a", Intercept: "10.1.2.3:8883", Remote: remote}}},
		"intercept with a name": {Mode: "client", Profile: "hybrid", Transparent: ":9040",
			Routes: []Route{{Name: "a", Intercept: "broker.intern:8883", Remote: remote}}},
		"intercept with IPv6": {Mode: "client", Profile: "hybrid", Transparent: ":9040",
			Routes: []Route{{Name: "a", Intercept: "[fd00::1]:8883", Remote: remote}}},
		"same intercept twice": {Mode: "client", Profile: "hybrid", Transparent: ":9040",
			Routes: []Route{{Name: "a", Intercept: "10.1.2.3:8883", Remote: remote}, {Name: "b", Intercept: "10.1.2.3:8883", Remote: remote}}},
		"neither listen nor intercept": {Mode: "client", Profile: "hybrid", Transparent: ":9040",
			Routes: []Route{{Name: "a", Remote: remote}}},
		"tunnel would catch itself": {Mode: "client", Profile: "hybrid", Transparent: ":9040",
			Routes: []Route{{Name: "a", Intercept: "10.1.2.3:8883", Remote: Remote{Address: "10.1.2.3:8883"}}}},
		"transparent in mode server": {Mode: "server", Profile: "hybrid", Transparent: ":9040"},
	} {
		if _, err := newState(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// listen and intercept together are fine: apps on the gateway and devices behind it
	st, err := newState(Config{Mode: "client", Profile: "hybrid", Transparent: ":9040",
		Routes: []Route{{Name: "a", Listen: "127.0.0.2:443", Intercept: "10.1.2.3:443", Remote: remote}}})
	if err != nil {
		t.Fatal(err)
	}
	if st.routes["127.0.0.2:443"] == nil || st.intercepts["10.1.2.3:443"] == nil {
		t.Errorf("route with listen and intercept is missing on one side: %+v", st.all)
	}
}

func TestClientRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pqwrap.yaml")
	os.WriteFile(path, []byte("mode: client\nprofile: hybrid\n"), 0o644)
	hostsFile = filepath.Join(dir, "hosts")
	t.Cleanup(func() { hostsFile = "/etc/hosts" })
	run := func(args ...string) int { return clientCmd(append(args, "-config", path)) }

	if code := run("add", "broker", "--intercept", "192.168.1.20:8883", "--via", "gw.example:8883"); code == 0 {
		t.Error("intercept route accepted without a transparent listener")
	}
	os.WriteFile(path, []byte("mode: client\nprofile: hybrid\ntransparent: \":9040\"\n"), 0o644)
	if code := run("add", "broker", "--intercept", "192.168.1.20:8883", "--via", "gw.example:8883"); code != 0 {
		t.Fatalf("add failed: %d", code)
	}
	if code := run("add", "barkasse.intern:443", "--via", "gw.example:8443"); code != 0 {
		t.Fatalf("add of a normal route failed: %d", code)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 2 || cfg.Routes[0].Listen != "" || cfg.Routes[0].Intercept != "192.168.1.20:8883" ||
		cfg.Routes[1].Listen != "127.0.0.2:443" {
		t.Errorf("unexpected routes: %+v", cfg.Routes)
	}
	if hosts, _ := os.ReadFile(hostsFile); strings.Contains(string(hosts), "broker") {
		t.Errorf("intercept route got a hosts line: %s", hosts)
	}

	rules, err := nftRules(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"hook prerouting", `ip daddr 192.168.1.20 tcp dport 8883 redirect to :9040 comment "broker"`} {
		if !strings.Contains(rules, part) {
			t.Errorf("%q missing in:\n%s", part, rules)
		}
	}
	if strings.Contains(rules, "barkasse") {
		t.Errorf("route without intercept got a rule:\n%s", rules)
	}
	if local, _ := nftRules(cfg, true); !strings.Contains(local, "hook output") {
		t.Errorf("--local should use the output hook:\n%s", local)
	}

	if code := run("remove", "broker"); code != 0 {
		t.Fatalf("remove failed: %d", code)
	}
	if cfg, _ = loadConfig(path); len(cfg.Routes) != 1 {
		t.Errorf("route still there: %+v", cfg.Routes)
	}
	if _, err := nftRules(cfg, false); err == nil {
		t.Error("rules without an intercept route should be an error")
	}
}

// The whole path with a real nftables redirect and the real SO_ORIGINAL_DST.
// The test runs itself again in its own network namespace (no root needed),
// loads the rules from nftRules there and dials an address that only exists
// as a rule. Skipped where unshare or nft is missing.
func TestTransparentRedirect(t *testing.T) {
	const inside = "PQWRAP_TEST_NETNS"
	if os.Getenv(inside) == "" {
		for _, tool := range []string{"unshare", "nft", "ip"} {
			if _, err := exec.LookPath(tool); err != nil {
				t.Skipf("%s not found", tool)
			}
		}
		if err := exec.Command("unshare", "-Urn", "true").Run(); err != nil {
			t.Skipf("no unprivileged network namespaces here: %v", err)
		}
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^TestTransparentRedirect$", "-test.v")
		cmd.Env = append(os.Environ(), inside+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("in the network namespace: %v\n%s", err, out)
		}
		if bytes.Contains(out, []byte("--- SKIP")) {
			t.Skipf("skipped in the network namespace:\n%s", out)
		}
		return
	}

	const dst = "10.1.2.3:8883" // nothing listens there, only the rule knows the address
	sh := func(stdin string, args ...string) error {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return errors.New(strings.Join(args, " ") + ": " + err.Error() + ": " + string(out))
		}
		return nil
	}
	if err := sh("", "ip", "link", "set", "lo", "up"); err != nil {
		t.Fatal(err)
	}
	if err := sh("", "ip", "addr", "add", "10.1.2.3/32", "dev", "lo"); err != nil {
		t.Fatal(err)
	}

	p, logs, pki := transparentEntry(t, "127.0.0.1:9040", dst)
	rules, err := nftRules(Config{Mode: "client", Transparent: "127.0.0.1:9040",
		Routes: []Route{{Name: "broker", Intercept: dst}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := sh(rules, "nft", "-f", "-"); err != nil {
		t.Skipf("nftables redirect not available: %v", err)
	}

	cfg := pki.clientConfig([]tls.CurveID{tls.X25519})
	cfg.ServerName = "legacy"
	conn, err := tls.Dial("tcp", dst, cfg)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, conn)
	conn.Close()
	line := logs.waitFor(t, `"msg":"connection"`)
	for _, part := range []string{`"route":"broker"`, `"original_dst":"` + dst + `"`, `"pq":true`} {
		if !strings.Contains(line, part) {
			t.Errorf("%s missing in %s", part, line)
		}
	}

	// Without the redirect the same listener turns the connection away
	direct, err := net.Dial("tcp", p.addr(t, transparentKey+"127.0.0.1:9040"))
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	if _, err := direct.Read(make([]byte, 1)); err == nil {
		t.Error("direct connection stayed open")
	}
	logs.waitFor(t, `"msg":"not a redirected connection"`)
}
