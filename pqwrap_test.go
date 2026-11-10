package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Each case: profile on pqwrap, groups offered by the client, expected result.
var profileCases = []struct {
	name    string
	profile string
	client  []tls.CurveID // nil = Go default (hybrid + classical)
	ok      bool
	want    tls.CurveID
}{
	{"hybrid accepts X25519MLKEM768", "hybrid", []tls.CurveID{tls.X25519MLKEM768}, true, tls.X25519MLKEM768},
	{"hybrid accepts SecP256r1MLKEM768", "hybrid", []tls.CurveID{tls.SecP256r1MLKEM768}, true, tls.SecP256r1MLKEM768},
	{"hybrid with default client", "hybrid", nil, true, tls.X25519MLKEM768},
	{"hybrid rejects X25519", "hybrid", []tls.CurveID{tls.X25519}, false, 0},
	{"hybrid rejects P-256", "hybrid", []tls.CurveID{tls.CurveP256}, false, 0},
	{"high accepts SecP384r1MLKEM1024", "high", []tls.CurveID{tls.SecP384r1MLKEM1024}, true, tls.SecP384r1MLKEM1024},
	{"high rejects X25519MLKEM768", "high", []tls.CurveID{tls.X25519MLKEM768}, false, 0},
	{"pq accepts MLKEM1024", "pq", []tls.CurveID{tls.MLKEM1024}, true, tls.MLKEM1024},
	{"pq rejects hybrid", "pq", []tls.CurveID{tls.X25519MLKEM768}, false, 0},
	{"compat prefers hybrid", "compat", nil, true, tls.X25519MLKEM768},
	{"compat allows X25519", "compat", []tls.CurveID{tls.X25519}, true, tls.X25519},
	{"classic uses X25519", "classic", nil, true, tls.X25519},
	{"classic rejects hybrid", "classic", []tls.CurveID{tls.X25519MLKEM768}, false, 0},
}

func TestProfiles(t *testing.T) {
	pki := newTestPKI(t)
	backend := echoServer(t, pki.serverConfig("backend"))

	for _, tc := range profileCases {
		t.Run(tc.name, func(t *testing.T) {
			addr, _ := startProxy(t, pki, tc.profile, Backend{Address: backend, TLS: true, Name: "backend", CA: pki.caFile})

			conn, err := tls.Dial("tcp", addr, pki.clientConfig(tc.client))
			if !tc.ok {
				if err == nil {
					conn.Close()
					t.Fatal("connection accepted, should have been rejected")
				}
				return
			}
			if err != nil {
				t.Fatalf("connection rejected: %v", err)
			}
			defer conn.Close()
			if got := conn.ConnectionState().CurveID; got != tc.want {
				t.Errorf("group %v, want %v", got, tc.want)
			}
			echo(t, conn)
		})
	}
}

func TestTLS13Only(t *testing.T) {
	pki := newTestPKI(t)
	backend := echoServer(t, pki.serverConfig("backend"))
	addr, _ := startProxy(t, pki, "compat", Backend{Address: backend, TLS: true, Name: "backend", CA: pki.caFile})

	cfg := pki.clientConfig(nil)
	cfg.MaxVersion = tls.VersionTLS12
	if conn, err := tls.Dial("tcp", addr, cfg); err == nil {
		conn.Close()
		t.Fatal("TLS 1.2 was accepted")
	}
}

func TestLogLine(t *testing.T) {
	pki := newTestPKI(t)
	backend := echoServer(t, pki.serverConfig("backend"))
	addr, logs := startProxy(t, pki, "hybrid", Backend{Address: backend, TLS: true, Name: "backend", CA: pki.caFile})

	conn, err := tls.Dial("tcp", addr, pki.clientConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	echo(t, conn)
	conn.Close()

	line := logs.waitFor(t, `"msg":"connection"`)
	for _, part := range []string{`"group":"X25519MLKEM768"`, `"group_id":"0x11ec"`, `"pq":true`, `"backend_group":"X25519MLKEM768"`, `"bytes_in":5`} {
		if !strings.Contains(line, part) {
			t.Errorf("%s missing in %s", part, line)
		}
	}

	// Rejected clients show up with the groups they offered
	if conn, err := tls.Dial("tcp", addr, pki.clientConfig([]tls.CurveID{tls.X25519})); err == nil {
		conn.Close()
	}
	line = logs.waitFor(t, `"msg":"rejected"`)
	if !strings.Contains(line, `"offered":["X25519"]`) {
		t.Errorf("offered groups missing: %s", line)
	}
}

func TestPlaintextBackend(t *testing.T) {
	pki := newTestPKI(t)
	backend := echoServer(t, nil)
	addr, logs := startProxy(t, pki, "hybrid", Backend{Address: backend, TLS: false})

	conn, err := tls.Dial("tcp", addr, pki.clientConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	echo(t, conn)
	conn.Close()
	if line := logs.waitFor(t, `"msg":"connection"`); !strings.Contains(line, `"backend_group":"none"`) {
		t.Errorf("unexpected log line: %s", line)
	}
}

// A backend with a certificate from another CA must not be accepted
func TestBadBackendCert(t *testing.T) {
	pki := newTestPKI(t)
	other := newTestPKI(t)
	backend := echoServer(t, other.serverConfig("backend"))
	addr, logs := startProxy(t, pki, "hybrid", Backend{Address: backend, TLS: true, Name: "backend", CA: pki.caFile})

	conn, err := tls.Dial("tcp", addr, pki.clientConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Write([]byte("hello"))
	if n, _ := conn.Read(make([]byte, 5)); n > 0 {
		t.Error("data got through despite a bad backend certificate")
	}
	conn.Close()
	logs.waitFor(t, `"msg":"backend unreachable"`)
}

// A legacy client with TLS 1.2 and X25519 talks through the tunnel to a legacy
// server. Its own TLS has to arrive at the server untouched, only the hop
// between the two pqwraps uses ML-KEM.
func TestTunnel(t *testing.T) {
	pki := newTestPKI(t)
	legacy := echoServer(t, pki.serverConfig("legacy"))
	exit, exitLogs := startProxy(t, pki, "hybrid", Backend{Address: legacy, TLS: false})
	entry, entryLogs := startConfig(t, Config{Mode: "client", Profile: "hybrid",
		Backend: Backend{Address: exit, TLS: true, Name: "backend", CA: pki.caFile}})

	cfg := pki.clientConfig([]tls.CurveID{tls.X25519})
	cfg.ServerName = "legacy" // pqwrap only has a certificate for "backend"
	cfg.MaxVersion = tls.VersionTLS12
	conn, err := tls.Dial("tcp", entry, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v := conn.ConnectionState().Version; v != tls.VersionTLS12 {
		t.Errorf("inner TLS is %s, want TLS 1.2 from the legacy server", tls.VersionName(v))
	}
	echo(t, conn)
	conn.Close()

	line := entryLogs.waitFor(t, `"msg":"connection"`)
	for _, part := range []string{`"mode":"client"`, `"group":"X25519MLKEM768"`, `"pq":true`, `"bytes_in":`} {
		if !strings.Contains(line, part) {
			t.Errorf("%s missing in %s", part, line)
		}
	}
	if line := exitLogs.waitFor(t, `"msg":"connection"`); !strings.Contains(line, `"pq":true`) {
		t.Errorf("unexpected log line on the server side: %s", line)
	}
}

// The client side only offers its profile's groups, a mismatch fails the tunnel
func TestTunnelProfileMismatch(t *testing.T) {
	pki := newTestPKI(t)
	exit, _ := startProxy(t, pki, "hybrid", Backend{Address: echoServer(t, nil), TLS: false})
	entry, logs := startConfig(t, Config{Mode: "client", Profile: "classic",
		Backend: Backend{Address: exit, TLS: true, Name: "backend", CA: pki.caFile}})

	conn, err := net.Dial("tcp", entry)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	logs.waitFor(t, `"msg":"remote rejected"`)
}

func TestTunnelNeedsTLS(t *testing.T) {
	if _, err := newState(Config{Mode: "client", Profile: "hybrid", Backend: Backend{Address: "x:443"}}); err == nil {
		t.Fatal("client mode without backend TLS was accepted")
	}
}

// One client-side pqwrap protects two services, each through its own exit
func TestRoutes(t *testing.T) {
	pki := newTestPKI(t)
	var routes []Route
	for i, name := range []string{"legacy-a", "legacy-b"} {
		legacy := echoServer(t, pki.serverConfig(name))
		exit, _ := startProxy(t, pki, "hybrid", Backend{Address: legacy, TLS: false})
		routes = append(routes, Route{Name: name, Listen: fmt.Sprintf("127.0.0.%d:0", i+1),
			Remote: Remote{Address: exit, Name: "backend", CA: pki.caFile}})
	}
	p, logs := startClient(t, Config{Mode: "client", Profile: "hybrid", Routes: routes})

	for _, r := range routes {
		cfg := pki.clientConfig([]tls.CurveID{tls.X25519})
		cfg.ServerName = r.Name // the inner TLS reaches the right legacy server
		conn, err := tls.Dial("tcp", p.addr(t, r.Listen), cfg)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		echo(t, conn)
		conn.Close()
		logs.waitFor(t, `"route":"`+r.Name+`"`)
	}
}

// A reload adds and removes routes without touching the others
func TestRouteReload(t *testing.T) {
	pki := newTestPKI(t)
	exit, _ := startProxy(t, pki, "hybrid", Backend{Address: echoServer(t, nil), TLS: false})
	remote := Remote{Address: exit, Name: "backend", CA: pki.caFile}
	a := Route{Name: "a", Listen: "127.0.0.1:0", Remote: remote}
	b := Route{Name: "b", Listen: "127.0.0.2:0", Remote: remote}
	p, _ := startClient(t, Config{Mode: "client", Profile: "hybrid", Routes: []Route{a}})
	oldA := p.addr(t, a.Listen)

	st, err := newState(Config{Mode: "client", Profile: "hybrid", Routes: []Route{b}})
	if err != nil {
		t.Fatal(err)
	}
	p.state.Store(st)
	if err := p.syncListeners(st); err != nil {
		t.Fatal(err)
	}

	if conn, err := net.Dial("tcp", oldA); err == nil {
		conn.Close()
		t.Error("removed route still accepts connections")
	}
	conn, err := net.Dial("tcp", p.addr(t, b.Listen))
	if err != nil {
		t.Fatal(err)
	}
	echo(t, conn)
	conn.Close()
}

func TestRouteNotOnLoopback(t *testing.T) {
	pki := newTestPKI(t)
	_, logs := startClient(t, Config{Mode: "client", Profile: "hybrid", Routes: []Route{{
		Name: "lan", Listen: "0.0.0.0:0", Remote: Remote{Address: "gw:443", CA: pki.caFile}}}})
	logs.waitFor(t, `"msg":"route not on loopback"`)
}

func TestClientCmd(t *testing.T) {
	pki := newTestPKI(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "pqwrap.yaml")
	os.WriteFile(path, []byte("# tunnel entry on this laptop\nmode: client\nprofile: hybrid\n"), 0o644)
	hostsFile = filepath.Join(dir, "hosts")
	os.WriteFile(hostsFile, []byte("127.0.0.1\tlocalhost\n"), 0o644)
	t.Cleanup(func() { hostsFile = "/etc/hosts" })

	run := func(args ...string) int { return clientCmd(append(args, "-config", path)) }
	if code := run("add", "barkasse.intern:443", "--via", "gw.example:8443"); code != 0 {
		t.Fatalf("add failed: %d", code)
	}
	if code := run("add", "mail.intern:993", "--via", "gw.example:8993", "--ca", pki.caFile); code != 0 {
		t.Fatalf("second add failed: %d", code)
	}
	if code := run("add", "barkasse.intern:443", "--via", "gw.example:8443"); code == 0 {
		t.Error("adding the same name twice was accepted")
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 2 || cfg.Routes[0].Listen != "127.0.0.2:443" || cfg.Routes[1].Listen != "127.0.0.3:993" ||
		cfg.Routes[1].Remote.CA != pki.caFile {
		t.Errorf("unexpected routes: %+v", cfg.Routes)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "# tunnel entry on this laptop") {
		t.Errorf("comment lost:\n%s", data)
	}
	hosts, _ := os.ReadFile(hostsFile)
	for _, want := range []string{"127.0.0.1\tlocalhost", "127.0.0.2\tbarkasse.intern\t# pqwrap", "127.0.0.3\tmail.intern\t# pqwrap"} {
		if !strings.Contains(string(hosts), want) {
			t.Errorf("%q missing in hosts:\n%s", want, hosts)
		}
	}
	if _, err := newState(cfg); err != nil {
		t.Errorf("written config doesn't start: %v", err)
	}

	if code := run("remove", "barkasse.intern"); code != 0 {
		t.Fatalf("remove failed: %d", code)
	}
	if code := run("remove", "unknown.intern"); code == 0 {
		t.Error("removing an unknown name was accepted")
	}
	cfg, _ = loadConfig(path)
	hosts, _ = os.ReadFile(hostsFile)
	if len(cfg.Routes) != 1 || strings.Contains(string(hosts), "barkasse") || !strings.Contains(string(hosts), "localhost") {
		t.Errorf("remove left %+v and hosts:\n%s", cfg.Routes, hosts)
	}
}

// --- helpers ---

func startProxy(t *testing.T, pki *testPKI, profile string, b Backend) (string, *logBuffer) {
	t.Helper()
	return startConfig(t, Config{Profile: profile, Cert: pki.certFile, Key: pki.keyFile, Backend: b})
}

func startConfig(t *testing.T, cfg Config) (string, *logBuffer) {
	t.Helper()
	if cfg.Mode == "client" {
		// The single tunnel without routes, on a free port
		cfg.Listen = "127.0.0.1:0"
		p, logs := startClient(t, cfg)
		return p.addr(t, cfg.Listen), logs
	}
	st, err := newState(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logs := &logBuffer{}
	p := &proxy{log: slog.New(slog.NewJSONHandler(logs, nil))}
	p.state.Store(st)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go p.serve(l)
	return l.Addr().String(), logs
}

// startClient runs a pqwrap in client mode with a listener per route
func startClient(t *testing.T, cfg Config) (*proxy, *logBuffer) {
	t.Helper()
	st, err := newState(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logs := &logBuffer{}
	p := &proxy{log: slog.New(slog.NewJSONHandler(logs, nil))}
	p.state.Store(st)
	if err := p.syncListeners(st); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, l := range p.listeners {
			l.Close()
		}
	})
	return p, logs
}

// addr is where the listener for a route's listen address actually ended up
func (p *proxy) addr(t *testing.T, listen string) string {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	l, ok := p.listeners[listen]
	if !ok {
		t.Fatalf("no listener for %s", listen)
	}
	return l.Addr().String()
}

func echoServer(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		l = tls.NewListener(l, cfg)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String()
}

func echo(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo broken: %q %v", buf, err)
	}
}

// logBuffer collects the log lines written by the proxy
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) waitFor(t *testing.T, text string) string {
	t.Helper()
	for range 50 {
		b.mu.Lock()
		for _, line := range strings.Split(b.buf.String(), "\n") {
			if strings.Contains(line, text) {
				b.mu.Unlock()
				return line
			}
		}
		b.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no log line containing %s:\n%s", text, b.buf.String())
	return ""
}

// testPKI is a throwaway CA plus a certificate for pqwrap
type testPKI struct {
	ca                        *x509.Certificate
	caKey                     *ecdsa.PrivateKey
	pool                      *x509.CertPool
	caFile, certFile, keyFile string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &testPKI{ca: ca, caKey: key, pool: x509.NewCertPool()}
	p.pool.AddCert(ca)

	p.caFile = writePEM(t, dir, "ca.crt", "CERTIFICATE", der)
	cert := p.serverConfig("backend").Certificates[0]
	p.certFile = writePEM(t, dir, "pqwrap.crt", "CERTIFICATE", cert.Certificate[0])
	keyDER, _ := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	p.keyFile = writePEM(t, dir, "pqwrap.key", "PRIVATE KEY", keyDER)
	return p
}

func (p *testPKI) serverConfig(name string) *tls.Config {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func (p *testPKI) clientConfig(groups []tls.CurveID) *tls.Config {
	return &tls.Config{RootCAs: p.pool, ServerName: "backend", CurvePreferences: groups}
}

func writePEM(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
