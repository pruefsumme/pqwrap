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
	if line := logs.waitFor(t, `"msg":"connection"`); !strings.Contains(line, `"backend_group":"plaintext"`) {
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

// --- helpers ---

func startProxy(t *testing.T, pki *testPKI, profile string, b Backend) (string, *logBuffer) {
	t.Helper()
	st, err := newState(Config{Profile: profile, Cert: pki.certFile, Key: pki.keyFile, Backend: b})
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
