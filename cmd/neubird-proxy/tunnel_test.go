package main

import (
	"bytes"
	"context"
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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/proxy"
	"github.com/neubirdai/neubird-proxy/internal/redact"
	"github.com/neubirdai/neubird-proxy/internal/tunnel"
)

// testCA is the relay CA: it signs the test relay's server certificate,
// which the proxy pins (tunnel.ca_file).
type testCA struct {
	dir  string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	file string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tenant CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	ca := &testCA{dir: t.TempDir(), cert: c, key: k}
	ca.file = ca.writePEM(t, "ca.crt", "CERTIFICATE", der)
	return ca
}

func (ca *testCA) writePEM(t *testing.T, name, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(ca.dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// sign issues a certificate for pub. A SPIFFE ID makes it a proxy client
// certificate; none makes it the relay's server certificate.
func (ca *testCA) sign(t *testing.T, pub any, spiffe string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if spiffe != "" {
		u, _ := url.Parse(spiffe)
		tmpl.URIs = []*url.URL{u}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// relay is a minimal relay: like the real one, it accepts a proxy only by
// a pinned key fingerprint (pin records one), and hands back the HTTP/2
// client for each tunnel.
func startRelay(t *testing.T, ca *testCA) (string, chan *http2.ClientConn, func(string)) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var mu sync.Mutex
	pinned := map[string]bool{}
	pin := func(fp string) { mu.Lock(); pinned[fp] = true; mu.Unlock() }
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{ca.sign(t, &k.PublicKey, "")}, PrivateKey: k}},
		ClientAuth:   tls.RequireAnyClientCert, NextProtos: []string{tunnel.ALPN},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			fp, _ := tunnel.Fingerprint(c.PublicKey)
			mu.Lock()
			defer mu.Unlock()
			if !pinned[fp] {
				return fmt.Errorf("key %s not pinned", fp)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	conns := make(chan *http2.ClientConn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := c.(*tls.Conn)
			if tc.Handshake() != nil {
				continue
			}
			if cc, err := (&http2.Transport{}).NewClientConn(tc); err == nil {
				conns <- cc
			}
		}
	}()
	return ln.Addr().String(), conns, pin
}

// keygen writes the key and prints its fingerprint, the one thing NeuBird
// records; fingerprint prints the same for the key or a certificate.
func TestKeygen(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "tunnel.key")
	code, out, errOut := runCmd(t, cmdKeygen, "-tenant", "metlife", "-proxy", "aks-prod", "-key-out", key)
	if code != 0 || !strings.Contains(out, "tenant: metlife") || !strings.Contains(out, "proxy: aks-prod") {
		t.Fatalf("code %d %s %s", code, out, errOut)
	}
	fp := fingerprintIn(t, out)
	if fi, _ := os.Stat(key); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", fi.Mode().Perm())
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("key printed")
	}
	if code, got, _ := runCmd(t, cmdFingerprint, key); code != 0 || strings.TrimSpace(got) != fp {
		t.Fatalf("fingerprint of the key: %d %q, want %s", code, got, fp)
	}
	signer, err := tunnel.LoadKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tunnel.Mint(signer, "spiffe://neubird.ai/tenant/metlife/proxy/aks-prod", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	certFile := writeFile(t, "minted.crt", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})))
	if code, got, _ := runCmd(t, cmdFingerprint, certFile); code != 0 || strings.TrimSpace(got) != fp {
		t.Fatalf("fingerprint of a certificate for the key: %d %q, want %s", code, got, fp)
	}
	if code, _, errOut := runCmd(t, cmdKeygen, "-tenant", "metlife", "-proxy", "aks-prod", "-key-out", key); code != 1 || !strings.Contains(errOut, "refusing to overwrite") {
		t.Fatalf("overwrite: %d %s", code, errOut)
	}
	if code, _, _ := runCmd(t, cmdKeygen, "-tenant", "Met Life", "-proxy", "x", "-key-out", key+"2"); code != 2 {
		t.Fatalf("invalid tenant accepted")
	}
}

func fingerprintIn(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "fingerprint:" {
			return f[1]
		}
	}
	t.Fatalf("no fingerprint in %q", out)
	return ""
}

// tunnelConfig runs keygen, records the fingerprint with the relay (pin),
// and writes a tunnel-only config whose one connection points at upstream.
// The proxy mints its own certificate from the key.
func tunnelConfig(t *testing.T, ca *testCA, pin func(string), relay, upstream string) string {
	t.Helper()
	key := filepath.Join(ca.dir, "tunnel.key")
	code, out, errOut := runCmd(t, cmdKeygen, "-tenant", "metlife", "-proxy", "aks-prod", "-key-out", key)
	if code != 0 {
		t.Fatal(errOut)
	}
	pin(fingerprintIn(t, out))
	return writeFile(t, "config.yaml", `
listen: "off"
client_token_env: PROXY_TOKEN
allow_http_upstreams: true
connections:
  - name: api
    upstream: `+upstream+`
tunnel:
  relays: ["`+relay+`"]
  tenant: metlife
  proxy: aks-prod
  key_file: `+key+`
  ca_file: `+ca.file+`
`)
}

// End to end through the real proxy: a request sent down the tunnel is
// authenticated, forwarded, redacted and audited like an inbound one.
func TestProxyOverTunnel(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"owner":"jane@example.com","host":"app-1"}`)
	}))
	defer up.Close()
	ca := newTestCA(t)
	relayAddr, conns, pin := startRelay(t, ca)
	cfgPath := tunnelConfig(t, ca, pin, relayAddr, up.URL)

	t.Setenv("PROXY_TOKEN", testToken)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := redact.New(cfg.Redaction)
	logs := &lockedBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	srv, err := proxy.New(cfg, engine, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := tunnel.Load(cfg.Tunnel)
	if err != nil {
		t.Fatal(err)
	}
	client := tunnel.New(cfg.Tunnel, id, srv, log, srv.Metrics.Registry)
	client.Start(context.Background())
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		client.Shutdown(ctx)
	}()

	var cc *http2.ClientConn
	select {
	case cc = <-conns:
	case <-time.After(5 * time.Second):
		t.Fatal("no tunnel")
	}
	call := func(auth string) (int, string) {
		req, _ := http.NewRequest("GET", "https://tunnel/api/items", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	if code, body := call("Bearer " + testToken); code != 200 || body != `{"owner":"[REDACTED:EMAIL]","host":"app-1"}` {
		t.Fatalf("code %d body %s", code, body)
	}
	if code, _ := call(""); code != 401 {
		t.Fatalf("no token over the tunnel: %d", code)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), `"via":"tunnel"`) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), `"via":"tunnel"`) || !strings.Contains(logs.String(), `"rules":{"email":1}`) {
		t.Fatalf("audit lines:\n%s", logs.String())
	}
}

func TestToolsWithTunnel(t *testing.T) {
	ca := newTestCA(t)
	relayAddr, _, pin := startRelay(t, ca)
	cfg := tunnelConfig(t, ca, pin, relayAddr, "https://api.example.com")
	env := envFile(t, "k")

	code, out, _ := runCmd(t, cmdValidate, "-config", cfg, "-env-file", env)
	if code != 0 || !strings.Contains(out, "tunnel: 1 relay(s) x 1 connection(s), no inbound listener") ||
		!strings.Contains(out, "identity: tenant metlife, proxy aks-prod") {
		t.Fatalf("validate: %d\n%s", code, out)
	}
	code, out, _ = runCmd(t, cmdValidate, "-offline", "-config", cfg)
	if code != 0 || !strings.Contains(out, "not checked (offline)") {
		t.Fatalf("validate offline: %d\n%s", code, out)
	}

	code, out, _ = runCmd(t, cmdTest, "-config", cfg, "-env-file", env)
	for _, want := range []string{"tunnel -> " + relayAddr, "identity   tenant metlife, proxy aks-prod",
		"ok    relay      " + relayAddr + ": mutual TLS and neubird-tunnel/1"} {
		if !strings.Contains(out, want) {
			t.Errorf("test output missing %q:\n%s", want, out)
		}
	}

	_, out, _ = runCmd(t, cmdNetpol, "-config", cfg, "-format", "list")
	if !strings.Contains(out, "127.0.0.1:"+strings.Split(relayAddr, ":")[1]) || !strings.Contains(out, "api.example.com:443") {
		t.Fatalf("netpol: %s", out)
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
