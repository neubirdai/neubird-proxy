package tunnel

import (
	"bufio"
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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/metrics"
)

// The vectors from docs/tunnel-protocol.md; neubird-relay tests the same.
func TestIDVectors(t *testing.T) {
	for id, want := range map[string]string{
		"spiffe://neubird.ai/tenant/metlife/proxy/aks-prod":       "metlife/aks-prod",
		"spiffe://neubird.ai/tenant/a/proxy/b":                    "a/b",
		"spiffe://neubird.ai/tenant/metlife/proxy/aks-prod/extra": "",
		"spiffe://example.com/tenant/metlife/proxy/aks-prod":      "",
		"spiffe://neubird.ai/tenant/MetLife/proxy/aks-prod":       "",
		"spiffe://neubird.ai/tenant/metlife/proxy/-aks":           "",
		"spiffe://neubird.ai/tenant/metlife/proxy/":               "",
		"spiffe://neubird.ai/tenant/metlife/proxy/aks?x=1":        "",
		"https://neubird.ai/tenant/metlife/proxy/aks-prod":        "",
	} {
		tenant, proxy, err := ParseID(id)
		got := ""
		if err == nil {
			got = tenant + "/" + proxy
		}
		if got != want {
			t.Errorf("ParseID(%q) = %q (%v), want %q", id, got, err, want)
		}
	}
	if id, err := FormatID("metlife", "aks-prod"); err != nil || id != "spiffe://neubird.ai/tenant/metlife/proxy/aks-prod" {
		t.Fatalf("FormatID = %q, %v", id, err)
	}
	if _, err := FormatID("Met Life", "x"); err == nil {
		t.Fatal("FormatID accepted an invalid tenant")
	}
}

// --- test PKI ---

type pki struct {
	dir    string
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caFile string
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	ca, _ := x509.ParseCertificate(der)
	p := &pki{dir: t.TempDir(), ca: ca, caKey: k}
	p.caFile = p.write(t, "ca.crt", "CERTIFICATE", der)
	return p
}

func (p *pki) write(t *testing.T, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(p.dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type leafOpts struct {
	uris      []string
	server    bool
	noAuth    bool // no extended key usage
	notBefore time.Time
	notAfter  time.Time
}

func (p *pki) leaf(t *testing.T, name string, o leafOpts) (tls.Certificate, string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: o.notBefore, NotAfter: o.notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	switch {
	case o.server:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"relay.test"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	case !o.noAuth:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	for _, u := range o.uris {
		pu, _ := url.Parse(u)
		tmpl.URIs = append(tmpl.URIs, pu)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &k.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(k)
	certFile := p.write(t, name+".crt", "CERTIFICATE", der)
	keyFile := p.write(t, name+".key", "EC PRIVATE KEY", kder)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, certFile, keyFile
}

func (p *pki) proxyConfig(t *testing.T, relays ...string) *config.Tunnel {
	t.Helper()
	_, cert, key := p.leaf(t, "proxy", leafOpts{uris: []string{"spiffe://neubird.ai/tenant/metlife/proxy/aks-prod"}})
	return &config.Tunnel{Relays: relays, CertFile: cert, KeyFile: key, CAFile: p.caFile, ConnectionsPerRelay: 1}
}

func TestLoad(t *testing.T) {
	p := newPKI(t)
	cfg := p.proxyConfig(t, "relay.test:443")
	id, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if id.Tenant != "metlife" || id.Proxy != "aks-prod" || id.DaysLeft() < 0.9 {
		t.Fatalf("%+v", id)
	}
	for name, c := range map[string]struct {
		o    leafOpts
		want string
	}{
		"two IDs":       {leafOpts{uris: []string{"spiffe://neubird.ai/tenant/a/proxy/b", "spiffe://neubird.ai/tenant/c/proxy/d"}}, "at most one URI SAN"},
		"bad ID":        {leafOpts{uris: []string{"spiffe://neubird.ai/tenant/A/proxy/b"}}, "SPIFFE ID must be"},
		"no clientAuth": {leafOpts{uris: []string{"spiffe://neubird.ai/tenant/a/proxy/b"}, noAuth: true}, "clientAuth"},
		"expired": {leafOpts{uris: []string{"spiffe://neubird.ai/tenant/a/proxy/b"},
			notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Hour)}, "not now"},
	} {
		t.Run(name, func(t *testing.T) {
			_, cert, key := p.leaf(t, strings.ReplaceAll(name, " ", "-"), c.o)
			_, err := Load(&config.Tunnel{CertFile: cert, KeyFile: key, CAFile: p.caFile})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	// A certificate naming nothing is fine: the relay names the proxy from
	// its records, by key.
	_, cert, key := p.leaf(t, "no-spiffe-id", leafOpts{})
	if id, err := Load(&config.Tunnel{CertFile: cert, KeyFile: key, CAFile: p.caFile}); err != nil || id.Tenant != "" || id.Name() != "named by NeuBird's records" {
		t.Fatalf("certificate without a SPIFFE ID: %+v %v", id, err)
	}
	if _, err := Load(&config.Tunnel{CertFile: cfg.CertFile, KeyFile: cfg.KeyFile, CAFile: cfg.CertFile + ".missing"}); err == nil {
		t.Fatal("missing CA file accepted")
	}
}

// --- fake relay ---

type tunnelConn struct {
	cc     *http2.ClientConn
	tenant string
	proxy  string
}

type fakeRelay struct {
	ln      net.Listener
	tunnels chan tunnelConn
	accepts atomic.Int32
}

func newRelay(t *testing.T, p *pki, alpn string) *fakeRelay {
	t.Helper()
	cert, _, _ := p.leaf(t, "relay", leafOpts{server: true})
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{alpn}, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRelay{ln: ln, tunnels: make(chan tunnelConn, 16)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r.accepts.Add(1)
			tc := c.(*tls.Conn)
			if tc.Handshake() != nil {
				continue
			}
			tenant, proxy, _ := ParseID(tc.ConnectionState().PeerCertificates[0].URIs[0].String())
			cc, err := (&http2.Transport{}).NewClientConn(tc)
			if err != nil {
				continue
			}
			r.tunnels <- tunnelConn{cc: cc, tenant: tenant, proxy: proxy}
		}
	}()
	return r
}

func (r *fakeRelay) next(t *testing.T) tunnelConn {
	t.Helper()
	select {
	case tc := <-r.tunnels:
		return tc
	case <-time.After(5 * time.Second):
		t.Fatal("no tunnel connected")
		return tunnelConn{}
	}
}

func newClient(t *testing.T, cfg *config.Tunnel, h http.Handler) (*Client, *metrics.Registry) {
	t.Helper()
	id, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reg := &metrics.Registry{}
	c := New(cfg, id, h, slog.New(slog.NewTextHandler(io.Discard, nil)), reg)
	c.proxyFor = func(*url.URL) (*url.URL, error) { return nil, nil }
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c.Shutdown(ctx)
	})
	return c, reg
}

func get(t *testing.T, tc tunnelConn, path string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "https://tunnel"+path, nil)
	req.Header.Set("Authorization", "Bearer proxy-token")
	resp, err := tc.cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestTunnelServesRequestsAndStreams(t *testing.T) {
	p := newPKI(t)
	relay := newRelay(t, p, ALPN)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/splunk/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			for i := 0; i < 3; i++ {
				fmt.Fprintf(w, "data: %d\n\n", i)
				w.(http.Flusher).Flush()
				time.Sleep(80 * time.Millisecond)
			}
			return
		}
		fmt.Fprintf(w, "%s %s auth=%s via=%s", r.Method, r.URL.Path, r.Header.Get("Authorization"), Via(r.Context()))
	})
	c, reg := newClient(t, p.proxyConfig(t, relay.ln.Addr().String()), h)
	c.Start(context.Background())
	tc := relay.next(t)
	if tc.tenant != "metlife" || tc.proxy != "aks-prod" {
		t.Fatalf("relay saw %s/%s", tc.tenant, tc.proxy)
	}

	if _, body := get(t, tc, "/splunk/services/mcp"); body != "GET /splunk/services/mcp auth=Bearer proxy-token via=tunnel" {
		t.Fatalf("body %q", body)
	}

	req, _ := http.NewRequest("GET", "https://tunnel/splunk/stream", nil)
	resp, err := tc.cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(resp.Body)
	start := time.Now()
	line, _ := br.ReadString('\n')
	if line != "data: 0\n" || time.Since(start) > 60*time.Millisecond {
		t.Fatalf("first event %q after %s: not streamed", line, time.Since(start))
	}
	io.Copy(io.Discard, br)
	resp.Body.Close()

	var out strings.Builder
	reg.Write(&out)
	for _, want := range []string{
		`neubird_proxy_tunnels{relay="` + relay.ln.Addr().String() + `"} 1`,
		`neubird_proxy_tunnel_connects_total{relay="` + relay.ln.Addr().String() + `",result="ok"} 1`,
		"neubird_proxy_tunnel_cert_expiry_days ",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("metrics missing %s:\n%s", want, out.String())
		}
	}
}

func TestTunnelReconnects(t *testing.T) {
	p := newPKI(t)
	relay := newRelay(t, p, ALPN)
	c, _ := newClient(t, p.proxyConfig(t, relay.ln.Addr().String()), http.NotFoundHandler())
	c.Start(context.Background())
	first := relay.next(t)
	first.cc.Close() // relay restart, or a revocation
	second := relay.next(t)
	if resp, _ := get(t, second, "/x"); resp.StatusCode != 404 {
		t.Fatalf("status %d on the new tunnel", resp.StatusCode)
	}
}

func TestTunnelRefusesWrongProtocolAndUntrustedRelay(t *testing.T) {
	p := newPKI(t)
	wrong := newRelay(t, p, "h2")
	c, reg := newClient(t, p.proxyConfig(t, wrong.ln.Addr().String()), http.NotFoundHandler())
	c.Start(context.Background())
	waitFor(t, func() bool {
		return metricHas(reg, `result="tls_error"`) || metricHas(reg, `result="protocol_mismatch"`)
	})
	select {
	case <-wrong.tunnels:
		t.Fatal("tunnel served over the wrong protocol")
	default:
	}

	other := newPKI(t) // relay signed by a CA the proxy doesn't pin
	untrusted := newRelay(t, other, ALPN)
	cfg := p.proxyConfig(t, untrusted.ln.Addr().String())
	c2, reg2 := newClient(t, cfg, http.NotFoundHandler())
	c2.Start(context.Background())
	waitFor(t, func() bool { return metricHas(reg2, `result="tls_error"`) })
}

func TestTunnelThroughHTTPProxy(t *testing.T) {
	p := newPKI(t)
	relay := newRelay(t, p, ALPN)
	var connects atomic.Int32
	px, _ := net.Listen("tcp", "127.0.0.1:0")
	defer px.Close()
	go func() {
		for {
			c, err := px.Accept()
			if err != nil {
				return
			}
			go func() {
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect || req.Header.Get("Proxy-Authorization") == "" {
					io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
					c.Close()
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					c.Close()
					return
				}
				connects.Add(1)
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go io.Copy(up, br)
				io.Copy(c, up)
			}()
		}
	}()
	c, _ := newClient(t, p.proxyConfig(t, relay.ln.Addr().String()), http.NotFoundHandler())
	c.proxyFor = func(*url.URL) (*url.URL, error) {
		return url.Parse("http://user:pass@" + px.Addr().String())
	}
	c.Start(context.Background())
	tc := relay.next(t)
	if resp, _ := get(t, tc, "/x"); resp.StatusCode != 404 || connects.Load() != 1 {
		t.Fatalf("status %d, CONNECTs %d", resp.StatusCode, connects.Load())
	}
}

func TestTunnelGracefulShutdown(t *testing.T) {
	p := newPKI(t)
	relay := newRelay(t, p, ALPN)
	started := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		io.WriteString(w, "finished")
	})
	c, _ := newClient(t, p.proxyConfig(t, relay.ln.Addr().String()), h)
	c.Start(context.Background())
	tc := relay.next(t)

	result := make(chan string, 1)
	go func() {
		_, body := get(t, tc, "/slow")
		result <- body
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if got := <-result; got != "finished" {
		t.Fatalf("in-flight request got %q", got)
	}
	time.Sleep(200 * time.Millisecond)
	if n := relay.accepts.Load(); n != 1 {
		t.Fatalf("reconnected after shutdown: %d accepts", n)
	}
}

func metricHas(reg *metrics.Registry, s string) bool {
	var b strings.Builder
	reg.Write(&b)
	return strings.Contains(b.String(), s)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// With TLS 1.3 the proxy's handshake succeeds before the relay has checked
// its certificate; a refused certificate must not count as connected.
func TestTunnelRefusedCertificateIsNotConnected(t *testing.T) {
	p := newPKI(t)
	relay := newRelay(t, p, ALPN)
	other := newPKI(t) // the proxy's certificate is from a CA the relay doesn't trust
	cfg := other.proxyConfig(t, relay.ln.Addr().String())
	cfg.CAFile = p.caFile // but it does pin the right relay CA
	c, reg := newClient(t, cfg, http.NotFoundHandler())
	c.Start(context.Background())
	waitFor(t, func() bool { return metricHas(reg, `result="rejected"`) })
	if metricHas(reg, `result="ok"`) || c.Connected() != 0 {
		t.Fatalf("refused tunnel counted as connected (%d up)", c.Connected())
	}
	if _, err := c.Check(context.Background(), relay.ln.Addr().String()); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("Check of a refused certificate: %v", err)
	}
}

// A renewed certificate written over the old files is used on the next
// connect, without a restart.
func TestTunnelReloadsRenewedCertificate(t *testing.T) {
	p := newPKI(t)
	relay := newRelay(t, p, ALPN)
	cfg := p.proxyConfig(t, relay.ln.Addr().String())
	c, _ := newClient(t, cfg, http.NotFoundHandler())
	c.Start(context.Background())
	first := relay.next(t)
	waitFor(t, func() bool { return c.Connected() == 1 })

	renewed, _, _ := p.leaf(t, "renewed", leafOpts{uris: []string{"spiffe://neubird.ai/tenant/metlife/proxy/aks-prod"}})
	os.Rename(filepath.Join(p.dir, "renewed.crt"), cfg.CertFile)
	os.Rename(filepath.Join(p.dir, "renewed.key"), cfg.KeyFile)
	first.cc.Close() // the relay closes the tunnel (e.g. the old certificate expired)
	relay.next(t)
	c.idMu.Lock()
	got := c.id.Leaf.SerialNumber
	c.idMu.Unlock()
	want, _ := x509.ParseCertificate(renewed.Certificate[0])
	if got.Cmp(want.SerialNumber) != 0 {
		t.Fatalf("tunnel uses serial %s, want the renewed %s", got, want.SerialNumber)
	}
}

// A client started before its certificate files load keeps trying and
// connects once they do.
func TestTunnelStartsWithoutIdentity(t *testing.T) {
	p := newPKI(t)
	relay := newRelay(t, p, ALPN)
	cfg := p.proxyConfig(t, relay.ln.Addr().String())
	good, _ := os.ReadFile(cfg.CertFile)
	os.WriteFile(cfg.CertFile, []byte("not a certificate"), 0o600)
	reg := &metrics.Registry{}
	c := New(cfg, nil, http.NotFoundHandler(), slog.New(slog.NewTextHandler(io.Discard, nil)), reg)
	c.proxyFor = func(*url.URL) (*url.URL, error) { return nil, nil }
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c.Shutdown(ctx)
	})
	c.Start(context.Background())
	waitFor(t, func() bool { return metricHas(reg, `result="identity_error"`) })
	os.WriteFile(cfg.CertFile, good, 0o600)
	relay.next(t)
}

// Only plain HTTP requests cross the tunnel, whatever the connection's
// settings: CONNECT and TRACE are refused before the handler. (HTTP/2
// itself keeps upgrades out.)
func TestTunnelOnlyPlainHTTP(t *testing.T) {
	p := newPKI(t)
	relay := newRelay(t, p, ALPN)
	var reached atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		fmt.Fprint(w, "ok")
	})
	c, _ := newClient(t, p.proxyConfig(t, relay.ln.Addr().String()), h)
	c.Start(context.Background())
	tc := relay.next(t)

	for _, m := range []string{http.MethodConnect, http.MethodTrace} {
		req, _ := http.NewRequest(m, "https://tunnel/splunk/services/mcp", nil)
		if m == http.MethodConnect {
			req.URL.Path = "" // CONNECT carries an authority, not a path
		}
		resp, err := tc.cc.RoundTrip(req)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed || !strings.Contains(string(b), "method_not_allowed") {
			t.Errorf("%s: %d %q", m, resp.StatusCode, b)
		}
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("%d refused requests reached the handler", n)
	}
	if _, body := get(t, tc, "/splunk/services/mcp"); body != "ok" {
		t.Fatalf("plain GET: %q", body)
	}

}
