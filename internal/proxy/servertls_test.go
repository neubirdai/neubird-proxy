package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/metrics"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestServerTLSReload rotates the listener's certificate and client CA on
// disk and checks new handshakes pick both up without a restart, that files
// which stop loading keep the previous set, and that HTTP/2 still
// negotiates.
func TestServerTLSReload(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), filepath.Join(dir, "ca.crt")
	caA, caAKey := newCA(t)
	srvA, srvAKey := newLeaf(t, caA, caAKey, "proxy", true)
	writePEM(t, caFile, "CERTIFICATE", caA.Raw)
	writePEM(t, certFile, "CERTIFICATE", srvA.Raw)
	writeKey(t, keyFile, srvAKey)

	var logs bytes.Buffer
	reg := &metrics.Registry{}
	st, err := NewServerTLS(&config.TLS{CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile},
		slog.New(slog.NewTextHandler(&logs, nil)), reg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{
		TLSConfig: st.Config(),
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.Proto) }),
	}
	go hs.ServeTLS(ln, "", "")
	defer hs.Close()
	url := "https://" + ln.Addr().String()

	// get connects afresh (no pooled connection), trusting roots and
	// presenting cert, and returns the server's leaf and the protocol.
	get := func(roots *x509.Certificate, cert tls.Certificate) (*x509.Certificate, string, error) {
		pool := x509.NewCertPool()
		pool.AddCert(roots)
		tr := &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, ServerName: "proxy"},
			ForceAttemptHTTP2: true,
		}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr}).Get(url)
		if err != nil {
			return nil, "", err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.TLS.PeerCertificates[0], string(body), nil
	}
	cliA, cliAKey := newLeaf(t, caA, caAKey, "gateway", false)
	certA := tls.Certificate{Certificate: [][]byte{cliA.Raw}, PrivateKey: cliAKey}

	leaf, proto, err := get(caA, certA)
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.Equal(srvA) || proto != "HTTP/2.0" {
		t.Fatalf("before rotation: got %q over %s", leaf.Subject.CommonName, proto)
	}

	// Rotate everything to a new CA: new server certificate, and only
	// clients from the new CA accepted.
	caB, caBKey := newCA(t)
	srvB, srvBKey := newLeaf(t, caB, caBKey, "proxy", true)
	writePEM(t, caFile, "CERTIFICATE", caB.Raw)
	writePEM(t, certFile, "CERTIFICATE", srvB.Raw)
	writeKey(t, keyFile, srvBKey)
	st.Refresh()
	if !strings.Contains(logs.String(), "reloaded") {
		t.Fatalf("reload not logged: %s", logs.String())
	}
	cliB, cliBKey := newLeaf(t, caB, caBKey, "gateway", false)
	certB := tls.Certificate{Certificate: [][]byte{cliB.Raw}, PrivateKey: cliBKey}
	if leaf, _, err = get(caB, certB); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if !leaf.Equal(srvB) {
		t.Fatalf("after rotation the server presented %v", leaf.NotAfter)
	}
	if _, _, err := get(caB, certA); err == nil {
		t.Fatal("client certificate from the old CA still accepted after rotation")
	}

	// A half-written rotation (garbage key) keeps the last good set.
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	st.Refresh()
	st.Refresh()
	if n := strings.Count(logs.String(), "don't load"); n != 1 {
		t.Fatalf("load error logged %d times, want once", n)
	}
	if leaf, _, err = get(caB, certB); err != nil || !leaf.Equal(srvB) {
		t.Fatalf("bad files replaced the working certificate: %v", err)
	}

	var m bytes.Buffer
	reg.Write(&m)
	if !strings.Contains(m.String(), "neubird_proxy_tls_cert_expiry_days 0.04") {
		t.Fatalf("expiry metric missing or wrong:\n%s", m.String())
	}
	// The test certificates expire within the hour: warned once, not per refresh.
	if n := strings.Count(logs.String(), "expires soon"); n != 1 {
		t.Fatalf("expiry warned %d times, want once", n)
	}
}

func TestServerTLSStartupErrors(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := newCA(t)
	srv, srvKey := newLeaf(t, ca, caKey, "proxy", true)
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePEM(t, certFile, "CERTIFICATE", srv.Raw)
	writeKey(t, keyFile, srvKey)
	empty := filepath.Join(dir, "empty.crt")
	os.WriteFile(empty, []byte("\n"), 0o600)

	for name, c := range map[string]config.TLS{
		"missing key":   {CertFile: certFile, KeyFile: filepath.Join(dir, "nope")},
		"key mismatch":  {CertFile: certFile, KeyFile: certFile},
		"empty CA file": {CertFile: certFile, KeyFile: keyFile, ClientCAFile: empty},
	} {
		if _, err := NewServerTLS(&c, discardLog(), nil); err == nil {
			t.Errorf("%s: started", name)
		}
	}
}
