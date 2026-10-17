package tunnel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/metrics"
)

// Without cert_file, the proxy mints its own certificate from the key:
// self-signed, naming tenant/proxy, for client authentication only.
func TestLoadMintsFromKey(t *testing.T) {
	p := newPKI(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	cfg := &config.Tunnel{Tenant: "metlife", Proxy: "aks-prod", KeyFile: p.write(t, "k.pem", "EC PRIVATE KEY", der), CAFile: p.caFile}
	id, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	leaf := id.Leaf
	if !id.Minted || id.Tenant != "metlife" || id.Proxy != "aks-prod" {
		t.Fatalf("identity %+v", id)
	}
	// Without tenant and proxy the minted certificate names nothing (no
	// URI SAN): the relay knows the proxy by its key.
	anon, err := Load(&config.Tunnel{KeyFile: cfg.KeyFile, CAFile: p.caFile})
	if err != nil {
		t.Fatal(err)
	}
	if anon.Tenant != "" || anon.Proxy != "" || !anon.Minted || len(anon.Leaf.URIs) != 0 ||
		anon.Leaf.Subject.CommonName != "neubird-proxy" || anon.Fingerprint != id.Fingerprint || !hasClientAuth(anon.Leaf) {
		t.Fatalf("unnamed: %+v", anon)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://neubird.ai/tenant/metlife/proxy/aks-prod" ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || leaf.IsCA {
		t.Fatalf("minted: URIs %v EKU %v CA %v", leaf.URIs, leaf.ExtKeyUsage, leaf.IsCA)
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil || !bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		t.Fatalf("not self-signed: %v", err)
	}
	if d := leaf.NotAfter.Sub(time.Now()); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Fatalf("valid for %v", d)
	}
	want, _ := Fingerprint(&k.PublicKey)
	if id.Fingerprint != want || !strings.HasPrefix(want, "sha256:") || len(want) != 71 {
		t.Fatalf("fingerprint %q, want %q", id.Fingerprint, want)
	}
	again, _ := Load(cfg)
	if again.Fingerprint != id.Fingerprint || bytes.Equal(again.Leaf.Raw, id.Leaf.Raw) {
		t.Fatal("a reload should mint a new certificate for the same key")
	}

	// PKCS #8 and RSA keys load too; a certificate file is not a key.
	p8, _ := x509.MarshalPKCS8PrivateKey(k)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, f := range map[string]string{
		"pkcs8": p.write(t, "k8.pem", "PRIVATE KEY", p8),
		"rsa":   p.write(t, "kr.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk)),
	} {
		if _, err := Load(&config.Tunnel{Tenant: "metlife", Proxy: "aks-prod", KeyFile: f, CAFile: p.caFile}); err != nil {
			t.Errorf("%s key: %v", name, err)
		}
	}
	if _, err := Load(&config.Tunnel{Tenant: "metlife", Proxy: "aks-prod", KeyFile: p.caFile, CAFile: p.caFile}); err == nil || !strings.Contains(err.Error(), "not a private key") {
		t.Fatalf("certificate as key: %v", err)
	}
	if _, err := Load(&config.Tunnel{Tenant: "Met Life", Proxy: "aks-prod", KeyFile: cfg.KeyFile, CAFile: p.caFile}); err == nil {
		t.Fatal("bad tenant name accepted")
	}
}

// A cert_file must agree with tenant/proxy when both are given.
func TestLoadCertFileMustMatchNames(t *testing.T) {
	p := newPKI(t)
	cfg := p.proxyConfig(t, "relay.test:443") // a cert for metlife/aks-prod
	cfg.Tenant, cfg.Proxy = "metlife", "aks-dev"
	if _, err := Load(cfg); err == nil || !strings.Contains(err.Error(), "cert_file is for metlife/aks-prod") {
		t.Fatalf("mismatch: %v", err)
	}
	cfg.Proxy = "aks-prod"
	if id, err := Load(cfg); err != nil || id.Minted {
		t.Fatalf("matching names: %v", err)
	}
}

// Re-minting on every connect is routine: the client logs a reload only
// when the key or relay CA changes.
func TestMintedReloadIsQuiet(t *testing.T) {
	p := newPKI(t)
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	keyFile := filepath.Join(dir, "k.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
	cfg := &config.Tunnel{Relays: []string{"relay.test:443"}, Tenant: "metlife", Proxy: "aks-prod", KeyFile: keyFile, CAFile: p.caFile, ConnectionsPerRelay: 1}
	id, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	c := New(cfg, id, nil, slog.New(slog.NewTextHandler(&logs, nil)), &metrics.Registry{})
	for i := 0; i < 3; i++ {
		if _, err := c.identity(); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(logs.String(), "reloaded") || strings.Contains(logs.String(), "expires soon") {
		t.Fatalf("noisy reload:\n%s", logs.String())
	}
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der2, _ := x509.MarshalECPrivateKey(k2)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der2}), 0o600)
	if _, err := c.identity(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "reloaded") {
		t.Fatalf("a new key wasn't logged:\n%s", logs.String())
	}
}
