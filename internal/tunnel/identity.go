// Package tunnel connects the proxy out to NeuBird relays and serves
// NeuBird's requests over those connections, so a customer needs no
// inbound path. The wire contract is docs/tunnel-protocol.md.
package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

// ALPN is the protocol both sides must negotiate (docs/tunnel-protocol.md).
const ALPN = "neubird-tunnel/1"

const trustDomain = "neubird.ai"

var label = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// FormatID builds the SPIFFE ID a proxy certificate carries.
func FormatID(tenant, proxy string) (string, error) {
	if !label.MatchString(tenant) || !label.MatchString(proxy) {
		return "", fmt.Errorf("tenant and proxy must be DNS labels (lower case, digits, hyphens), got %q and %q", tenant, proxy)
	}
	return "spiffe://" + trustDomain + "/tenant/" + tenant + "/proxy/" + proxy, nil
}

// ParseID reads tenant and proxy names from a SPIFFE ID, strictly.
func ParseID(id string) (tenant, proxy string, err error) {
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "spiffe" || u.Host != trustDomain || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", "", fmt.Errorf("not a %s SPIFFE ID: %q", trustDomain, id)
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "tenant" || parts[3] != "proxy" ||
		!label.MatchString(parts[2]) || !label.MatchString(parts[4]) {
		return "", "", fmt.Errorf("SPIFFE ID must be spiffe://%s/tenant/<tenant>/proxy/<proxy>, got %q", trustDomain, id)
	}
	return parts[2], parts[4], nil
}

// Identity is the proxy's tunnel identity, loaded and checked.
type Identity struct {
	Certificate tls.Certificate
	Leaf        *x509.Certificate
	RelayCAs    *x509.CertPool
	Tenant      string
	Proxy       string
}

// Load reads the certificate, key and relay CA from cfg's files and checks
// them, so a bad file fails at startup with a clear message instead of as
// a stream of handshake errors.
func Load(cfg *config.Tunnel) (*Identity, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tunnel certificate or key: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("tunnel certificate: %w", err)
	}
	cert.Leaf = leaf
	if len(leaf.URIs) != 1 {
		return nil, fmt.Errorf("tunnel certificate must have exactly one URI SAN (the SPIFFE ID), has %d", len(leaf.URIs))
	}
	tenant, proxy, err := ParseID(leaf.URIs[0].String())
	if err != nil {
		return nil, fmt.Errorf("tunnel certificate: %w", err)
	}
	if !hasClientAuth(leaf) {
		return nil, errors.New("tunnel certificate lacks the clientAuth extended key usage")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("tunnel certificate is valid %s to %s, not now", leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("tunnel.ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tunnel.ca_file: no certificates in %s", cfg.CAFile)
	}
	return &Identity{Certificate: cert, Leaf: leaf, RelayCAs: pool, Tenant: tenant, Proxy: proxy}, nil
}

func hasClientAuth(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

// DaysLeft is how long until the certificate expires.
func (id *Identity) DaysLeft() float64 { return time.Until(id.Leaf.NotAfter).Hours() / 24 }
