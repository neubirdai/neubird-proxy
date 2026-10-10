// Package tunnel connects the proxy out to NeuBird relays and serves
// NeuBird's requests over those connections, so a customer needs no
// inbound path. The wire contract is docs/tunnel-protocol.md.
package tunnel

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
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
	// Fingerprint names the key: "sha256:" and the hex SHA-256 of its DER
	// SubjectPublicKeyInfo. The relay accepts the proxy only if NeuBird has
	// it on record.
	Fingerprint string
	// Minted: the certificate was made here, from the key, not read from
	// cert_file.
	Minted bool
}

// mintValidity is how long a minted certificate is valid. It is re-minted
// on every load (each connect, and hourly), so it never gets near expiry;
// a tunnel open that long is drained by the relay and reconnects.
const mintValidity = 90 * 24 * time.Hour

// Load reads the key (and certificate, if cert_file is set) and the relay
// CA, and checks them, so a bad file fails at startup with a clear message
// instead of as a stream of handshake errors. Without cert_file it mints a
// self-signed certificate for tenant/proxy from the key.
func Load(cfg *config.Tunnel) (*Identity, error) {
	var cert tls.Certificate
	minted := cfg.CertFile == ""
	if minted {
		key, err := LoadKey(cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		id, err := FormatID(cfg.Tenant, cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("tunnel: %w", err)
		}
		if cert, err = Mint(key, id, time.Now()); err != nil {
			return nil, fmt.Errorf("tunnel certificate: %w", err)
		}
	} else {
		var err error
		if cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
			return nil, fmt.Errorf("tunnel certificate or key: %w", err)
		}
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
	if (cfg.Tenant != "" && cfg.Tenant != tenant) || (cfg.Proxy != "" && cfg.Proxy != proxy) {
		return nil, fmt.Errorf("tunnel: tenant/proxy %s/%s, but cert_file is for %s/%s", cfg.Tenant, cfg.Proxy, tenant, proxy)
	}
	if !hasClientAuth(leaf) {
		return nil, errors.New("tunnel certificate lacks the clientAuth extended key usage")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("tunnel certificate is valid %s to %s, not now", leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	}
	fp, err := Fingerprint(leaf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("tunnel key: %w", err)
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("tunnel.ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tunnel.ca_file: no certificates in %s", cfg.CAFile)
	}
	return &Identity{Certificate: cert, Leaf: leaf, RelayCAs: pool, Tenant: tenant, Proxy: proxy, Fingerprint: fp, Minted: minted}, nil
}

// Mint makes a self-signed client certificate for the SPIFFE ID id, from
// key, valid from an hour before now for mintValidity.
func Mint(key crypto.Signer, id string, now time.Time) (tls.Certificate, error) {
	uri, err := url.Parse(id)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: strings.TrimPrefix(id, "spiffe://"+trustDomain+"/")},
		URIs:         []*url.URL{uri},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(mintValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// LoadKey reads a PEM private key: EC (SEC 1), PKCS #8 or RSA (PKCS #1).
func LoadKey(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tunnel key: %w", err)
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		return nil, fmt.Errorf("tunnel key: %s is not PEM", path)
	}
	var k any
	switch b.Type {
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(b.Bytes)
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	default:
		return nil, fmt.Errorf("tunnel key: %s holds a %q, not a private key", path, b.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("tunnel key: %w", err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("tunnel key: unsupported key type %T", k)
	}
	return s, nil
}

// Fingerprint names a public key as NeuBird's tenant records pin it:
// "sha256:" and the lowercase hex SHA-256 of its DER SubjectPublicKeyInfo.
func Fingerprint(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
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
