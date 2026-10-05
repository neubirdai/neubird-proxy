package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/neubirdai/neubird-proxy/internal/tunnel"
)

// cmdCSR generates the tunnel's private key and a certificate signing
// request for NeuBird to sign. The key stays here; only the CSR is sent.
func cmdCSR(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("csr", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant name NeuBird gave you (required)")
	proxyName := fs.String("proxy", "", "a name for this proxy deployment, e.g. aks-prod (required)")
	keyOut := fs.String("key-out", "tunnel.key", "where to write the private key (never send this)")
	csrOut := fs.String("csr-out", "tunnel.csr", "where to write the CSR (send this to NeuBird)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: neubird-proxy csr -tenant <tenant> -proxy <name> [-key-out tunnel.key] [-csr-out tunnel.csr]")
		fmt.Fprintln(stderr, "\nGenerates the tunnel key and a certificate signing request. Send NeuBird the CSR only.")
		fs.PrintDefaults()
	}
	if fs.Parse(args) != nil {
		return 2
	}
	id, err := tunnel.FormatID(*tenant, *proxyName)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	for _, f := range []string{*keyOut, *csrOut} {
		if _, err := os.Stat(f); err == nil {
			fmt.Fprintf(stderr, "error: %s exists; refusing to overwrite (move it away first)\n", f)
			return 1
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	uri, _ := url.Parse(id)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: *proxyName + "." + *tenant},
		URIs:    []*url.URL{uri},
	}, key)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if err := os.WriteFile(*keyOut, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if err := os.WriteFile(*csrOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o644); err != nil {
		os.Remove(*keyOut)
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(stdout, "identity: %s\n", id)
	fmt.Fprintf(stdout, "private key: %s (keep it here; store it in the proxy's Secret)\n", *keyOut)
	fmt.Fprintf(stdout, "CSR:         %s (send this to NeuBird)\n", *csrOut)
	fmt.Fprintln(stdout, "\nNeuBird returns a signed certificate and its relay CA. Put the key, certificate and CA")
	fmt.Fprintln(stdout, "in a Secret and point tunnel.key_file, tunnel.cert_file and tunnel.ca_file at them.")
	return 0
}
