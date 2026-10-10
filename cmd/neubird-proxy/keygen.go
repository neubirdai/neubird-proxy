package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/neubirdai/neubird-proxy/internal/tunnel"
)

// cmdKeygen makes the proxy's tunnel key. The key never leaves the
// cluster; NeuBird records only its fingerprint, which isn't secret. The
// proxy mints its own certificate from the key, so there's nothing to sign
// or renew.
func cmdKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant name NeuBird gave you (required)")
	proxyName := fs.String("proxy", "", "a name for this proxy deployment, e.g. aks-prod (required)")
	keyOut := fs.String("key-out", "tunnel.key", "where to write the private key (never send this)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: neubird-proxy keygen -tenant <tenant> -proxy <name> [-key-out tunnel.key]")
		fmt.Fprintln(stderr, "\nMakes the tunnel key and prints its fingerprint. Send NeuBird the fingerprint only.")
		fs.PrintDefaults()
	}
	if fs.Parse(args) != nil {
		return 2
	}
	if _, err := tunnel.FormatID(*tenant, *proxyName); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if _, err := os.Stat(*keyOut); err == nil {
		fmt.Fprintf(stderr, "error: %s exists; refusing to overwrite (move it away first)\n", *keyOut)
		return 1
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if err := os.WriteFile(*keyOut, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	fp, _ := tunnel.Fingerprint(&key.PublicKey)
	fmt.Fprintf(stdout, "key:         %s (keep it here; store it in the proxy's Secret)\n", *keyOut)
	fmt.Fprintf(stdout, "fingerprint: %s\n", fp)
	fmt.Fprintf(stdout, "\nSend NeuBird the fingerprint; it isn't secret. NeuBird records it for %s/%s and\n", *tenant, *proxyName)
	fmt.Fprintln(stdout, "sends back the relay CA certificate and hostname. Then, in the proxy config:")
	fmt.Fprintf(stdout, "\n  tunnel:\n    relays: [\"%s.tunnel.neubird.ai:443\"]\n    tenant: %s\n    proxy: %s\n", *tenant, *tenant, *proxyName)
	fmt.Fprintln(stdout, "    key_file: /etc/neubird-proxy/tunnel/tunnel.key\n    ca_file: /etc/neubird-proxy/tunnel/relay-ca.crt")
	return 0
}

// cmdFingerprint prints the fingerprint of a key or certificate file, for
// recording a proxy that already has one.
func cmdFingerprint(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] == "-h" || args[0] == "-help" {
		fmt.Fprintln(stderr, "usage: neubird-proxy fingerprint <key or certificate file>")
		return 2
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if b, _ := pem.Decode(raw); b != nil && b.Type == "CERTIFICATE" {
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		fp, _ := tunnel.Fingerprint(c.PublicKey)
		fmt.Fprintln(stdout, fp)
		return 0
	}
	key, err := tunnel.LoadKey(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	fp, err := tunnel.Fingerprint(key.Public())
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	fmt.Fprintln(stdout, fp)
	return 0
}
