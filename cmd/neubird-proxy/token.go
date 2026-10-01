package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

// cmdToken prints a new random token for client_token_env (or the HMAC
// key). It prints nothing else, so it can go straight into a Secret:
//
//	kubectl create secret generic neubird-proxy --from-literal=NEUBIRD_PROXY_TOKEN="$(neubird-proxy token)" ...
func cmdToken(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	n := fs.Int("bytes", 32, "random bytes (printed as twice as many hex characters)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: neubird-proxy token [-bytes 32]")
		fs.PrintDefaults()
	}
	if fs.Parse(args) != nil {
		return 2
	}
	if *n*2 < config.MinTokenLength {
		fmt.Fprintf(stderr, "error: -bytes %d gives %d characters; the proxy requires at least %d\n", *n, *n*2, config.MinTokenLength)
		return 2
	}
	b := make([]byte, *n)
	if _, err := rand.Read(b); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	fmt.Fprintln(stdout, hex.EncodeToString(b))
	return 0
}
