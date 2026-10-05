package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestExampleConfigPassesCheck(t *testing.T) {
	t.Setenv("NEUBIRD_PROXY_TOKEN", strings.Repeat("x", 32))
	t.Setenv("NEUBIRD_PROXY_TOKEN_SERVICENOW", strings.Repeat("y", 32))
	t.Setenv("APIM_SUBSCRIPTION_KEY", "x")
	if err := run("../../deploy/config.example.yaml", true, quiet); err != nil {
		t.Fatalf("deploy/config.example.yaml must stay valid: %v", err)
	}
}

func TestStartupFailures(t *testing.T) {
	t.Setenv("T", strings.Repeat("x", 32))
	cases := map[string]struct{ path, want string }{
		"missing file": {"/nonexistent/config.yaml", "no such file"},
		"missing env":  {writeConfig(t, "client_token_env: UNSET_VAR_XYZ\nconnections: [{name: a, upstream: 'https://x'}]\n"), "UNSET_VAR_XYZ is not set"},
		"bad regex": {writeConfig(t, "client_token_env: T\nconnections: [{name: a, upstream: 'https://x'}]\n"+
			"redaction: {custom: [{name: bad, regex: '(?<=x)y'}]}\n"), "redaction.custom[0] (bad)"},
		"unknown builtin": {writeConfig(t, "client_token_env: T\nconnections: [{name: a, upstream: 'https://x'}]\n"+
			"redaction: {builtins: [ssn]}\n"), `unknown rule "ssn"`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := run(c.path, true, quiet)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}

func TestWarnings(t *testing.T) {
	t.Setenv("T", strings.Repeat("x", 32))
	p := writeConfig(t, "client_token_env: T\nallow_http_upstreams: true\nconnections:\n"+
		"  - {name: raw, upstream: 'http://x', passthrough: true}\n"+
		"  - {name: tight, upstream: 'https://x', paths: ['/a']}\n"+
		"  - {name: writes, upstream: 'https://x', paths: ['/a'], methods: [GET, POST]}\n")
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(warnings(cfg), "\n")
	for _, want := range []string{"allow_http_upstreams", "raw: passthrough", "raw: no paths allowlist", "writes: allows POST"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing warning %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "tight") {
		t.Errorf("tight connection should not warn:\n%s", got)
	}
	if h := configHash(p); len(h) != 64 {
		t.Errorf("config hash %q", h)
	}
}

func TestRedactOffline(t *testing.T) {
	// No connection tokens in the environment: -redact must not need them.
	cfg := writeConfig(t, "client_token_env: UNSET_TOKEN_ENV\nconnections: [{name: a, upstream: 'https://x'}]\n"+
		"redaction: {custom: [{name: member_id, regex: '\\bMET[0-9]{9}\\b'}]}\n")
	in := filepath.Join(t.TempDir(), "sample.log")
	os.WriteFile(in, []byte("user jane%40example.com member MET123456789 ssn=219099999\n"), 0o600)
	var out, errOut strings.Builder
	if err := redactOffline(cfg, in, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "user [REDACTED:EMAIL] member [REDACTED:MEMBER_ID] ssn=[REDACTED:US_SSN]\n\n" {
		t.Fatalf("out %q", got)
	}
	if !strings.Contains(errOut.String(), "redactions: 3") {
		t.Fatalf("stderr %q", errOut.String())
	}
	bin := filepath.Join(t.TempDir(), "bin")
	os.WriteFile(bin, []byte{0x1f, 0x8b, 0x08, 0x00, 0xff}, 0o600)
	if err := redactOffline(cfg, bin, &out, &errOut); err == nil || !strings.Contains(err.Error(), "not UTF-8") {
		t.Fatalf("binary input: %v", err)
	}
}

func TestNoInboundTLSWarningWhenListenOff(t *testing.T) {
	t.Setenv("T", strings.Repeat("x", 32))
	p := writeConfig(t, "client_token_env: T\nlisten: \"off\"\nconnections: [{name: a, upstream: 'https://x', paths: ['/a']}]\n"+
		"tunnel: {relays: ['r:443'], cert_file: c, key_file: k, ca_file: ca}\n")
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(warnings(cfg), "\n"); strings.Contains(w, "tls") {
		t.Fatalf("TLS warning with no inbound listener:\n%s", w)
	}
}
