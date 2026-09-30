package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	t.Setenv("NEUBIRD_PROXY_TOKEN", "x")
	t.Setenv("APIM_SUBSCRIPTION_KEY", "x")
	if err := run("../../deploy/config.example.yaml", true, quiet); err != nil {
		t.Fatalf("deploy/config.example.yaml must stay valid: %v", err)
	}
}

func TestStartupFailures(t *testing.T) {
	t.Setenv("T", "x")
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
