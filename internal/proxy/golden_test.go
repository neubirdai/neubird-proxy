package proxy

import (
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// goldenConfig mirrors the proposal's example config, with every builtin on.
const goldenConfig = `
client_token_env: NEUBIRD_PROXY_TOKEN
allow_http_upstreams: true
upstream_defaults:
  headers:
    Ocp-Apim-Subscription-Key: ${APIM_SUBSCRIPTION_KEY}
connections:
  - name: splunk
    upstream: UPSTREAM/splunk
  - name: servicenow
    upstream: UPSTREAM/servicenow
    client_auth: basic
  - name: maestro
    upstream: UPSTREAM/maestro-mcp
redaction:
  blocked_key_patterns: ["(?i).*ssn.*", "(?i).*password.*", "(?i).*dob.*"]
  custom:
    - name: member_id
      regex: "\\bMET[0-9]{9}\\b"
  allowed_values: ["(?i)[a-z0-9._-]+@metlife\\.com"]
`

// Golden tests run synthetic PII for each pilot connection through the
// full proxy. Review testdata/golden/*.golden when rules change; run
// go test ./internal/proxy -run Golden -update to regenerate.
func TestGolden(t *testing.T) {
	cases := []struct {
		file, conn, contentType string
		auth                    map[string]string
		mustKeep                []string
	}{
		{"splunk_export.json", "splunk", "application/json", bearer,
			[]string{"svc-claims@metlife.com", "latency_ms=41", "build=4.12.1", "2026-09-30T14:02:11.000+00:00"}},
		{"servicenow_table.json", "servicenow", "application/json", map[string]string{"Authorization": basic("neubird", token)},
			[]string{"6816f79cc0a8016401c5a33be04be441", "INC0010042", "svc-snow@metlife.com", `"reopen_count":0`, `"close_notes":null`}},
		{"maestro_mcp.sse", "maestro", "text/event-stream", bearer,
			[]string{"CLAIMS_NIGHTLY_03", "ABEND", ": keepalive"}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join("testdata", "golden", c.file))
			if err != nil {
				t.Fatal(err)
			}
			f := newFixture(t, goldenConfig, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", c.contentType)
				w.Write(in)
			})
			resp, got := f.do(t, "GET", "/"+c.conn+"/x", c.auth)
			if resp.StatusCode != 200 {
				t.Fatalf("status %d: %s", resp.StatusCode, got)
			}

			for _, pii := range []string{
				"j.rivera@example.com", "(212) 555-0147", "10.44.8.21", "4111-1111-1111-1111", "219-09-9999",
				"MET104938271", "MET220019384", "dana.whitfield@example.org", "646-555-0192", "219099999",
				"1984-03-17", "5500 0000 0000 0004", "10.12.0.44", "ops-oncall@example.com", "(917) 555-0110",
				"MET553201877", "s3cr3t!",
			} {
				if strings.Contains(got, pii) {
					t.Errorf("PII %q survived redaction", pii)
				}
			}
			for _, keep := range c.mustKeep {
				if !strings.Contains(got, keep) {
					t.Errorf("non-PII %q was lost", keep)
				}
			}
			if c.contentType == "application/json" {
				dec := json.NewDecoder(strings.NewReader(got))
				for {
					var v any
					if err := dec.Decode(&v); err == io.EOF {
						break
					} else if err != nil {
						t.Fatalf("redacted body is not valid JSON: %v", err)
					}
				}
			}

			golden := filepath.Join("testdata", "golden", c.file+".golden")
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update to create)", err)
			}
			if got != string(want) {
				t.Errorf("output differs from %s\n got: %s\nwant: %s", golden, got, want)
			}
		})
	}
}
