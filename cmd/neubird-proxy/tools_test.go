package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const testToken = "tools-test-token-0123456789abcdef0123"

func runCmd(t *testing.T, cmd func([]string, io.Writer, io.Writer) int, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut strings.Builder
	code := cmd(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// mockUpstream answers like a backend that wants upstream credential
// "backend-secret": an MCP server at /mcp, and JSON with PII elsewhere.
func mockUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Backend-Key") != "backend-secret" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			io.WriteString(w, `{"message":"bad key"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/mcp" {
			var msg struct{ Method string }
			json.NewDecoder(r.Body).Decode(&msg)
			switch msg.Method {
			case "initialize":
				w.Header().Set("Mcp-Session-Id", "s1")
				io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"Mock","version":"9"}}}`)
			case "tools/list":
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"get_info\"},{\"name\":\"run_query\"},{\"name\":\"delete_all\"}]}}\n\n")
			default:
				w.WriteHeader(202)
			}
			return
		}
		io.WriteString(w, `{"owner":"jane@example.com","host":"app-1"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func toolsConfig(t *testing.T, upstream string) string {
	return writeFile(t, "config.yaml", `
client_token_env: PROXY_TOKEN
allow_http_upstreams: true
connections:
  - name: api
    upstream: `+upstream+`
    headers: {X-Backend-Key: "${BACKEND_KEY}"}
  - name: mcp
    upstream: `+upstream+`
    methods: [POST]
    paths: [/mcp]
    headers: {X-Backend-Key: "${BACKEND_KEY}"}
    mcp_tools: [get_info, run_query, renamed_tool]
`)
}

func envFile(t *testing.T, backendKey string) string {
	return writeFile(t, "secrets.env", "# test secrets\nexport PROXY_TOKEN="+testToken+"\nBACKEND_KEY='"+backendKey+"'\n")
}

func TestValidateOfflineAndMissingSecrets(t *testing.T) {
	cfg := toolsConfig(t, "http://127.0.0.1:1")
	code, out, _ := runCmd(t, cmdValidate, "-config", cfg)
	if code != 1 || !strings.Contains(out, "PROXY_TOKEN is not set") || !strings.Contains(out, "-offline") {
		t.Fatalf("code %d out %s", code, out)
	}
	code, out, _ = runCmd(t, cmdValidate, "-offline", "-config", cfg)
	if code != 0 || !strings.Contains(out, "VALID") || !strings.Contains(out, "not checked (offline, placeholders used): BACKEND_KEY, PROXY_TOKEN") {
		t.Fatalf("code %d out %s", code, out)
	}
	for _, want := range []string{"api ", "mcp ", "allow_http_upstreams is set", "connection api: no paths allowlist"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	code, out, _ = runCmd(t, cmdValidate, "-config", cfg, "-env-file", envFile(t, "k"))
	if code != 0 || strings.Contains(out, "not checked") {
		t.Fatalf("with env file: code %d out %s", code, out)
	}
}

func TestValidateReportsEverythingAtOnce(t *testing.T) {
	cfg := writeFile(t, "bad.yaml", "client_token_env: T\nconnections:\n  - {name: a, upstream: 'http://x', methods: [TRACE]}\n"+
		"redaction: {custom: [{name: bad, regex: '(?=x)'}]}\n")
	code, out, _ := runCmd(t, cmdValidate, "-offline", "-config", cfg)
	if code != 1 {
		t.Fatalf("code %d", code)
	}
	for _, want := range []string{"plain http", `unsupported method "TRACE"`, "redaction.custom[0] (bad)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestTestCommand(t *testing.T) {
	up := mockUpstream(t)
	cfg := toolsConfig(t, up.URL)

	code, out, _ := runCmd(t, cmdTest, "-config", cfg, "-env-file", envFile(t, "backend-secret"))
	if code != 0 {
		t.Fatalf("code %d:\n%s", code, out)
	}
	for _, want := range []string{
		"ok    dns", "ok    tcp", "warn  tls        plain http",
		"ok    request    HTTP 200, application/json", "redactions: email 1",
		"info  server     Mock 9", "ok    tools      2 of 3 server tools allowed: get_info, run_query",
		"blocked by mcp_tools: delete_all", "not offered by the server (typo or renamed?): renamed_tool",
		"all 2 connections OK",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, testToken) || strings.Contains(out, "backend-secret") {
		t.Fatal("a secret was printed")
	}

	// Wrong backend credential: the upstream says 401.
	code, out, _ = runCmd(t, cmdTest, "-config", cfg, "-env-file", envFile(t, "wrong"), "api")
	if code != 1 || !strings.Contains(out, "rejected the credentials") {
		t.Fatalf("bad credential: code %d:\n%s", code, out)
	}

	// The proxy's own policy refuses the probe.
	code, out, _ = runCmd(t, cmdTest, "-config", cfg, "-env-file", envFile(t, "backend-secret"), "-path", "/other", "mcp")
	if code != 1 || !strings.Contains(out, "refused by the proxy: path_not_allowed") || !strings.Contains(out, "pass -path") {
		t.Fatalf("policy: code %d:\n%s", code, out)
	}

	code, out, _ = runCmd(t, cmdTest, "-config", cfg, "-env-file", envFile(t, "backend-secret"), "-show", "api")
	if code != 0 || !strings.Contains(out, `"owner":"[REDACTED:EMAIL]"`) {
		t.Fatalf("-show: code %d:\n%s", code, out)
	}
}

func TestTestCommandNetworkFailures(t *testing.T) {
	for name, c := range map[string]struct{ upstream, want string }{
		"dns": {"http://nonexistent-host.invalid", "FAIL  dns"},
		"tcp": {"http://127.0.0.1:1", "FAIL  tcp"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := toolsConfig(t, c.upstream)
			code, out, _ := runCmd(t, cmdTest, "-config", cfg, "-env-file", envFile(t, "k"), "api")
			if code != 1 || !strings.Contains(out, c.want) || !strings.Contains(out, "1 of 1 connections FAILED") {
				t.Fatalf("code %d:\n%s", code, out)
			}
		})
	}
}

func TestTestCommandTLS(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer up.Close()
	cfg := writeFile(t, "config.yaml", "client_token_env: PROXY_TOKEN\nconnections:\n  - {name: api, upstream: '"+up.URL+"'}\n")
	code, out, _ := runCmd(t, cmdTest, "-config", cfg, "-env-file", envFile(t, "k"))
	if code != 1 || !strings.Contains(out, "FAIL  tls") || !strings.Contains(out, "set upstream_ca_file") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestPreviewSample(t *testing.T) {
	cfg := toolsConfig(t, "http://127.0.0.1:1") // never contacted: the sample is served locally
	sample := writeFile(t, "sample.json", `{"user":"jane@example.com","note":"<script>alert(1)</script> ssn 219-09-9999","host":"app-1"}`)
	report := filepath.Join(t.TempDir(), "report.html")

	code, out, _ := runCmd(t, cmdPreview, "-config", cfg, "-connection", "api", "-html", report, sample)
	if code != 0 {
		t.Fatalf("code %d:\n%s", code, out)
	}
	for _, pat := range []string{
		`2 -\s+"user": "jane@example\.com"`, `\+\s+"user": "\[REDACTED:EMAIL\]"`,
		`redactions: email 1, us_ssn 1`, `report written`,
	} {
		matches(t, out, pat)
	}
	html, _ := os.ReadFile(report)
	if strings.Contains(string(html), "<script>alert(1)</script>") {
		t.Fatal("report does not escape the sample")
	}
	if !strings.Contains(string(html), `<span class="m">[REDACTED:EMAIL]</span>`) || !strings.Contains(string(html), "unredacted data") {
		t.Fatalf("report:\n%s", html)
	}

	// -html - writes only the report.
	code, out, _ = runCmd(t, cmdPreview, "-config", cfg, "-connection", "api", "-html", "-", sample)
	if code != 0 || !strings.HasPrefix(out, "<!doctype html>") {
		t.Fatalf("-html -: code %d, starts %.40q", code, out)
	}

	// Several connections and none picked.
	if code, _, errOut := runCmd(t, cmdPreview, "-config", cfg, sample); code != 2 || !strings.Contains(errOut, "-connection") {
		t.Fatalf("code %d %s", code, errOut)
	}
}

func TestPreviewRefusedAndText(t *testing.T) {
	cfg := toolsConfig(t, "http://127.0.0.1:1")
	bin := writeFile(t, "blob", "\x1f\x8b\x08\x00binary")
	code, out, _ := runCmd(t, cmdPreview, "-config", cfg, "-connection", "api", "-content-type", "text/plain", bin)
	if code != 0 || !strings.Contains(out, "REFUSED") || !strings.Contains(out, "not_text") {
		t.Fatalf("code %d:\n%s", code, out)
	}
	log := writeFile(t, "a.log", "ok line\nuser=jane%40example.com\nlast line\n")
	code, out, _ = runCmd(t, cmdPreview, "-config", cfg, "-connection", "api", log)
	if code != 0 || !strings.Contains(out, "text/plain") || !strings.Contains(out, "+ user=[REDACTED:EMAIL]") {
		t.Fatalf("code %d:\n%s", code, out)
	}
}

func TestPreviewLive(t *testing.T) {
	up := mockUpstream(t)
	cfg := toolsConfig(t, up.URL)
	code, out, _ := runCmd(t, cmdPreview, "-config", cfg, "-env-file", envFile(t, "backend-secret"), "-connection", "api", "-live", "-path", "/x")
	if code != 0 {
		t.Fatalf("code %d:\n%s", code, out)
	}
	matches(t, out, `-\s+"owner": "jane@example\.com"`)
	matches(t, out, `\+\s+"owner": "\[REDACTED:EMAIL\]"`)
	code, _, errOut := runCmd(t, cmdPreview, "-config", cfg, "-env-file", envFile(t, "wrong"), "-connection", "api", "-live")
	if code != 1 || !strings.Contains(errOut, "HTTP 401") {
		t.Fatalf("bad credential: code %d %s", code, errOut)
	}
}

func TestToken(t *testing.T) {
	_, a, _ := runCmd(t, cmdToken)
	_, b, _ := runCmd(t, cmdToken)
	if !regexp.MustCompile(`^[0-9a-f]{64}\n$`).MatchString(a) || a == b {
		t.Fatalf("tokens %q %q", a, b)
	}
	if code, _, errOut := runCmd(t, cmdToken, "-bytes", "8"); code != 2 || !strings.Contains(errOut, "at least 32") {
		t.Fatalf("short token: %d %s", code, errOut)
	}
}

func TestMetricsCommand(t *testing.T) {
	pod := `# HELP neubird_proxy_requests_total x
neubird_proxy_requests_total{connection="splunk",code="200"} 5
neubird_proxy_requests_total{connection="splunk",code="405"} 2
neubird_proxy_redactions_total{connection="splunk",rule="email"} 3
neubird_proxy_blocked_total{connection="splunk",reason="method_not_allowed"} 2
neubird_proxy_response_bytes_total{connection="splunk"} 1000
`
	a, b := writeFile(t, "a.txt", pod), writeFile(t, "b.txt", pod)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, pod) }))
	defer srv.Close()
	code, out, _ := runCmd(t, cmdMetrics, a, b, srv.URL)
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	for _, pat := range []string{`Requests \(total 21\)`, `15\s+splunk\s+200`, `6\s+splunk\s+405`, `Redactions \(total 9\)`,
		`Blocked \(total 6\)`, `Response bytes \(total 3000\)`} {
		matches(t, out, pat)
	}
	if got := parseLabels(`{a="x\"y",b="c\\d\ne"}`); got["a"] != `x"y` || got["b"] != "c\\d\ne" {
		t.Fatalf("labels %q", got)
	}
}

func matches(t *testing.T, out, pattern string) {
	t.Helper()
	if !regexp.MustCompile(pattern).MatchString(out) {
		t.Errorf("no match for %s in:\n%s", pattern, out)
	}
}
