package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/redact"
)

const (
	token       = "neubird-test-token-0123456789abcdef"
	scopedToken = "scoped-token-for-one-connection-0123"
	oldToken    = "previous-token-being-rotated-out-01"
)

type fixture struct {
	proxy *httptest.Server
	srv   *Server
	logs  *syncBuffer

	mu   sync.Mutex
	last *http.Request // last request seen by the upstream
}

func (f *fixture) lastReq() *http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

// newFixture starts a fake APIM upstream running handler, and a proxy whose
// config is yamlTmpl with UPSTREAM replaced by the upstream's URL.
func newFixture(t *testing.T, yamlTmpl string, handler http.HandlerFunc) *fixture {
	t.Helper()
	f := &fixture{logs: &syncBuffer{}}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.last = r.Clone(r.Context())
		f.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(up.Close)

	yml := strings.ReplaceAll(yamlTmpl, "UPSTREAM", up.URL)
	cfg, err := config.Parse([]byte(yml), func(k string) (string, bool) {
		v, ok := map[string]string{
			"NEUBIRD_PROXY_TOKEN":   token,
			"APIM_SUBSCRIPTION_KEY": "apim-key",
			"SN_USER":               "sn-user",
			"SN_PASS":               "sn-pass",
			"REDACTION_HMAC_KEY":    "hmac-key",
			"SCOPED_TOKEN":          scopedToken,
			"OLD_TOKEN":             oldToken,
		}[k]
		return v, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redact.New(cfg.Redaction)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(f.logs, nil))
	f.srv, err = New(cfg, engine, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.proxy = httptest.NewServer(f.srv)
	t.Cleanup(f.proxy.Close)
	return f
}

const baseConfig = `
client_token_env: NEUBIRD_PROXY_TOKEN
allow_http_upstreams: true
max_body_bytes: 4096
upstream_defaults:
  headers:
    Ocp-Apim-Subscription-Key: ${APIM_SUBSCRIPTION_KEY}
connections:
  - name: splunk
    upstream: UPSTREAM/splunk-api
    client_auth: bearer
    methods: [GET, HEAD, POST, DELETE]
  - name: servicenow
    upstream: UPSTREAM/servicenow
    client_auth: basic
  - name: maestro
    upstream: UPSTREAM/maestro-mcp
    client_auth: header
    client_auth_header: X-NeuBird-Token
    host: maestro.proxy.test
    methods: [GET, POST]
  - name: direct
    upstream: UPSTREAM
    upstream_basic_auth: {username_env: SN_USER, password_env: SN_PASS}
  - name: elastic
    upstream: UPSTREAM/elastic
    passthrough: true
redaction:
  blocked_key_patterns: ["(?i).*password.*"]
  custom:
    - name: member_id
      regex: "\\bMET[0-9]{9}\\b"
  allowed_values: ["(?i)[a-z0-9._-]+@metlife\\.com"]
`

func (f *fixture) do(t *testing.T, method, path string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, f.proxy.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := f.proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

var bearer = map[string]string{"Authorization": "Bearer " + token}

func jsonHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}
}

func TestRoutingAndCredentialSwap(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{"email":"jane@example.com","svc":"svc@metlife.com","member":"MET123456789","password":"x"}`))
	resp, body := f.do(t, "GET", "/splunk/services/search/jobs?output_mode=json&search=a%20b", map[string]string{
		"Authorization":             "Bearer " + token,
		"Ocp-Apim-Subscription-Key": "attacker-supplied",
		"Accept-Encoding":           "gzip",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	want := `{"email":"[REDACTED:EMAIL]","svc":"svc@metlife.com","member":"[REDACTED:MEMBER_ID]","password":"[REDACTED:SECRET_ASSIGNMENT]"}`
	if body != want {
		t.Fatalf("body\n got %s\nwant %s", body, want)
	}
	if resp.ContentLength != int64(len(want)) {
		t.Fatalf("content-length %d, body %d", resp.ContentLength, len(want))
	}

	up := f.lastReq()
	if up.URL.Path != "/splunk-api/services/search/jobs" || up.URL.RawQuery != "output_mode=json&search=a%20b" {
		t.Fatalf("upstream got %s?%s", up.URL.Path, up.URL.RawQuery)
	}
	if got := up.Header.Get("Ocp-Apim-Subscription-Key"); got != "apim-key" {
		t.Fatalf("subscription key = %q", got)
	}
	if up.Header.Get("Authorization") != "" || up.Header.Get("Accept-Encoding") != "" {
		t.Fatalf("leaked headers upstream: %v", up.Header)
	}
}

func TestEncodedPathPreserved(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	f.do(t, "GET", "/servicenow/api/now/table/a%2Fb", map[string]string{"Authorization": basic("any", token)})
	if got := f.lastReq().URL.RawPath; got != "/servicenow/api/now/table/a%2Fb" {
		t.Fatalf("raw path = %q", got)
	}
}

func basic(user, pass string) string {
	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth(user, pass)
	return r.Header.Get("Authorization")
}

func TestClientAuthModes(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	cases := []struct {
		name string
		path string
		hdr  map[string]string
		want int
	}{
		{"bearer ok", "/splunk/x", bearer, 200},
		{"bearer scheme is case-insensitive", "/splunk/x", map[string]string{"Authorization": "bearer " + token}, 200},
		{"bearer missing", "/splunk/x", nil, 401},
		{"bearer wrong", "/splunk/x", map[string]string{"Authorization": "Bearer nope"}, 401},
		{"bearer sent as basic", "/splunk/x", map[string]string{"Authorization": basic("u", token)}, 401},
		{"basic ok", "/servicenow/x", map[string]string{"Authorization": basic("admin", token)}, 200},
		{"basic wrong", "/servicenow/x", map[string]string{"Authorization": basic("admin", "nope")}, 401},
		{"basic sent as bearer", "/servicenow/x", bearer, 401},
		{"header ok", "/maestro/x", map[string]string{"X-NeuBird-Token": token}, 200},
		{"header wrong", "/maestro/x", map[string]string{"X-NeuBird-Token": "nope"}, 401},
		{"unknown connection", "/nope/x", bearer, 404},
		{"prefix must be a whole segment", "/splunkx/y", bearer, 404},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, body := f.do(t, "GET", c.path, c.hdr)
			if resp.StatusCode != c.want {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, c.want, body)
			}
		})
	}
}

func TestHeaderModeCredentialStripped(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	f.do(t, "GET", "/maestro/x", map[string]string{"X-NeuBird-Token": token})
	if f.lastReq().Header.Get("X-NeuBird-Token") != "" {
		t.Fatal("client credential header forwarded upstream")
	}
}

func TestHostRouting(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	resp, _ := f.do(t, "GET", "/api/v1/plans", map[string]string{"Host": "maestro.proxy.test:8443", "X-NeuBird-Token": token})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := f.lastReq().URL.Path; got != "/maestro-mcp/api/v1/plans" {
		t.Fatalf("upstream path %q", got)
	}
}

func TestUpstreamBasicAuthInjected(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	f.do(t, "GET", "/direct/api/now/table/incident", bearer)
	u, p, ok := f.lastReq().BasicAuth()
	if !ok || u != "sn-user" || p != "sn-pass" {
		t.Fatalf("upstream basic auth = %q %q %v", u, p, ok)
	}
}

func TestFailClosed(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		reason  string
	}{
		{"body too large", jsonHandler(`{"x":"` + strings.Repeat("jane@example.com ", 400) + `"}`), "body_too_large"},
		{"binary content type", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			io.WriteString(w, "jane@example.com")
		}, "unsupported_content_type"},
		{"unparseable content type", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json; ;;")
			io.WriteString(w, "jane@example.com")
		}, "unsupported_content_type"},
		{"brotli", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "br")
			io.WriteString(w, "jane@example.com")
		}, "unsupported_content_encoding"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, baseConfig, c.handler)
			resp, body := f.do(t, "GET", "/splunk/x", bearer)
			if resp.StatusCode != 502 || !strings.Contains(body, c.reason) {
				t.Fatalf("status %d body %s", resp.StatusCode, body)
			}
			if strings.Contains(body, "jane@") {
				t.Fatal("unredacted data in error body")
			}
			if n := f.srv.Metrics.Blocked.Value("splunk", c.reason); n != 1 {
				t.Fatalf("blocked metric = %v", n)
			}
			logs := f.waitForAudit(t)
			if !strings.Contains(logs, `"blocked":"`+c.reason+`"`) {
				t.Fatalf("audit line missing block reason: %s", logs)
			}
		})
	}
}

func TestGzipIsDecodedAndRedacted(t *testing.T) {
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, _ *http.Request) {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		io.WriteString(zw, "user jane@example.com logged in")
		zw.Close()
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(b.Bytes())
	})
	resp, body := f.do(t, "GET", "/splunk/x", bearer)
	if body != "user [REDACTED:EMAIL] logged in" || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("body %q encoding %q", body, resp.Header.Get("Content-Encoding"))
	}
}

func TestTextAndInvalidJSONFallBack(t *testing.T) {
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", r.URL.Query().Get("ct"))
		io.WriteString(w, `<r>jane@example.com</r>`)
	})
	for _, ct := range []string{"application/xml", "application/json", "text/csv", ""} {
		_, body := f.do(t, "GET", "/splunk/x?ct="+ct, bearer)
		if body != "<r>[REDACTED:EMAIL]</r>" {
			t.Fatalf("ct %q: body %q", ct, body)
		}
	}
}

func TestErrorResponsesAreRedacted(t *testing.T) {
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		io.WriteString(w, `{"error":"no user jane@example.com"}`)
	})
	resp, body := f.do(t, "GET", "/splunk/x", bearer)
	if resp.StatusCode != 500 || body != `{"error":"no user [REDACTED:EMAIL]"}` {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
}

func TestPassthrough(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{"email":"jane@example.com"}`))
	_, body := f.do(t, "GET", "/elastic/_search", map[string]string{"Authorization": "Bearer " + token, "Accept-Encoding": "gzip"})
	if body != `{"email":"jane@example.com"}` {
		t.Fatalf("passthrough body changed: %s", body)
	}
	if f.lastReq().Header.Get("Accept-Encoding") != "gzip" {
		t.Fatal("passthrough should keep Accept-Encoding")
	}
}

func TestLocationRewrite(t *testing.T) {
	var upstreamURL string
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("kind") {
		case "abs":
			w.Header().Set("Location", upstreamURL+"/splunk-api/services/search/jobs/123?x=1")
		case "path":
			w.Header().Set("Location", "/splunk-api/services/search/jobs/123")
		case "foreign":
			w.Header().Set("Location", "https://elsewhere.example.com/x")
		}
		w.WriteHeader(201)
	})
	upstreamURL = "http://" + f.lastReqHost(t)
	for kind, want := range map[string]string{
		"abs":     "/splunk/services/search/jobs/123?x=1",
		"path":    "/splunk/services/search/jobs/123",
		"foreign": "https://elsewhere.example.com/x",
	} {
		resp, _ := f.do(t, "POST", "/splunk/services/search/jobs?kind="+kind, bearer)
		if got := resp.Header.Get("Location"); got != want {
			t.Errorf("%s: Location = %q, want %q", kind, got, want)
		}
	}
}

// lastReqHost primes the upstream once to learn its host:port.
func (f *fixture) lastReqHost(t *testing.T) string {
	f.do(t, "GET", "/splunk/", bearer)
	return f.lastReq().Host
}

func TestUpgradeRejected(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	resp, body := f.do(t, "GET", "/splunk/ws", map[string]string{
		"Authorization": "Bearer " + token, "Connection": "Upgrade", "Upgrade": "websocket",
	})
	if resp.StatusCode != 400 || !strings.Contains(body, "upgrade_not_supported") {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if f.lastReq() != nil {
		t.Fatal("upgrade request reached upstream")
	}
}

func TestUpstreamDown(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	f.srv.cfg.Connections[0].UpstreamURL.Host = "127.0.0.1:1"
	resp, body := f.do(t, "GET", "/splunk/x", bearer)
	if resp.StatusCode != 502 || !strings.Contains(body, "upstream_unavailable") {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
}

func TestAuditAndMetrics(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{"a":"jane@example.com","b":"bob@example.com","c":"MET123456789"}`))
	f.do(t, "GET", "/splunk/services/x", bearer)
	logs := f.waitForAudit(t)
	for _, want := range []string{`"connection":"splunk"`, `"status":200`, `"redactions":3`, `"email":2`, `"member_id":1`, `"path":"/services/x"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("audit line missing %s: %s", want, logs)
		}
	}
	if strings.Contains(logs, "jane@") || strings.Contains(logs, "MET123456789") || strings.Contains(logs, token) {
		t.Fatalf("audit line leaks values: %s", logs)
	}
	if f.srv.Metrics.Redactions.Value("splunk", "email") != 2 || f.srv.Metrics.Requests.Value("splunk", "200") != 1 {
		t.Fatal("metrics not updated")
	}
	var b strings.Builder
	f.srv.Metrics.Registry.Write(&b)
	if !strings.Contains(b.String(), `neubird_proxy_redactions_total{connection="splunk",rule="email"} 2`) {
		t.Fatalf("exposition: %s", b.String())
	}
}

// MCP over SSE: each event must reach the client, redacted, before the
// upstream sends the next one.
func TestSSEStreamsThroughProxy(t *testing.T) {
	next := make(chan struct{})
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: message\ndata: {\"result\":{\"text\":\"owner jane@example.com\"}}\n\n")
		w.(http.Flusher).Flush()
		<-next
		io.WriteString(w, "data: {\"result\":{\"text\":\"MET123456789\"}}\n\n")
	})
	req, _ := http.NewRequest("POST", f.proxy.URL+"/maestro/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call"}`))
	req.Header.Set("X-NeuBird-Token", token)
	resp, err := f.proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)

	readEvent := func() string {
		var ev strings.Builder
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				line, err := br.ReadString('\n')
				ev.WriteString(line)
				if line == "\n" || err != nil {
					return
				}
			}
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("event not streamed; proxy is buffering")
		}
		return ev.String()
	}

	if got := readEvent(); got != "event: message\ndata: {\"result\":{\"text\":\"owner [REDACTED:EMAIL]\"}}\n\n" {
		t.Fatalf("first event %q", got)
	}
	close(next)
	if got := readEvent(); got != "data: {\"result\":{\"text\":\"[REDACTED:MEMBER_ID]\"}}\n\n" {
		t.Fatalf("second event %q", got)
	}
}

// waitForAudit returns the logs once the audit line is written. It is
// written after the handler returns, which can trail the client's read.
func (f *fixture) waitForAudit(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		logs := f.logs.String()
		if strings.Contains(logs, `"msg":"request"`) || time.Now().After(deadline) {
			return logs
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
