package proxy

import (
	"bufio"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/redact"
)

func TestRequestBodyTooLarge(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	req, _ := http.NewRequest("POST", f.proxy.URL+"/splunk/services/search/jobs", strings.NewReader(strings.Repeat("x", 5000)))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(body), "request_too_large") {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
}

// An oversized SSE event arrives after headers are sent, so the only way
// to fail closed is to cut the stream. Earlier events still arrive.
func TestSSEEventTooLargeCutsStream(t *testing.T) {
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"ok\":\"jane@example.com\"}\n\n")
		w.(http.Flusher).Flush()
		io.WriteString(w, "data: "+strings.Repeat("secret-bob@example.com ", 400))
		w.(http.Flusher).Flush()
		io.WriteString(w, "\n\n")
	})
	req, _ := http.NewRequest("GET", f.proxy.URL+"/splunk/stream", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(bufio.NewReader(resp.Body))
	if readErr == nil {
		t.Fatalf("stream ended cleanly; client cannot tell it was cut. body=%q logs=%s", body, f.waitForAudit(t))
	}
	if string(body) != "data: {\"ok\":\"[REDACTED:EMAIL]\"}\n\n" {
		t.Fatalf("body %q", body)
	}
	logs := f.waitForAudit(t)
	if !strings.Contains(logs, `"blocked":"sse_event_too_large"`) {
		t.Fatalf("audit line missing block reason: %s", logs)
	}
	if f.srv.Metrics.Blocked.Value("splunk", "sse_event_too_large") != 1 {
		t.Fatal("blocked metric not incremented")
	}
}

func TestHeadAndNoContent(t *testing.T) {
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/splunk-api/empty" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream") // would be blocked with a body
		w.Header().Set("Content-Length", "10")
	})
	resp, _ := f.do(t, "HEAD", "/splunk/thing", bearer)
	if resp.StatusCode != 200 {
		t.Fatalf("HEAD status %d", resp.StatusCode)
	}
	resp, _ = f.do(t, "DELETE", "/splunk/empty", bearer)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("204 status %d", resp.StatusCode)
	}
}

func TestHMACThroughProxy(t *testing.T) {
	cfg := baseConfig + "  mask: hmac\n"
	f := newFixture(t, cfg, jsonHandler(`{"a":"jane@example.com","b":"jane@example.com","c":"bob@example.com"}`))
	_, body := f.do(t, "GET", "/splunk/x", bearer)
	var a, b, c string
	if _, err := fmtSscanJSON(body, &a, &b, &c); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	if a != b || a == c || !strings.HasPrefix(a, "[REDACTED:EMAIL:") {
		t.Fatalf("a=%q b=%q c=%q", a, b, c)
	}
}

func fmtSscanJSON(body string, a, b, c *string) (int, error) {
	var v struct{ A, B, C string }
	if err := jsonUnmarshal(body, &v); err != nil {
		return 0, err
	}
	*a, *b, *c = v.A, v.B, v.C
	return 3, nil
}

// MetLife's APIM internal hostname uses an internal CA; upstream_ca_file
// must be trusted, and nothing else changes.
func TestUpstreamCAFile(t *testing.T) {
	up := httptest.NewTLSServer(jsonHandler(`{"email":"jane@example.com"}`))
	defer up.Close()
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	build := func(extra string) (*Server, error) {
		yml := "client_token_env: T\nconnections: [{name: splunk, upstream: '" + up.URL + "'}]\n" + extra
		cfg, err := config.Parse([]byte(yml), func(string) (string, bool) { return token, true })
		if err != nil {
			t.Fatal(err)
		}
		e, _ := redact.New(cfg.Redaction)
		return New(cfg, e, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	}
	call := func(s *Server) *http.Response {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/splunk/x", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		s.ServeHTTP(rec, req)
		return rec.Result()
	}

	untrusted, err := build("")
	if err != nil {
		t.Fatal(err)
	}
	if resp := call(untrusted); resp.StatusCode != 502 {
		t.Fatalf("self-signed upstream accepted without CA file: %d", resp.StatusCode)
	}

	trusted, err := build("upstream_ca_file: " + caFile + "\n")
	if err != nil {
		t.Fatal(err)
	}
	resp := call(trusted)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != `{"email":"[REDACTED:EMAIL]"}` {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}

	if _, err := build("upstream_ca_file: /nonexistent\n"); err == nil {
		t.Fatal("missing CA file accepted")
	}
	junk := filepath.Join(t.TempDir(), "junk.crt")
	os.WriteFile(junk, []byte("not a cert"), 0o600)
	if _, err := build("upstream_ca_file: " + junk + "\n"); err == nil {
		t.Fatal("CA file without certificates accepted")
	}
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

// Regression tests for the Sep 30 review findings.

func TestDotSegmentsRejected(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{"email":"jane@example.com"}`))
	for _, p := range []string{
		"/elastic/../splunk/services/search/jobs/export",
		"/elastic/%2e%2e/splunk/x",
		"/elastic/%252e%252e/splunk/x",
		"/elastic/..%5Csplunk/x",
		"/splunk/./x",
	} {
		req, _ := http.NewRequest("GET", f.proxy.URL, nil)
		req.URL.Opaque = p // send the path exactly as written, uncleaned
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := f.proxy.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 400 || !strings.Contains(string(body), "invalid_path") {
			t.Errorf("%s: status %d body %s", p, resp.StatusCode, body)
		}
	}
	if f.lastReq() != nil {
		t.Fatal("a dot-segment request reached the upstream")
	}
	// Dots inside a segment are ordinary.
	if resp, _ := f.do(t, "GET", "/splunk/services/app.v1/..x", bearer); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestResponseHeadersRedacted(t *testing.T) {
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<https://sn.example.com/api/now/table/incident?sysparm_query=caller.email=jane@example.com&sysparm_offset=100>; rel="next"`)
		w.Header().Set("X-Requested-By", "MET123456789")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	})
	resp, _ := f.do(t, "GET", "/splunk/x", bearer)
	if got := resp.Header.Get("Link"); strings.Contains(got, "jane@") || !strings.Contains(got, "caller.email=[REDACTED:EMAIL]&sysparm_offset=100") {
		t.Fatalf("Link = %q", got)
	}
	if got := resp.Header.Get("X-Requested-By"); got != "[REDACTED:MEMBER_ID]" {
		t.Fatalf("X-Requested-By = %q", got)
	}
}

func TestRangeStrippedAndPartialBlocked(t *testing.T) {
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("force206") != "" {
			w.WriteHeader(http.StatusPartialContent)
		}
		io.WriteString(w, `{"a":"jane.doe@met`)
	})
	f.do(t, "GET", "/splunk/x", map[string]string{"Authorization": "Bearer " + token, "Range": "bytes=0-99", "If-Range": `"etag"`})
	if h := f.lastReq().Header; h.Get("Range") != "" || h.Get("If-Range") != "" {
		t.Fatalf("Range forwarded: %v", h)
	}
	resp, body := f.do(t, "GET", "/splunk/x?force206=1", bearer)
	if resp.StatusCode != 502 || !strings.Contains(body, "partial_content") {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	// Passthrough connections keep Range.
	f.do(t, "GET", "/elastic/x", map[string]string{"Authorization": "Bearer " + token, "Range": "bytes=0-99"})
	if f.lastReq().Header.Get("Range") != "bytes=0-99" {
		t.Fatal("passthrough lost Range")
	}
}

func TestUpstreamErrorLogOmitsURL(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	f.srv.cfg.Connections[0].UpstreamURL.Host = "127.0.0.1:1"
	f.do(t, "GET", "/splunk/api/now/table/sys_user?sysparm_query=email=jane@example.com", bearer)
	logs := f.waitForAudit(t)
	if !strings.Contains(logs, `"msg":"upstream error"`) {
		t.Fatalf("no upstream error logged: %s", logs)
	}
	if strings.Contains(logs, "jane@") || strings.Contains(logs, "sysparm_query=") {
		t.Fatalf("upstream error log leaks the URL: %s", logs)
	}
}
