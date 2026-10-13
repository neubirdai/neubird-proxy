package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// host_methods narrows methods per destination: read-only for one host,
// while the shared methods (POST for Splunk MCP) apply to the others.
func TestHostMethods(t *testing.T) {
	destDialControl = nil
	t.Cleanup(func() { destDialControl = refuseInternalAddresses })
	ok := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`ok`)) }

	// The fake upstream is 127.0.0.1: a rule for it makes it read-only.
	f := newFixture(t, tunnelNoTokenConfig+`  host_methods:
    - {hosts: ['127.0.0.1'], methods: [GET]}
`, ok)
	h := map[string]string{"X-Neubird-Destination": f.upstream}
	if resp, body := f.do(t, "GET", "/_neubird/dest/api/now/table/incident", h); resp.StatusCode != 200 || !strings.Contains(body, "ok") {
		t.Fatalf("GET: %d %s", resp.StatusCode, body)
	}
	resp, _ := f.do(t, "POST", "/_neubird/dest/api/now/table/incident", h)
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET" {
		t.Fatalf("POST to a read-only host: %d, Allow %q", resp.StatusCode, resp.Header.Get("Allow"))
	}

	// A rule for another host leaves this one on the shared methods.
	g := newFixture(t, tunnelNoTokenConfig+`  host_methods:
    - {hosts: ['*.service-now.com'], methods: [GET]}
`, ok)
	if resp, _ := g.do(t, "POST", "/_neubird/dest/services/mcp", map[string]string{"X-Neubird-Destination": g.upstream}); resp.StatusCode != 200 {
		t.Fatalf("POST to a host without a rule: %d", resp.StatusCode)
	}
}
