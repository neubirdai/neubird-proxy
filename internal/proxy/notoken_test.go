package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// A tunnel-only proxy (listen: off) whose open mode takes no proxy token:
// every request arrives over the mutually authenticated tunnel.
const tunnelNoTokenConfig = `
listen: "off"
allow_http_upstreams: true
tunnel: {relays: ['relay.example.com:443'], tenant: acme, proxy: aks, key_file: k, ca_file: ca}
neubird_destinations:
  hosts: ['127.0.0.1']
  methods: [GET, POST]
  client_auth: none
`

func TestTunnelNoTokenForwards(t *testing.T) {
	destDialControl = nil
	t.Cleanup(func() { destDialControl = refuseInternalAddresses })
	f := newFixture(t, tunnelNoTokenConfig, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	resp, body := f.do(t, "GET", "/_neubird/dest/services/mcp", map[string]string{
		"X-Neubird-Destination":            f.upstream,
		"X-Neubird-Upstream-Authorization": "Bearer splunk-token",
	})
	if resp.StatusCode != 200 || !strings.Contains(body, "ok") {
		t.Fatalf("status %d, body %s", resp.StatusCode, body)
	}
	up := f.lastReq()
	if up.URL.Path != "/services/mcp" || up.Header.Get("Authorization") != "Bearer splunk-token" {
		t.Fatalf("upstream got %s, Authorization %q", up.URL.Path, up.Header.Get("Authorization"))
	}
	// The rest of the policy still applies.
	if resp, _ := f.do(t, "DELETE", "/_neubird/dest/x", map[string]string{"X-Neubird-Destination": f.upstream}); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "GET", "/_neubird/dest/x", map[string]string{"X-Neubird-Destination": "https://other.example.com"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unlisted destination: %d", resp.StatusCode)
	}
}

// The status endpoint answers without a token and tells NeuBird to send none.
func TestTunnelNoTokenStatus(t *testing.T) {
	f := newFixture(t, tunnelNoTokenConfig, func(w http.ResponseWriter, r *http.Request) {})
	for _, hdr := range []map[string]string{{}, {"Authorization": "Bearer anything"}} {
		resp, raw := f.do(t, "GET", "/_neubird/status", hdr)
		if resp.StatusCode != 200 {
			t.Fatalf("status %d: %s", resp.StatusCode, raw)
		}
		var st Status
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			t.Fatal(err)
		}
		if st.Destinations == nil || st.Destinations.ClientAuth != "none" {
			t.Fatalf("destinations: %+v", st.Destinations)
		}
	}
}
