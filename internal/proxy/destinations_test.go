package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const destinationsConfig = `
client_token_env: NEUBIRD_PROXY_TOKEN
allow_http_upstreams: true
upstream_defaults:
  headers:
    Ocp-Apim-Subscription-Key: ${APIM_SUBSCRIPTION_KEY}
connections:
  - name: splunk
    upstream: UPSTREAM/splunk
neubird_destinations:
  hosts: ['127.0.0.1', '*.acme.internal']
  methods: [GET, POST]
`

func TestDestinationsForward(t *testing.T) {
	// The fake upstream is on loopback, which open mode refuses to dial.
	destDialControl = nil
	t.Cleanup(func() { destDialControl = refuseInternalAddresses })
	f := newFixture(t, destinationsConfig, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/rest/next")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":"bob@example.com"}`))
	})
	dest := f.upstream

	resp, body := f.do(t, "GET", "/_neubird/dest/rest/api/2/myself", map[string]string{
		"Authorization":                    "Bearer " + token,
		"X-Neubird-Destination":            dest,
		"X-Neubird-Upstream-Authorization": "Bearer jira-oauth",
	})
	if resp.StatusCode != 200 || strings.Contains(body, "bob@example.com") {
		t.Fatalf("status %d, body %s (want 200, redacted)", resp.StatusCode, body)
	}
	up := f.lastReq()
	if up.URL.Path != "/rest/api/2/myself" || up.Header.Get("Authorization") != "Bearer jira-oauth" {
		t.Fatalf("upstream got %s, Authorization %q", up.URL.Path, up.Header.Get("Authorization"))
	}
	if up.Header.Get("Ocp-Apim-Subscription-Key") != "" || up.Header.Get("X-Neubird-Destination") != "" {
		t.Fatalf("leaked headers upstream: %v", up.Header)
	}
	logs := f.logs.String()
	if !strings.Contains(logs, `"connection":"_destinations"`) || !strings.Contains(logs, `"destination":"`+dest+`"`) || strings.Contains(logs, "jira-oauth") {
		t.Fatalf("audit: %s", logs)
	}

	// A same-origin redirect comes back through open mode.
	req, _ := http.NewRequest("GET", f.proxy.URL+"/_neubird/dest/redirect", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Neubird-Destination", dest)
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/_neubird/dest/rest/next" {
		t.Fatalf("Location = %q", loc)
	}
	// The method ceiling applies.
	resp, _ = f.do(t, "DELETE", "/_neubird/dest/x", map[string]string{"Authorization": "Bearer " + token, "X-Neubird-Destination": dest})
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE: %d", resp.StatusCode)
	}
}

func TestDestinationsRefused(t *testing.T) {
	f := newFixture(t, destinationsConfig, func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached the upstream")
	})
	for name, dest := range map[string]string{
		"not listed":    "https://evil.example.com",
		"ip not listed": "http://10.0.0.1",
		"suffix spoof":  "https://jira.acme.internal.evil.com",
		"with path":     "https://jira.acme.internal/admin",
		"with user":     "https://u:p@jira.acme.internal",
		"no header":     "",
		"bad scheme":    "ftp://jira.acme.internal",
	} {
		hdr := map[string]string{"Authorization": "Bearer " + token}
		if dest != "" {
			hdr["X-Neubird-Destination"] = dest
		}
		resp, body := f.do(t, "GET", "/_neubird/dest/x", hdr)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "destination_not_allowed") {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
	}
	// Without the token, nothing is said about the destination.
	resp, _ := f.do(t, "GET", "/_neubird/dest/x", map[string]string{"X-Neubird-Destination": "https://evil.example.com"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
	// The template is never routable by name.
	resp, _ = f.do(t, "GET", "/_destinations/x", map[string]string{"Authorization": "Bearer " + token})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("by name: %d", resp.StatusCode)
	}
}

func TestDestinationsStatus(t *testing.T) {
	f := newFixture(t, destinationsConfig, func(w http.ResponseWriter, r *http.Request) {})
	_, raw := f.do(t, "GET", "/_neubird/status", map[string]string{"Authorization": "Bearer " + token})
	var st Status
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatal(err)
	}
	if st.Destinations == nil || st.Destinations.ClientAuth != "bearer" || strings.Join(st.Destinations.CredentialHeaders, ",") != "Authorization" {
		t.Fatalf("destinations: %+v", st.Destinations)
	}
	// Only how to send requests: no hosts, connections or upstreams.
	for _, leak := range []string{"acme.internal", "127.0.0.1", "splunk", "apim-key"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("status leaks %q: %s", leak, raw)
		}
	}
	for _, tok := range []string{"", "wrong-token-wrong-token-wrong-token"} {
		hdr := map[string]string{}
		if tok != "" {
			hdr["Authorization"] = "Bearer " + tok
		}
		if resp, _ := f.do(t, "GET", "/_neubird/status", hdr); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("token %q: status %d", tok, resp.StatusCode)
		}
	}
	if resp, _ := f.do(t, "POST", "/_neubird/status", map[string]string{"Authorization": "Bearer " + token}); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: status %d", resp.StatusCode)
	}
}

// Without open mode there is nothing for NeuBird to ask about.
func TestStatusWithoutDestinations(t *testing.T) {
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, r *http.Request) {})
	if resp, _ := f.do(t, "GET", "/_neubird/status", map[string]string{"Authorization": "Bearer " + token}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// A named connection keeps the customer's credential: a NeuBird one is never
// forwarded (the header allowlist drops it).
func TestNamedConnectionDropsNeuBirdCredential(t *testing.T) {
	f := newFixture(t, destinationsConfig, func(w http.ResponseWriter, r *http.Request) {})
	resp, _ := f.do(t, "GET", "/splunk/x", map[string]string{
		"Authorization":                    "Bearer " + token,
		"X-Neubird-Upstream-Authorization": "Bearer neubird",
	})
	up := f.lastReq()
	if resp.StatusCode != 200 || up.Header.Get("Authorization") != "" || up.Header.Get("X-Neubird-Upstream-Authorization") != "" ||
		up.Header.Get("Ocp-Apim-Subscription-Key") != "apim-key" {
		t.Fatalf("status %d, upstream headers %v", resp.StatusCode, up.Header)
	}
}

// With the real guard, a listed loopback destination is still refused at dial
// time: the 502 comes from the dial, not the pattern check.
func TestDestinationsDialGuard(t *testing.T) {
	f := newFixture(t, destinationsConfig, func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached the upstream")
	})
	resp, body := f.do(t, "GET", "/_neubird/dest/x", map[string]string{"Authorization": "Bearer " + token, "X-Neubird-Destination": f.upstream})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
}

func TestRefuseInternalAddresses(t *testing.T) {
	for addr, refused := range map[string]bool{
		"127.0.0.1:443":      true,
		"[::1]:443":          true,
		"169.254.169.254:80": true,
		"0.0.0.0:80":         true,
		"[fe80::1]:443":      true,
		"10.1.2.3:443":       false,
		"203.0.113.7:443":    false,
	} {
		if err := refuseInternalAddresses("tcp", addr, nil); (err != nil) != refused {
			t.Errorf("%s: err=%v, want refused=%v", addr, err, refused)
		}
	}
}
