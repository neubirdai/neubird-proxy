package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const credentialsConfig = `
client_token_env: NEUBIRD_PROXY_TOKEN
allow_http_upstreams: true
upstream_defaults:
  headers:
    Ocp-Apim-Subscription-Key: ${APIM_SUBSCRIPTION_KEY}
connections:
  - name: jira
    upstream: UPSTREAM/jira
    credentials: neubird
  - name: datadog
    upstream: UPSTREAM/dd
    credentials: neubird
    credential_headers: [DD-API-KEY, DD-APPLICATION-KEY]
    client_auth: header
    client_auth_header: X-NeuBird-Token
  - name: splunk
    upstream: UPSTREAM/splunk
  - name: scoped
    upstream: UPSTREAM/scoped
    client_token_env: SCOPED_TOKEN
    methods: [GET, POST]
    paths: [/mcp]
    mcp_tools: [search]
    response_fields: [result.id]
`

func TestNeuBirdCredentialsForwarded(t *testing.T) {
	f := newFixture(t, credentialsConfig, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})

	resp, body := f.do(t, "GET", "/jira/rest/api/2/issue/X-1", map[string]string{
		"Authorization":                    "Bearer " + token,
		"X-Neubird-Upstream-Authorization": "Bearer jira-oauth-access-token",
		"X-Neubird-Upstream-Cookie":        "session=steal",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	up := f.lastReq()
	if got := up.Header.Get("Authorization"); got != "Bearer jira-oauth-access-token" {
		t.Fatalf("upstream Authorization = %q; want the NeuBird-held credential, not the proxy token", got)
	}
	if up.Header.Get("Cookie") != "" || up.Header.Get("Ocp-Apim-Subscription-Key") != "apim-key" {
		t.Fatalf("upstream headers: %v", up.Header)
	}
	for k := range up.Header {
		if strings.HasPrefix(k, "X-Neubird-") {
			t.Fatalf("credential carrier header %s reached the upstream", k)
		}
	}
	if !strings.Contains(f.logs.String(), `"credentials":"neubird"`) || strings.Contains(f.logs.String(), "jira-oauth-access-token") {
		t.Fatalf("audit line: %s", f.logs.String())
	}

	// Several headers, and the proxy token in its own header.
	resp, body = f.do(t, "GET", "/datadog/api/v1/monitor", map[string]string{
		"X-NeuBird-Token":                       token,
		"X-Neubird-Upstream-Dd-Api-Key":         "api-key",
		"X-Neubird-Upstream-Dd-Application-Key": "app-key",
		"X-Neubird-Upstream-Authorization":      "Bearer not-listed",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	up = f.lastReq()
	if up.Header.Get("Dd-Api-Key") != "api-key" || up.Header.Get("Dd-Application-Key") != "app-key" || up.Header.Get("Authorization") != "" {
		t.Fatalf("datadog upstream headers: %v", up.Header)
	}

	// No credential sent: forwarded without one; the backend decides.
	resp, _ = f.do(t, "GET", "/jira/rest/api/2/myself", map[string]string{"Authorization": "Bearer " + token})
	if resp.StatusCode != 200 || f.lastReq().Header.Get("Authorization") != "" {
		t.Fatalf("no credential: status %d, upstream Authorization %q", resp.StatusCode, f.lastReq().Header.Get("Authorization"))
	}
}

func TestCustomerCredentialsRefuseNeuBirdOnes(t *testing.T) {
	f := newFixture(t, credentialsConfig, func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached the upstream")
	})
	resp, body := f.do(t, "GET", "/splunk/services/server/info", map[string]string{
		"Authorization":                    "Bearer " + token,
		"x-neubird-upstream-authorization": "Splunk abc",
	})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "credentials_not_accepted") {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	// Authentication still comes first.
	resp, _ = f.do(t, "GET", "/splunk/services/server/info", map[string]string{
		"X-Neubird-Upstream-Authorization": "Splunk abc",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: status %d", resp.StatusCode)
	}
}

func TestStatusAPI(t *testing.T) {
	f := newFixture(t, credentialsConfig, func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached the upstream")
	})
	f.srv.Version = "v-test"

	get := func(tok string) (*http.Response, Status) {
		t.Helper()
		hdr := map[string]string{}
		if tok != "" {
			hdr["Authorization"] = "Bearer " + tok
		}
		resp, body := f.do(t, "GET", "/_neubird/status", hdr)
		var st Status
		if resp.StatusCode == 200 {
			if err := json.Unmarshal([]byte(body), &st); err != nil {
				t.Fatal(err)
			}
		}
		return resp, st
	}

	resp, st := get(token)
	if resp.StatusCode != 200 || st.Version != "v-test" {
		t.Fatalf("status %d: %+v", resp.StatusCode, st)
	}
	var names []string
	for _, c := range st.Connections {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "jira,datadog,splunk" {
		t.Fatalf("default token lists %v; the scoped connection must not appear", names)
	}
	dd := st.Connections[1]
	if dd.Credentials != "neubird" || strings.Join(dd.CredentialHeaders, ",") != "Dd-Api-Key,Dd-Application-Key" ||
		dd.ClientAuth != "header" || dd.ClientAuthHeader != "X-NeuBird-Token" || strings.Join(dd.Methods, ",") != "GET,HEAD" {
		t.Fatalf("datadog: %+v", dd)
	}
	if sp := st.Connections[2]; sp.Credentials != "customer" || sp.CredentialHeaders != nil || !sp.Redaction {
		t.Fatalf("splunk: %+v", sp)
	}

	resp, st = get(scopedToken)
	if resp.StatusCode != 200 || len(st.Connections) != 1 {
		t.Fatalf("scoped: %d %+v", resp.StatusCode, st)
	}
	if sc := st.Connections[0]; sc.Name != "scoped" || !sc.PathsRestricted || !sc.FieldsRestricted || strings.Join(sc.MCPTools, ",") != "search" {
		t.Fatalf("scoped: %+v", sc)
	}

	// Nothing from config values leaves: no upstream URL, no secrets.
	_, raw := f.do(t, "GET", "/_neubird/status", map[string]string{"Authorization": "Bearer " + token})
	for _, leak := range []string{"127.0.0.1", "apim-key", "/jira", token} {
		if strings.Contains(raw, leak) {
			t.Fatalf("status leaks %q: %s", leak, raw)
		}
	}

	for _, tok := range []string{"", "wrong-token-wrong-token-wrong-token"} {
		if resp, _ := get(tok); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("token %q: status %d", tok, resp.StatusCode)
		}
	}
	if resp, _ := f.do(t, "POST", "/_neubird/status", map[string]string{"Authorization": "Bearer " + token}); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: status %d", resp.StatusCode)
	}
}

func TestStatusAPIDisabled(t *testing.T) {
	f := newFixture(t, "disable_status_api: true\n"+credentialsConfig, func(w http.ResponseWriter, r *http.Request) {})
	resp, body := f.do(t, "GET", "/_neubird/status", map[string]string{"Authorization": "Bearer " + token})
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "unknown_connection") {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
}
