package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// tokenServer is a fake OAuth 2.0 token endpoint that mints tok-1, tok-2, ...
type tokenServer struct {
	*httptest.Server
	mu        sync.Mutex
	issued    int
	forms     []url.Values
	auths     []string
	expiresIn any    // the expires_in value it returns; nil omits it
	fail      string // when set, the error code it answers with, at HTTP 401
}

func newTokenServer(t *testing.T) *tokenServer {
	t.Helper()
	ts := &tokenServer{expiresIn: 3600}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		ts.mu.Lock()
		defer ts.mu.Unlock()
		ts.forms = append(ts.forms, r.PostForm)
		ts.auths = append(ts.auths, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		if ts.fail != "" {
			w.WriteHeader(http.StatusUnauthorized)
			// The description echoes the secret, as some providers do; it
			// must never reach NeuBird or the logs.
			fmt.Fprintf(w, `{"error":%q,"error_description":"bad secret s3cret&key"}`, ts.fail)
			return
		}
		ts.issued++
		resp := map[string]any{"access_token": fmt.Sprintf("tok-%d", ts.issued), "token_type": "Bearer"}
		if ts.expiresIn != nil {
			resp["expires_in"] = ts.expiresIn
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *tokenServer) fetches() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return len(ts.forms)
}

func oauthConfig(tokenURL, extra string) string {
	return `
client_token_env: NEUBIRD_PROXY_TOKEN
allow_http_upstreams: true
connections:
  - name: api
    upstream: UPSTREAM
    methods: [GET, POST]
    upstream_oauth2:
      token_url: ` + tokenURL + `
      client_id_env: OAUTH_ID
      client_secret_env: OAUTH_SECRET
      scopes: [read.logs, read.metrics]
      params: {audience: https://api.example.com}
` + extra
}

// bearerUpstream answers 200 to the tokens in accept and 401 to anything
// else, recording the Authorization header and body of each request.
type bearerUpstream struct {
	mu     sync.Mutex
	accept map[string]bool
	seen   []string
	bodies []string
}

func (u *bearerUpstream) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	defer u.mu.Unlock()
	auth := r.Header.Get("Authorization")
	u.seen = append(u.seen, auth)
	u.bodies = append(u.bodies, string(b))
	if !u.accept[strings.TrimPrefix(auth, "Bearer ")] {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"ok":true}`)
}

func TestOAuth2TokenInjectedAndCached(t *testing.T) {
	ts := newTokenServer(t)
	up := &bearerUpstream{accept: map[string]bool{"tok-1": true}}
	f := newFixture(t, oauthConfig(ts.URL+"/oauth/token", ""), up.handler)

	for i := 0; i < 3; i++ {
		resp, body := f.do(t, "GET", "/api/v1/things", bearer)
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: %d %s", i, resp.StatusCode, body)
		}
	}
	if n := ts.fetches(); n != 1 {
		t.Errorf("token fetched %d times for 3 requests, want 1 (cached)", n)
	}
	for _, a := range up.seen {
		if a != "Bearer tok-1" {
			t.Errorf("upstream saw Authorization %q, want the minted token and never NeuBird's", a)
		}
	}

	form, auth := ts.forms[0], ts.auths[0]
	if form.Get("grant_type") != "client_credentials" || form.Get("scope") != "read.logs read.metrics" ||
		form.Get("audience") != "https://api.example.com" {
		t.Errorf("token request form = %v", form)
	}
	if form.Get("client_secret") != "" {
		t.Error("client_secret sent in the body with auth_style basic")
	}
	// RFC 6749 2.3.1: id and secret are form-encoded before Basic.
	want := basic(url.QueryEscape("client id/1"), url.QueryEscape("s3cret&key"))
	if auth != want {
		t.Errorf("token request Authorization = %q, want %q", auth, want)
	}
}

func TestOAuth2AuthStyleBody(t *testing.T) {
	ts := newTokenServer(t)
	up := &bearerUpstream{accept: map[string]bool{"tok-1": true}}
	cfg := strings.Replace(oauthConfig(ts.URL, ""), "      scopes:", "      auth_style: body\n      scopes:", 1)
	f := newFixture(t, cfg, up.handler)

	if resp, body := f.do(t, "GET", "/api/x", bearer); resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if form := ts.forms[0]; form.Get("client_id") != "client id/1" || form.Get("client_secret") != "s3cret&key" {
		t.Errorf("token request form = %v", form)
	}
	if ts.auths[0] != "" {
		t.Errorf("token request sent Authorization %q with auth_style body", ts.auths[0])
	}
}

// A token is renewed before it expires, and expires_in is read when a
// provider sends it as a string.
func TestOAuth2RefreshesBeforeExpiry(t *testing.T) {
	ts := newTokenServer(t)
	ts.expiresIn = "1" // halved for short lifetimes: reused for 500ms
	up := &bearerUpstream{accept: map[string]bool{"tok-1": true, "tok-2": true}}
	f := newFixture(t, oauthConfig(ts.URL, ""), up.handler)

	f.do(t, "GET", "/api/a", bearer)
	f.do(t, "GET", "/api/b", bearer)
	if n := ts.fetches(); n != 1 {
		t.Fatalf("fetched %d tokens before expiry, want 1", n)
	}
	time.Sleep(600 * time.Millisecond)
	f.do(t, "GET", "/api/c", bearer)
	if n := ts.fetches(); n != 2 {
		t.Fatalf("fetched %d tokens after the lifetime passed, want 2", n)
	}
	if last := up.seen[len(up.seen)-1]; last != "Bearer tok-2" {
		t.Errorf("after refresh the upstream saw %q", last)
	}
}

// A cached token the upstream rejects (revoked, or expired early) is
// replaced and the request sent once more, body included.
func TestOAuth2RetriesOnceOn401WithANewToken(t *testing.T) {
	ts := newTokenServer(t)
	up := &bearerUpstream{accept: map[string]bool{"tok-1": true}}
	f := newFixture(t, oauthConfig(ts.URL, ""), up.handler)

	if resp, _ := f.do(t, "GET", "/api/warm", bearer); resp.StatusCode != 200 {
		t.Fatal("warm-up failed")
	}
	up.mu.Lock()
	up.accept = map[string]bool{"tok-2": true} // tok-1 revoked
	up.mu.Unlock()

	req, _ := http.NewRequest("POST", f.proxy.URL+"/api/search", strings.NewReader(`{"q":"x"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200 after the retry", resp.StatusCode)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	n := len(up.seen)
	if up.seen[n-2] != "Bearer tok-1" || up.seen[n-1] != "Bearer tok-2" {
		t.Errorf("upstream saw %v, want tok-1 rejected then tok-2", up.seen[n-2:])
	}
	if up.bodies[n-1] != `{"q":"x"}` {
		t.Errorf("retry body = %q, want the original body replayed", up.bodies[n-1])
	}
}

// A token just fetched and still refused is a scope or permission problem,
// not a stale token: no retry, and the 401 is passed on.
func TestOAuth2NoRetryWithAFreshToken(t *testing.T) {
	ts := newTokenServer(t)
	up := &bearerUpstream{accept: map[string]bool{}}
	f := newFixture(t, oauthConfig(ts.URL, ""), up.handler)

	resp, _ := f.do(t, "GET", "/api/x", bearer)
	if resp.StatusCode != 401 {
		t.Fatalf("status %d, want the upstream's 401", resp.StatusCode)
	}
	if n := ts.fetches(); n != 1 {
		t.Errorf("fetched %d tokens, want 1 (no retry on a fresh token)", n)
	}
}

func TestOAuth2TokenEndpointFailure(t *testing.T) {
	ts := newTokenServer(t)
	ts.fail = "invalid_client"
	up := &bearerUpstream{accept: map[string]bool{}}
	f := newFixture(t, oauthConfig(ts.URL, ""), up.handler)

	resp, body := f.do(t, "GET", "/api/x", bearer)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, `"upstream_auth_failed"`) ||
		!strings.Contains(body, "HTTP 401 (invalid_client)") {
		t.Fatalf("got %d %s, want 502 upstream_auth_failed naming the status and error code", resp.StatusCode, body)
	}
	if strings.Contains(body, "s3cret") || strings.Contains(f.logs.String(), "s3cret") {
		t.Error("the token endpoint's error_description leaked into the response or logs")
	}
	if len(up.seen) != 0 {
		t.Error("the request reached the upstream without a token")
	}
}

func TestOAuth2Helpers(t *testing.T) {
	for raw, want := range map[string]time.Duration{
		`3600`: time.Hour, `"3599"`: 3599 * time.Second, `""`: 0, `null`: 0, ``: 0, `-5`: 0, `"abc"`: 0,
	} {
		if got := expiresIn(json.RawMessage(raw)); got != want {
			t.Errorf("expiresIn(%s) = %v, want %v", raw, got, want)
		}
	}
	for lifetime, want := range map[time.Duration]time.Duration{
		0: tokenDefaultLifetime, time.Hour: time.Hour - tokenEarlyRefresh, time.Minute: 30 * time.Second,
	} {
		if got := refreshAfter(lifetime); got != want {
			t.Errorf("refreshAfter(%v) = %v, want %v", lifetime, got, want)
		}
	}
	for in, want := range map[string]string{
		"invalid_client": "invalid_client", "bad secret: s3cret": "", strings.Repeat("a", 65): "",
	} {
		if got := oauthErrorCode(in); got != want {
			t.Errorf("oauthErrorCode(%q) = %q, want %q", in, got, want)
		}
	}
}
