package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

const (
	// tokenEarlyRefresh renews a token this long before it expires, so a
	// request never leaves with one that lapses on the way.
	tokenEarlyRefresh = 60 * time.Second
	// tokenDefaultLifetime is how long to keep a token whose response gave
	// no expires_in. Short, because the real lifetime is unknown.
	tokenDefaultLifetime = 5 * time.Minute
	// tokenFetchTimeout bounds one token request.
	tokenFetchTimeout = 10 * time.Second
	// maxTokenResponse caps the token endpoint's body; a token response is
	// a few kilobytes at most.
	maxTokenResponse = 1 << 20
)

// tokenSource fetches and caches one connection's upstream access token
// with the client credentials grant.
type tokenSource struct {
	cfg    *config.OAuth2
	client *http.Client
	now    func() time.Time

	// mu is held across a fetch, so concurrent requests needing a new
	// token wait for one fetch instead of each sending their own.
	mu     sync.Mutex
	token  string
	expiry time.Time
}

func newTokenSource(cfg *config.OAuth2, transport http.RoundTripper) *tokenSource {
	return &tokenSource{
		cfg:    cfg,
		client: &http.Client{Transport: transport, Timeout: tokenFetchTimeout},
		now:    time.Now,
	}
}

// oauthError is a failure to get an upstream token. Its reason is safe to
// return to NeuBird and to log: the token endpoint's HTTP status and OAuth
// error code, never a credential.
type oauthError struct{ reason string }

func (e *oauthError) Error() string { return "upstream token: " + e.reason }

// Token returns a valid access token, fetching one if the cached one is
// missing or about to expire. fresh reports whether it was fetched by this
// call, which decides whether a 401 is worth a retry.
func (ts *tokenSource) Token(ctx context.Context) (token string, fresh bool, err error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.token != "" && ts.now().Before(ts.expiry) {
		return ts.token, false, nil
	}
	tok, lifetime, err := ts.fetch(ctx)
	if err != nil {
		return "", false, err
	}
	ts.token = tok
	ts.expiry = ts.now().Add(refreshAfter(lifetime))
	return tok, true, nil
}

// invalidate drops the cached token if it is still the one the upstream
// rejected, so a concurrent request that already refreshed it keeps the new
// one.
func (ts *tokenSource) invalidate(rejected string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.token == rejected {
		ts.token = ""
	}
}

// refreshAfter is how long to use a token with the given lifetime. Short
// lifetimes are halved rather than cut by the full margin, so a 60-second
// token is still reused.
func refreshAfter(lifetime time.Duration) time.Duration {
	if lifetime <= 0 {
		return tokenDefaultLifetime
	}
	if lifetime <= 2*tokenEarlyRefresh {
		return lifetime / 2
	}
	return lifetime - tokenEarlyRefresh
}

func (ts *tokenSource) fetch(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(ts.cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(ts.cfg.Scopes, " "))
	}
	for k, v := range ts.cfg.Params {
		form.Set(k, v)
	}
	if ts.cfg.AuthStyle == config.OAuth2AuthBody {
		form.Set("client_id", ts.cfg.ClientID)
		form.Set("client_secret", ts.cfg.ClientSecret)
	}

	ctx, cancel := context.WithTimeout(ctx, tokenFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.cfg.TokenURLParsed.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, &oauthError{"building the token request failed"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if ts.cfg.AuthStyle == config.OAuth2AuthBasic {
		// RFC 6749 section 2.3.1: form-encode both parts before Basic.
		req.SetBasicAuth(url.QueryEscape(ts.cfg.ClientID), url.QueryEscape(ts.cfg.ClientSecret))
	}

	resp, err := ts.client.Do(req)
	if err != nil {
		// The cause can carry the token URL; the reason says only that the
		// endpoint could not be reached.
		return "", 0, &oauthError{"the token endpoint could not be reached"}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))

	var tr struct {
		AccessToken string          `json:"access_token"`
		TokenType   string          `json:"token_type"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
		Error       string          `json:"error"`
	}
	_ = json.Unmarshal(body, &tr)
	if resp.StatusCode != http.StatusOK {
		reason := fmt.Sprintf("the token endpoint returned HTTP %d", resp.StatusCode)
		if code := oauthErrorCode(tr.Error); code != "" {
			reason += " (" + code + ")"
		}
		return "", 0, &oauthError{reason}
	}
	if tr.AccessToken == "" {
		return "", 0, &oauthError{"the token endpoint returned no access_token"}
	}
	if tr.TokenType != "" && !strings.EqualFold(tr.TokenType, "bearer") {
		return "", 0, &oauthError{fmt.Sprintf("the token endpoint returned token_type %q; only bearer tokens are supported", oauthErrorCode(tr.TokenType))}
	}
	return tr.AccessToken, expiresIn(tr.ExpiresIn), nil
}

// expiresIn reads expires_in as a number or a numeric string, since some
// providers (Azure AD v1) send it quoted. Zero means it was absent or
// unreadable.
func expiresIn(raw json.RawMessage) time.Duration {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n * float64(time.Second))
}

// oauthErrorCode keeps an OAuth error code safe to log and return: RFC 6749
// codes are lowercase ASCII with underscores, so anything else is dropped
// rather than echoed.
func oauthErrorCode(s string) string {
	if s == "" || len(s) > 64 {
		return ""
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return ""
		}
	}
	return s
}

// oauthTransport adds each upstream_oauth2 connection's access token to its
// requests. A 401 on a cached token gets one retry with a new token, since a
// token can be revoked or expire early on the provider's side.
type oauthTransport struct {
	base    http.RoundTripper
	sources map[string]*tokenSource
}

func (t *oauthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	st, _ := req.Context().Value(stateKey{}).(*reqState)
	if st == nil {
		return t.base.RoundTrip(req)
	}
	ts := t.sources[st.conn.Name]
	if ts == nil {
		return t.base.RoundTrip(req)
	}

	tok, fresh, err := ts.Token(req.Context())
	if err != nil {
		return nil, err
	}
	resp, err := t.base.RoundTrip(withBearer(req, tok))
	if err != nil || resp.StatusCode != http.StatusUnauthorized || fresh || !replayable(req, st) {
		return resp, err
	}

	ts.invalidate(tok)
	tok, _, err = ts.Token(req.Context())
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	retry := withBearer(req, tok)
	if st.replayBody != nil {
		body, err := st.replayBody()
		if err != nil {
			return resp, nil
		}
		retry.Body = body
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxTokenResponse))
	resp.Body.Close()
	return t.base.RoundTrip(retry)
}

// withBearer returns a copy of req carrying tok, leaving req untouched as
// the RoundTripper contract requires.
func withBearer(req *http.Request, tok string) *http.Request {
	out := req.Clone(req.Context())
	out.Header.Set("Authorization", "Bearer "+tok)
	return out
}

// replayable reports whether req's body can be sent a second time.
// checkRequest buffers every body, so in practice this is always true; the
// check keeps a retry from sending an empty body.
func replayable(req *http.Request, st *reqState) bool {
	return req.Body == nil || req.Body == http.NoBody || st.replayBody != nil
}
