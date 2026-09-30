// Package proxy is the redacting reverse proxy between NeuBird and
// MetLife's internal APIM endpoints.
//
// A request is routed by host (if a connection claims it) or by its first
// path segment, authenticated against the one NeuBird proxy token, stripped
// of that credential, given the APIM subscription key, and forwarded. Every
// response body is redacted before it is written back, and anything the
// proxy cannot redact is refused with a 502 rather than passed through.
package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/metrics"
	"github.com/neubirdai/neubird-proxy/internal/redact"
)

type Server struct {
	cfg     *config.Config
	engine  *redact.Engine
	log     *slog.Logger
	rp      *httputil.ReverseProxy
	byName  map[string]*config.Connection
	byHost  map[string]*config.Connection
	token   [32]byte
	Metrics *Metrics
}

type Metrics struct {
	Registry   *metrics.Registry
	Requests   *metrics.Counter
	Redactions *metrics.Counter
	Blocked    *metrics.Counter
	BytesOut   *metrics.Counter
}

func newMetrics() *Metrics {
	r := &metrics.Registry{}
	return &Metrics{
		Registry:   r,
		Requests:   r.Counter("neubird_proxy_requests_total", "Requests by connection and status code.", "connection", "code"),
		Redactions: r.Counter("neubird_proxy_redactions_total", "Masked values by connection and rule.", "connection", "rule"),
		Blocked:    r.Counter("neubird_proxy_blocked_total", "Responses refused (fail closed) by connection and reason.", "connection", "reason"),
		BytesOut:   r.Counter("neubird_proxy_response_bytes_total", "Response bytes sent to NeuBird by connection.", "connection"),
	}
}

// New builds a Server. The transport is exposed for tests that need to
// point at an httptest TLS server; nil means the configured default.
func New(cfg *config.Config, engine *redact.Engine, log *slog.Logger, transport http.RoundTripper) (*Server, error) {
	if transport == nil {
		t, err := newTransport(cfg)
		if err != nil {
			return nil, err
		}
		transport = t
	}
	s := &Server{
		cfg:     cfg,
		engine:  engine,
		log:     log,
		byName:  map[string]*config.Connection{},
		byHost:  map[string]*config.Connection{},
		token:   sha256.Sum256([]byte(cfg.ClientToken)),
		Metrics: newMetrics(),
	}
	for i := range cfg.Connections {
		c := &cfg.Connections[i]
		s.byName[c.Name] = c
		if c.Host != "" {
			s.byHost[c.Host] = c
		}
	}
	s.rp = &httputil.ReverseProxy{
		Rewrite:        s.rewrite,
		ModifyResponse: s.modifyResponse,
		ErrorHandler:   s.errorHandler,
		Transport:      transport,
		ErrorLog:       slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return s, nil
}

func newTransport(cfg *config.Config) (*http.Transport, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	// Bodies must arrive uncompressed to be redacted; see rewrite.
	t.DisableCompression = true
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.UpstreamCAFile != "" {
		pem, err := os.ReadFile(cfg.UpstreamCAFile)
		if err != nil {
			return nil, fmt.Errorf("upstream_ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("upstream_ca_file: no certificates found in %s", cfg.UpstreamCAFile)
		}
		t.TLSClientConfig.RootCAs = pool
	}
	return t, nil
}

// reqState travels in the request context from ServeHTTP through the
// ReverseProxy hooks, and feeds the audit line.
type reqState struct {
	conn    *config.Connection
	prefix  string // "/splunk" for path routing, "" for host routing
	rest    string // path after the prefix, decoded
	restRaw string // same, escaped as received
	stats   redact.Stats
	blocked string
	sse     *redact.SSEReader
}

type stateKey struct{}

func state(ctx context.Context) *reqState { return ctx.Value(stateKey{}).(*reqState) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &recorder{ResponseWriter: w}

	st, ok := s.route(r)
	if !ok {
		writeError(rec, http.StatusNotFound, "unknown_connection", "no connection matches this host or path")
		s.Metrics.Requests.Inc("_unknown", "404")
		return
	}
	name := st.conn.Name

	defer func() {
		p := recover()
		status := rec.status
		if p != nil {
			status = 0 // stream aborted mid-body
			if st.sse != nil && errors.Is(st.sse.Err(), redact.ErrEventTooLarge) {
				st.blocked = "sse_event_too_large"
				s.Metrics.Blocked.Inc(name, st.blocked)
			}
		}
		s.Metrics.Requests.Inc(name, strconv.Itoa(status))
		s.Metrics.BytesOut.Add(float64(rec.bytes), name)
		for rule, n := range st.stats {
			s.Metrics.Redactions.Add(float64(n), name, rule)
		}
		s.audit(r, st, status, rec.bytes, time.Since(start))
		if p != nil {
			panic(p)
		}
	}()

	if !s.authenticate(st.conn, r) {
		if st.conn.ClientAuth == config.AuthBasic {
			rec.Header().Set("WWW-Authenticate", `Basic realm="neubird-proxy"`)
		}
		writeError(rec, http.StatusUnauthorized, "unauthorized", "missing or invalid proxy token")
		return
	}
	// Upgraded connections (WebSocket) bypass response redaction entirely.
	if !st.conn.Passthrough && r.Header.Get("Upgrade") != "" {
		st.blocked = "upgrade_not_supported"
		s.Metrics.Blocked.Inc(name, st.blocked)
		writeError(rec, http.StatusBadRequest, "upgrade_not_supported", "protocol upgrades cannot be redacted")
		return
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(rec, r.Body, s.cfg.MaxBodyBytes)
	}

	s.rp.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), stateKey{}, st)))
}

func (s *Server) route(r *http.Request) (*reqState, bool) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if c, ok := s.byHost[host]; ok {
		return &reqState{conn: c, rest: r.URL.Path, restRaw: r.URL.EscapedPath(), stats: redact.Stats{}}, true
	}

	p := strings.TrimPrefix(r.URL.Path, "/")
	name, _, _ := strings.Cut(p, "/")
	c, ok := s.byName[name]
	if !ok {
		return nil, false
	}
	prefix := "/" + name
	st := &reqState{conn: c, prefix: prefix, rest: strings.TrimPrefix(r.URL.Path, prefix), stats: redact.Stats{}}
	// Names are [a-z0-9_-], so the escaped path has the same prefix unless
	// the client percent-encoded it; then fall back to the decoded path.
	if raw := r.URL.EscapedPath(); strings.HasPrefix(raw, prefix+"/") || raw == prefix {
		st.restRaw = strings.TrimPrefix(raw, prefix)
	}
	return st, true
}

func (s *Server) authenticate(c *config.Connection, r *http.Request) bool {
	var presented string
	switch c.ClientAuth {
	case config.AuthBearer:
		scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return false
		}
		presented = strings.TrimSpace(tok)
	case config.AuthBasic:
		_, pw, ok := r.BasicAuth()
		if !ok {
			return false
		}
		presented = pw
	case config.AuthHeader:
		presented = r.Header.Get(c.ClientAuthHeader)
	}
	if presented == "" {
		return false
	}
	// Hash both sides so the comparison is constant time regardless of length.
	sum := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(sum[:], s.token[:]) == 1
}

func (s *Server) rewrite(pr *httputil.ProxyRequest) {
	st := state(pr.In.Context())
	c := st.conn
	target := c.UpstreamURL

	out := pr.Out
	out.URL.Scheme = target.Scheme
	out.URL.Host = target.Host
	out.URL.Path = target.Path + st.rest
	out.URL.RawPath = ""
	if st.restRaw != "" {
		out.URL.RawPath = target.EscapedPath() + st.restRaw
	}
	out.URL.RawQuery = pr.In.URL.RawQuery
	out.Host = ""

	// The NeuBird credential never goes upstream, and the client cannot
	// supply its own APIM key or backend credential.
	h := out.Header
	h.Del("Authorization")
	h.Del("Proxy-Authorization")
	if c.ClientAuthHeader != "" {
		h.Del(c.ClientAuthHeader)
	}
	h.Del("Ocp-Apim-Subscription-Key")
	for k := range c.ResolvedHeaders {
		h.Del(k)
	}
	if !c.Passthrough {
		h.Del("Accept-Encoding")
		h.Del("TE")
	}
	for k, v := range c.ResolvedHeaders {
		h.Set(k, v)
	}
	if c.BasicAuth != nil {
		out.SetBasicAuth(c.BasicAuth.Username, c.BasicAuth.Password)
	}
}

// blockError is a fail-closed refusal; its reason is safe to return to
// NeuBird and to log.
type blockError struct{ reason string }

func (e *blockError) Error() string { return "redaction blocked: " + e.reason }

func (s *Server) modifyResponse(resp *http.Response) error {
	st := state(resp.Request.Context())
	s.rewriteLocation(resp, st)
	if st.conn.Passthrough {
		return nil
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return &blockError{"upgrade_not_supported"}
	}
	if resp.Body == nil || resp.Body == http.NoBody || resp.ContentLength == 0 ||
		resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified ||
		resp.Request.Method == http.MethodHead {
		return nil
	}
	h := resp.Header

	switch enc := strings.ToLower(strings.TrimSpace(h.Get("Content-Encoding"))); enc {
	case "", "identity":
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return &blockError{"bad_gzip"}
		}
		resp.Body = struct {
			io.Reader
			io.Closer
		}{zr, resp.Body}
		h.Del("Content-Encoding")
	default:
		return &blockError{"unsupported_content_encoding"}
	}

	kind := classify(h.Get("Content-Type"))
	if kind == kindSSE {
		st.sse = redact.NewSSEReader(resp.Body, s.engine, st.stats, s.cfg.MaxBodyBytes)
		resp.Body = st.sse
		resp.ContentLength = -1
		h.Del("Content-Length")
		return nil
	}
	if kind == kindUnsupported {
		return &blockError{"unsupported_content_type"}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxBodyBytes+1))
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("read upstream body: %w", err)
	}
	if int64(len(body)) > s.cfg.MaxBodyBytes {
		return &blockError{"body_too_large"}
	}
	if len(body) > 0 {
		var out []byte
		if kind == kindJSON {
			out, err = s.engine.JSON(body, st.stats)
		}
		if kind == kindText || err != nil {
			// Invalid JSON still gets value rules; only key rules are lost.
			out = s.engine.Text(body, st.stats)
		}
		body = out
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Del("Content-MD5")
	h.Del("Digest")
	return nil
}

// rewriteLocation maps a redirect to the upstream back onto the proxy, so
// connectors that follow it keep going through redaction.
func (s *Server) rewriteLocation(resp *http.Response, st *reqState) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	target := st.conn.UpstreamURL
	var rest string
	switch base := target.Scheme + "://" + target.Host + target.Path; {
	case hasPathPrefix(loc, base):
		rest = loc[len(base):]
	case strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, "//") && hasPathPrefix(loc, target.Path):
		rest = loc[len(target.Path):]
	default:
		return
	}
	if rest == "" || rest[0] == '?' {
		rest = "/" + rest
	}
	resp.Header.Set("Location", st.prefix+rest)
}

func hasPathPrefix(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	return len(s) == len(prefix) || s[len(prefix)] == '/' || s[len(prefix)] == '?' || strings.HasSuffix(prefix, "/")
}

type bodyKind int

const (
	kindUnsupported bodyKind = iota
	kindJSON
	kindText
	kindSSE
)

func classify(contentType string) bodyKind {
	if strings.TrimSpace(contentType) == "" {
		return kindText
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return kindUnsupported
	}
	switch {
	case mt == "text/event-stream":
		return kindSSE
	case mt == "application/json", strings.HasSuffix(mt, "+json"),
		mt == "application/x-ndjson", mt == "application/jsonl", mt == "application/json-seq":
		return kindJSON
	case strings.HasPrefix(mt, "text/"),
		mt == "application/xml", strings.HasSuffix(mt, "+xml"),
		mt == "application/csv", mt == "application/javascript",
		mt == "application/x-www-form-urlencoded", mt == "application/yaml":
		return kindText
	}
	return kindUnsupported
}

func (s *Server) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	st := state(r.Context())
	var be *blockError
	if errors.As(err, &be) {
		st.blocked = be.reason
		s.Metrics.Blocked.Inc(st.conn.Name, be.reason)
		writeError(w, http.StatusBadGateway, "redaction_blocked", be.reason)
		return
	}
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds max_body_bytes")
		return
	}
	s.log.Warn("upstream error", "connection", st.conn.Name, "error", err.Error())
	writeError(w, http.StatusBadGateway, "upstream_unavailable", "upstream request failed")
}

func (s *Server) audit(r *http.Request, st *reqState, status, nbytes int, d time.Duration) {
	// Paths can carry identifiers (ServiceNow sys_ids, user names); the
	// audit line gets the same value rules, counted separately.
	path := s.engine.String(st.rest, redact.Stats{})
	attrs := []any{
		"connection", st.conn.Name,
		"method", r.Method,
		"path", path,
		"status", status,
		"bytes", nbytes,
		"duration_ms", d.Milliseconds(),
		"redactions", st.stats.Total(),
	}
	if len(st.stats) > 0 {
		attrs = append(attrs, "rules", map[string]int(st.stats))
	}
	if st.blocked != "" {
		attrs = append(attrs, "blocked", st.blocked)
	}
	s.log.Info("request", attrs...)
}

func writeError(w http.ResponseWriter, code int, kind, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Del("Content-Length")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": kind, "reason": reason})
}

// recorder captures status and bytes. Unwrap keeps Flush reachable through
// http.ResponseController, which ReverseProxy uses to stream SSE.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 && code >= 200 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
