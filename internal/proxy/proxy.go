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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/metrics"
	"github.com/neubirdai/neubird-proxy/internal/redact"
	"github.com/neubirdai/neubird-proxy/internal/tunnel"
)

type Server struct {
	cfg    *config.Config
	engine *redact.Engine
	log    *slog.Logger
	rp     *httputil.ReverseProxy
	// rpDest serves open mode (neubird_destinations): same hooks, but a
	// transport that won't dial loopback, link-local or unspecified
	// addresses, since the host comes from the request.
	rpDest   *httputil.ReverseProxy
	dest     *config.NeubirdDestinations
	byName   map[string]*config.Connection
	byHost   map[string]*config.Connection
	tokens   map[string][][32]byte // connection name -> accepted token hashes
	limiters map[string]*bucket
	fields   map[string]*redact.Fields // connection name -> response allowlist
	tools    map[string]map[string]bool
	inflight chan struct{} // max_concurrent_requests
	buffered chan struct{} // max_concurrent_buffered
	// mem bounds buffered bodies' memory when the memory limit is known
	// (SetMemoryLimit); maxBuffered is the largest body that may be
	// buffered: max_body_bytes, or less if that couldn't fit.
	mem         *memBudget
	maxBuffered int64
	Metrics     *Metrics
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
	destTransport := transport
	if transport == nil {
		t, err := newTransport(cfg)
		if err != nil {
			return nil, err
		}
		transport = t
		dt := t.Clone()
		dt.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: destDialControl}).DialContext
		destTransport = dt
	}
	s := &Server{
		cfg:      cfg,
		engine:   engine,
		log:      log,
		byName:   map[string]*config.Connection{},
		byHost:   map[string]*config.Connection{},
		tokens:   map[string][][32]byte{},
		limiters: map[string]*bucket{},
		fields:   map[string]*redact.Fields{},
		tools:    map[string]map[string]bool{},
		inflight: make(chan struct{}, cfg.MaxConcurrentRequests),
		buffered: make(chan struct{}, cfg.MaxConcurrentBuffered),
		Metrics:  newMetrics(),
	}
	s.maxBuffered = cfg.MaxBodyBytes
	conns := make([]*config.Connection, 0, len(cfg.Connections)+1)
	for i := range cfg.Connections {
		c := &cfg.Connections[i]
		s.byName[c.Name] = c
		if c.Host != "" {
			s.byHost[c.Host] = c
		}
		conns = append(conns, c)
	}
	if d := cfg.NeubirdDestinations; d != nil {
		// Registered for tokens, limits and fields, never routable by name.
		s.dest = d
		conns = append(conns, d.Conn)
	}
	for _, c := range conns {
		for _, t := range c.ClientTokens {
			s.tokens[c.Name] = append(s.tokens[c.Name], sha256.Sum256([]byte(t)))
		}
		if c.RateLimit != nil {
			s.limiters[c.Name] = newBucket(c.RateLimit.RequestsPerSecond, c.RateLimit.Burst)
		}
		if len(c.ResponseFields) > 0 {
			f, err := redact.NewFields(c.ResponseFields)
			if err != nil {
				return nil, fmt.Errorf("connection %s: %w", c.Name, err)
			}
			s.fields[c.Name] = f
		}
		if len(c.MCPTools) > 0 {
			s.tools[c.Name] = map[string]bool{}
			for _, t := range c.MCPTools {
				s.tools[c.Name][t] = true
			}
		}
	}
	s.rp = &httputil.ReverseProxy{
		Rewrite:        s.rewrite,
		ModifyResponse: s.modifyResponse,
		ErrorHandler:   s.errorHandler,
		Transport:      transport,
		ErrorLog:       slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	if s.dest != nil {
		rp := *s.rp
		rp.Transport = destTransport
		s.rpDest = &rp
	}
	return s, nil
}

// destDialControl guards open mode's dials; tests swap it to reach a fake
// upstream on loopback.
var destDialControl = refuseInternalAddresses

// refuseInternalAddresses stops open mode from reaching the pod itself, the
// node's or cloud's metadata service (169.254.169.254) and other link-local
// or unspecified addresses, whatever the destination host resolved to. It
// sees the address actually dialed, so a name that resolves there is caught
// too. (Behind HTTPS_PROXY, that is the outbound proxy's address.)
//
// Also refused: cloud metadata and host-agent addresses outside link-local
// (Azure WireServer, Alibaba Cloud, AWS IMDS over IPv6), and the pod's own
// addresses, so a destination can't reach the proxy's admin port.
func refuseInternalAddresses(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() || isMetadataOrSelf(ip) {
		return fmt.Errorf("destination address %s is not allowed", host)
	}
	return nil
}

var metadataNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"168.63.129.16/32",   // Azure WireServer
		"100.100.100.200/32", // Alibaba Cloud metadata
		"fd00:ec2::254/128",  // AWS IMDS over IPv6
	} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// ownAddrs are the pod's interface addresses, read once.
var ownAddrs = sync.OnceValue(func() []net.IP {
	var out []net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out = append(out, n.IP)
		}
	}
	return out
})

func isMetadataOrSelf(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range metadataNets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, own := range ownAddrs() {
		if own.Equal(ip) {
			return true
		}
	}
	return false
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
	id      string
	conn    *config.Connection
	prefix  string // "/splunk" for path routing, "" for host routing
	rest    string // path after the prefix, decoded
	restRaw string // same, escaped as received
	stats   redact.Stats
	blocked string
	// dest is the open-mode destination (scheme://host:port), and destErr
	// why it can't be used; set only for /_neubird/dest requests.
	dest    string
	destErr string
	// credentials is "neubird" when an open-mode request carried a
	// NeuBird-held backend credential that was forwarded.
	credentials string
	// stream is the redacting reader for a streamed body (SSE or
	// multi-document JSON); its error explains a cut stream.
	stream interface{ Err() error }
}

type stateKey struct{}

func state(ctx context.Context) *reqState { return ctx.Value(stateKey{}).(*reqState) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &recorder{ResponseWriter: w}

	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		rec.Header().Set("Retry-After", "1")
		writeError(rec, http.StatusServiceUnavailable, "overloaded", "too many concurrent requests")
		s.Metrics.Requests.Inc("_overloaded", "503")
		return
	}

	if hasDotSegment(r.URL.Path) {
		// /elastic/../splunk/... would be routed as elastic (passthrough)
		// and then normalized by APIM to splunk, skipping redaction.
		writeError(rec, http.StatusBadRequest, "invalid_path", "path must not contain . or .. segments")
		s.Metrics.Requests.Inc("_invalid", "400")
		return
	}

	if r.URL.Path == statusPath {
		s.serveStatus(rec, r)
		return
	}

	st, ok := s.routeDest(r)
	if !ok {
		st, ok = s.route(r)
	}
	if !ok && !s.anyTokenValid(r) {
		// Without a token, an unknown name looks like any other refusal,
		// so names can't be probed.
		writeError(rec, http.StatusUnauthorized, "unauthorized", "missing or invalid proxy token")
		s.Metrics.Requests.Inc("_unknown", "401")
		return
	}
	if !ok {
		writeError(rec, http.StatusNotFound, "unknown_connection", "no connection matches this host or path")
		s.Metrics.Requests.Inc("_unknown", "404")
		return
	}
	name := st.conn.Name
	st.id = requestID(r.Header.Get("X-Request-Id"))
	rec.Header().Set("X-Request-Id", st.id)

	defer func() {
		p := recover()
		status := rec.status
		if p != nil {
			status = 0 // stream aborted mid-body
			if st.stream != nil {
				switch err := st.stream.Err(); {
				case errors.Is(err, redact.ErrEventTooLarge):
					st.blocked = "sse_event_too_large"
				case errors.Is(err, redact.ErrNotText):
					st.blocked = "sse_not_text"
				case errors.Is(err, redact.ErrDocTooLarge):
					st.blocked = "json_doc_too_large"
				case errors.Is(err, redact.ErrStreamNotJSON):
					st.blocked = "json_stream_invalid"
				}
				if st.blocked != "" {
					s.Metrics.Blocked.Inc(name, st.blocked)
				}
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
	if st.destErr != "" {
		// Checked after the token, so a caller without one learns nothing
		// about which hosts are allowed.
		st.blocked = "destination_not_allowed"
		s.Metrics.Blocked.Inc(name, st.blocked)
		writeError(rec, http.StatusForbidden, "destination_not_allowed", st.destErr)
		return
	}
	if !st.conn.MethodSet[r.Method] {
		st.blocked = "method_not_allowed"
		s.Metrics.Blocked.Inc(name, st.blocked)
		rec.Header().Set("Allow", allowHeader(st.conn))
		writeError(rec, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed on this connection")
		return
	}
	if !pathAllowed(st.conn, st.rest) {
		st.blocked = "path_not_allowed"
		s.Metrics.Blocked.Inc(name, st.blocked)
		writeError(rec, http.StatusForbidden, "path_not_allowed", "path not allowed on this connection")
		return
	}
	if b := s.limiters[name]; b != nil && !b.allow() {
		st.blocked = "rate_limited"
		s.Metrics.Blocked.Inc(name, st.blocked)
		rec.Header().Set("Retry-After", "1")
		writeError(rec, http.StatusTooManyRequests, "rate_limited", "connection rate limit exceeded")
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
	if len(st.conn.RequestDenyRes) > 0 || s.tools[name] != nil {
		reason, err := s.checkRequest(st.conn, r)
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			writeError(rec, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds max_body_bytes")
			return
		case err != nil:
			writeError(rec, http.StatusBadRequest, "bad_request", "could not read request body")
			return
		case reason != "":
			st.blocked = "request_denied"
			s.Metrics.Blocked.Inc(name, st.blocked)
			writeError(rec, http.StatusForbidden, "request_denied", reason)
			return
		}
	}

	rp := s.rp
	if st.dest != "" {
		rp = s.rpDest
	}
	rp.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), stateKey{}, st)))
}

// hasDotSegment reports whether the decoded path, or the path decoded once
// more (for upstreams that double-decode), has a "." or ".." segment.
// Backslashes count as separators, as some servers treat them so.
func hasDotSegment(p string) bool {
	check := func(p string) bool {
		for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
			// Servlet containers (Tomcat, Jetty, Spring) drop ;params from
			// a segment before resolving it, so "..;x" is ".." to them.
			seg, _, _ = strings.Cut(seg, ";")
			if seg == "." || seg == ".." {
				return true
			}
		}
		return false
	}
	if check(p) {
		return true
	}
	if twice, err := url.PathUnescape(p); err == nil && twice != p {
		return check(twice)
	}
	return false
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

// DestPathPrefix is where open-mode requests arrive:
// /_neubird/dest/<path>, with the destination in DestinationHeader.
const (
	DestPathPrefix    = "/_neubird/dest"
	DestinationHeader = "X-Neubird-Destination"
)

// routeDest handles an open-mode request (neubird_destinations): the
// destination comes from DestinationHeader and must match the configured
// host patterns. The returned state carries a per-request copy of the shared
// policy with that upstream; a destination that can't be used is recorded in
// destErr and refused once the token has been checked.
func (s *Server) routeDest(r *http.Request) (*reqState, bool) {
	if s.dest == nil {
		return nil, false
	}
	p := r.URL.Path
	if p != DestPathPrefix && !strings.HasPrefix(p, DestPathPrefix+"/") {
		return nil, false
	}
	conn := *s.dest.Conn
	st := &reqState{conn: &conn, prefix: DestPathPrefix, rest: strings.TrimPrefix(p, DestPathPrefix), stats: redact.Stats{}}
	if raw := r.URL.EscapedPath(); strings.HasPrefix(raw, DestPathPrefix+"/") || raw == DestPathPrefix {
		st.restRaw = strings.TrimPrefix(raw, DestPathPrefix)
	}
	u, reason := s.parseDestination(r.Header.Get(DestinationHeader))
	if reason != "" {
		st.destErr = reason
		return st, true
	}
	conn.UpstreamURL = u
	st.dest = u.Scheme + "://" + u.Host
	return st, true
}

// parseDestination turns DestinationHeader into the upstream base URL, or
// says why it can't be used.
func (s *Server) parseDestination(v string) (*url.URL, string) {
	if v == "" {
		return nil, DestinationHeader + " is required"
	}
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, "destination must be scheme://host[:port]"
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, "destination must be scheme://host[:port], nothing more"
	}
	if u.Scheme == "http" && !s.cfg.AllowHTTPUpstreams {
		return nil, "plain http destinations need allow_http_upstreams"
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	if !s.dest.MatchDestination(host, port) {
		return nil, "destination host is not in neubird_destinations.hosts"
	}
	// The port was only filled in for matching; the upstream Host header
	// keeps the destination as given.
	return &url.URL{Scheme: u.Scheme, Host: strings.ToLower(u.Host)}, ""
}

func allowHeader(c *config.Connection) string {
	var ms []string
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		if c.MethodSet[m] {
			ms = append(ms, m)
		}
	}
	return strings.Join(ms, ", ")
}

func pathAllowed(c *config.Connection, rest string) bool {
	if len(c.PathRes) == 0 {
		return true
	}
	if rest == "" {
		rest = "/"
	}
	for _, re := range c.PathRes {
		if re.MatchString(rest) {
			return true
		}
	}
	return false
}

// checkRequest applies request_deny_patterns and mcp_tools, returning a
// reason to refuse the request, or "". Deny patterns match the query string
// and body, raw and URL-decoded, since Splunk takes its search as a form
// field. The body is buffered (it is already capped at max_body_bytes) and
// restored for the upstream.
func (s *Server) checkRequest(c *config.Connection, r *http.Request) (string, error) {
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		if s.mem != nil {
			// The body, and the decoded copies matched below.
			size := s.cfg.MaxBodyBytes
			if r.ContentLength >= 0 && r.ContentLength < size {
				size = r.ContentLength
			}
			reserve := s.mem.clamp(size * requestBufferFactor)
			if err := s.mem.acquire(r.Context(), reserve); err != nil {
				return "", err
			}
			defer s.mem.release(reserve)
		}
		var err error
		body, err = io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return "", err
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}
	if tools := s.tools[c.Name]; tools != nil && r.Method == http.MethodPost {
		if reason := checkMCPTools(body, tools); reason != "" {
			return reason, nil
		}
	}
	candidates := []string{r.URL.RawQuery, string(body)}
	for _, raw := range []string{r.URL.RawQuery, string(body)} {
		// Decoded leniently: one bad escape must not hide the rest from
		// the patterns, since upstream decoders are lenient too.
		if dec := lenientUnescape(raw); dec != raw {
			candidates = append(candidates, dec)
		}
	}
	// JSON string escapes (\u007c for |) are decoded by the upstream too.
	if dec, ok := jsonStrings(body); ok {
		candidates = append(candidates, dec)
	}
	for i, re := range c.RequestDenyRes {
		for _, cand := range candidates {
			if re.MatchString(cand) {
				return fmt.Sprintf("request matches request_deny_patterns[%d]", i), nil
			}
		}
	}
	return "", nil
}

// requestBufferFactor is how many times its size a request body may take
// while checked: the body and its decoded copies.
const requestBufferFactor = 4

// lenientUnescape decodes %XX escapes and + as a space, leaving any
// malformed escape as it is, as most form decoders do.
func lenientUnescape(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			b.WriteByte(' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c >= 'a':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// jsonStrings returns every string (keys included) in a JSON body,
// decoded, one per line, or false if the body isn't JSON or has no
// escapes worth decoding.
func jsonStrings(body []byte) (string, bool) {
	if !bytes.Contains(body, []byte(`\`)) || !json.Valid(body) {
		return "", false
	}
	var b strings.Builder
	dec := json.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if s, ok := tok.(string); ok {
			b.WriteString(s)
			b.WriteByte('\n')
		}
	}
	return b.String(), true
}

// checkMCPTools refuses a JSON-RPC message or batch that calls a tool not
// in the allowlist. A body that is not JSON-RPC is refused too: on an MCP
// connection it cannot be checked.
func checkMCPTools(body []byte, tools map[string]bool) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return ""
	}
	var raws []json.RawMessage
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &raws); err != nil {
			return "body is not JSON-RPC"
		}
	} else {
		raws = []json.RawMessage{trimmed}
	}
	for _, raw := range raws {
		m, err := strictObject(raw)
		if err != nil {
			return "body is not JSON-RPC: " + err.Error()
		}
		var method string
		if v, ok := m["method"]; ok && json.Unmarshal(v, &method) != nil {
			return "body is not JSON-RPC"
		}
		if method != "tools/call" {
			continue
		}
		params, err := strictObject(m["params"])
		if err != nil {
			return "tools/call params: " + err.Error()
		}
		var name string
		if err := json.Unmarshal(params["name"], &name); err != nil {
			return "tools/call without a tool name"
		}
		if !tools[name] {
			return fmt.Sprintf("MCP tool %q is not in mcp_tools", name)
		}
	}
	return ""
}

// foldKey maps every rune to the smallest in its Unicode simple-fold
// orbit, so two keys fold equal exactly when strings.EqualFold says so.
func foldKey(s string) string {
	return strings.Map(func(r rune) rune {
		min := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < min {
				min = f
			}
		}
		return min
	}, s)
}

// strictObject decodes a JSON object whose keys are unambiguous: a key
// that repeats, or differs from another only in case, is refused, since
// parsers disagree on which one wins (Go's encoding/json matches field
// names case-insensitively and keeps the last).
func strictObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	out := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		// Folded as encoding/json compares (Unicode simple folding, so
		// "ſ" matches "s" and the Kelvin sign "k").
		f := foldKey(key)
		if seen[f] {
			return nil, fmt.Errorf("ambiguous key %q", key)
		}
		seen[f] = true
		// A key that folds to one this check reads, in another spelling,
		// would be read by a case-insensitive server instead.
		for _, k := range []string{"method", "params", "name"} {
			if key != k && strings.EqualFold(key, k) {
				return nil, fmt.Errorf("key %q is a variant of %q", key, k)
			}
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[key] = v
	}
	if _, err := dec.Token(); err != nil { // '}'
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the object")
	}
	return out, nil
}

// anyTokenValid reports whether r carries a token that opens some
// connection, or neubird_destinations.
func (s *Server) anyTokenValid(r *http.Request) bool {
	for _, c := range s.byName {
		if s.authenticate(c, r) {
			return true
		}
	}
	return s.dest != nil && s.authenticate(s.dest.Conn, r)
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
	// Hash both sides so the comparison is constant time regardless of
	// length, and check every accepted token so timing does not reveal
	// which one matched.
	sum := sha256.Sum256([]byte(presented))
	ok := 0
	for _, t := range s.tokens[c.Name] {
		ok |= subtle.ConstantTimeCompare(sum[:], t[:])
	}
	return ok == 1
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

	// Only allowlisted client headers go upstream. That drops the NeuBird
	// credential, cookies, and anything that steers APIM (Ocp-Apim-Trace,
	// a client-supplied subscription key).
	h := http.Header{}
	for k, vs := range out.Header {
		if c.HeaderSet[k] {
			h[k] = vs
		}
	}
	if c.Passthrough {
		// Nothing is inspected, so compression and ranges are harmless.
		for _, k := range []string{"Accept-Encoding", "Range", "If-Range"} {
			if v, ok := out.Header[k]; ok {
				h[k] = v
			}
		}
	}
	h.Set("X-Request-Id", st.id)
	if c.NeuBirdCredentials {
		for k := range c.CredentialHeaderSet {
			if vs := out.Header.Values(config.UpstreamCredentialPrefix + k); len(vs) > 0 {
				h[k] = vs
				st.credentials = "neubird"
			}
		}
	}
	out.Header = h
	// Accept-Encoding, Range and If-Range are not in the allowlist for
	// redacting connections: bodies must arrive whole and uncompressed, and
	// a value split across two partial bodies matches in neither.
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
	// Backend session cookies would let the holder reach the backend
	// without the proxy (a ServiceNow session works directly against the
	// SaaS instance). APIM's own headers describe MetLife's gateway.
	h := resp.Header
	h.Del("Set-Cookie")
	h.Del("Set-Cookie2")
	for k := range h {
		if strings.HasPrefix(k, "Ocp-Apim-") {
			h.Del(k)
		}
	}
	if st.conn.Passthrough {
		return nil
	}
	// Trailers arrive after the body and would skip header redaction.
	h.Del("Trailer")
	resp.Trailer = nil
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return &blockError{"upgrade_not_supported"}
	}
	if resp.StatusCode == http.StatusPartialContent {
		return &blockError{"partial_content"}
	}
	s.redactHeaders(resp.Header, st.stats)
	if resp.Body == nil || resp.Body == http.NoBody || resp.ContentLength == 0 ||
		resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified ||
		resp.Request.Method == http.MethodHead {
		return nil
	}

	gzipped := false
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
		gzipped = true
	default:
		return &blockError{"unsupported_content_encoding"}
	}

	// An upstream may not stall partway through a body for long: that
	// would hold buffers, budget and a request slot.
	idle := newIdleBody(resp.Body, streamIdleTimeout)
	resp.Body = idle

	kind := classify(h.Get("Content-Type"))
	fields := s.fields[st.conn.Name]
	if kind == kindSSE {
		sse := redact.NewSSEReader(resp.Body, s.engine, st.stats, s.maxBuffered).WithFields(fields)
		if s.mem != nil {
			sse.WithBudget(ctxBudget{s.mem, resp.Request.Context()})
		}
		// A stream may idle between events, but not halfway through one.
		idle.whilePending(sse.Pending)
		st.stream = sse
		resp.Body = &dropTrailers{ReadCloser: sse, resp: resp}
		resp.ContentLength = -1
		h.Del("Content-Length")
		return nil
	}
	if kind == kindUnsupported {
		return &blockError{"unsupported_content_type"}
	}
	if fields != nil && kind != kindJSON {
		// A field allowlist can only be enforced on JSON.
		return &blockError{"not_json"}
	}

	// Bound how many bodies are buffered at once, and, when the memory
	// limit is known, how much memory they may take together: each
	// reserves bufferFactor times its size (its declared length, or the
	// cap when it has none).
	select {
	case s.buffered <- struct{}{}:
		defer func() { <-s.buffered }()
	case <-resp.Request.Context().Done():
		resp.Body.Close()
		return resp.Request.Context().Err()
	}
	if s.mem != nil {
		size := s.maxBuffered
		if n := resp.ContentLength; n >= 0 && n < size && !gzipped {
			size = n
		}
		reserve := s.mem.clamp(size * bufferFactor)
		if err := s.mem.acquire(resp.Request.Context(), reserve); err != nil {
			resp.Body.Close()
			return err
		}
		defer s.mem.release(reserve)
	}

	if kind == kindJSON {
		// The first document is redacted here, before any header is sent,
		// so a single-document body (ServiceNow, most APIs) is still
		// all-or-nothing with an exact Content-Length. Further documents
		// (Splunk export) stream: each is sent as soon as it is redacted.
		// A length is only meaningful for the bytes we decode; gzip was
		// unwrapped above, so its declared length no longer applies.
		knownLen := resp.ContentLength
		if gzipped {
			knownLen = -1
		}
		js, single, raw, err := redact.NewJSONStream(resp.Body, s.engine, st.stats, s.maxBuffered, fields, knownLen)
		switch {
		case errors.Is(err, redact.ErrDocTooLarge):
			resp.Body.Close()
			return &blockError{"body_too_large"}
		case err != nil && fields != nil:
			resp.Body.Close()
			return &blockError{"not_json"}
		case err != nil:
			// Labeled JSON but isn't: the text path below re-reads what
			// the decoder consumed, then the rest.
			rest := resp.Body
			resp.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(raw), rest), rest}
			kind = kindText
		case single:
			resp.Body.Close()
			return setBody(resp, js.Bytes())
		default:
			// Later documents are decoded after this returns: each within
			// the budget, and the upstream may not stall halfway through.
			if s.mem != nil {
				js.WithBudget(ctxBudget{s.mem, resp.Request.Context()})
			}
			st.stream = js
			resp.Body = &dropTrailers{ReadCloser: js, resp: resp}
			resp.ContentLength = -1
			h.Del("Content-Length")
			h.Del("Content-MD5")
			h.Del("Digest")
			return nil
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBuffered+1))
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("read upstream body: %w", err)
	}
	if int64(len(body)) > s.maxBuffered {
		return &blockError{"body_too_large"}
	}
	if len(body) > 0 && !redact.IsText(body) {
		// e.g. gzip bytes labeled text/plain with no Content-Encoding.
		return &blockError{"not_text"}
	}
	if len(body) > 0 {
		// Text, or JSON that did not parse: value rules still apply, only
		// key rules are lost.
		body = s.engine.Text(body, st.stats)
	}
	return setBody(resp, body)
}

// dropTrailers clears resp.Trailer when a streamed body ends. The
// transport fills in trailers only once the upstream body hits EOF, after
// modifyResponse has returned, and ReverseProxy forwards whatever is there
// then; trailers would bypass header redaction.
type dropTrailers struct {
	io.ReadCloser
	resp *http.Response
}

func (d *dropTrailers) Read(p []byte) (int, error) {
	n, err := d.ReadCloser.Read(p)
	if err != nil {
		d.resp.Trailer = nil
	}
	return n, err
}

// streamIdleTimeout is how long a response body may go without a byte
// (for event streams, only while an event is partly received).
var streamIdleTimeout = 2 * time.Minute

// idleBody closes its body when a Read waits longer than the timeout,
// which ends the Read with an error.
type idleBody struct {
	io.ReadCloser
	timeout time.Duration
	timer   *time.Timer
	pending atomic.Pointer[func() bool]
}

func newIdleBody(rc io.ReadCloser, timeout time.Duration) *idleBody {
	b := &idleBody{ReadCloser: rc, timeout: timeout}
	b.timer = time.AfterFunc(time.Hour, func() {
		if p := b.pending.Load(); p != nil && !(*p)() {
			return // idle between events
		}
		b.ReadCloser.Close()
	})
	b.timer.Stop()
	return b
}

// whilePending limits the timeout to when pending reports true.
func (b *idleBody) whilePending(pending func() bool) { b.pending.Store(&pending) }

func (b *idleBody) Read(p []byte) (int, error) {
	b.timer.Reset(b.timeout)
	n, err := b.ReadCloser.Read(p)
	b.timer.Stop()
	return n, err
}

func (b *idleBody) Close() error {
	b.timer.Stop()
	return b.ReadCloser.Close()
}

func setBody(resp *http.Response, body []byte) error {
	// The upstream body has been read to its end, so the transport may
	// have filled in trailers: drop them, they'd skip header redaction.
	resp.Trailer = nil
	resp.Header.Del("Trailer")
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Del("Content-MD5")
	resp.Header.Del("Digest")
	return nil
}

// redactHeaders applies value rules to every response header value. Link
// headers carry pagination URLs with query filters (ServiceNow
// sysparm_query=caller.email=...), and custom headers can carry anything.
func (s *Server) redactHeaders(h http.Header, st redact.Stats) {
	for k, vs := range h {
		for i, v := range vs {
			vs[i] = s.engine.String(v, st)
		}
		h[k] = vs
	}
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
	// A *url.Error embeds the full upstream URL, query string included; log
	// only the cause, and redact that too.
	cause := err
	var ue *url.Error
	if errors.As(err, &ue) {
		cause = ue.Err
	}
	s.log.Warn("upstream error", "connection", st.conn.Name, "error", s.engine.String(cause.Error(), redact.Stats{}))
	writeError(w, http.StatusBadGateway, "upstream_unavailable", "upstream request failed")
}

func (s *Server) audit(r *http.Request, st *reqState, status, nbytes int, d time.Duration) {
	// Paths can carry identifiers (ServiceNow sys_ids, user names); the
	// audit line gets the same value rules, counted separately.
	path := s.engine.String(st.rest, redact.Stats{})
	attrs := []any{
		"request_id", st.id,
		"connection", st.conn.Name,
		"remote_addr", r.RemoteAddr,
		"method", r.Method,
		"path", path,
		"status", status,
		"bytes", nbytes,
		"duration_ms", d.Milliseconds(),
		"redactions", st.stats.Total(),
	}
	if via := tunnel.Via(r.Context()); via != "" {
		attrs = append(attrs, "via", via)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Client-controlled: bounded, and only address-like characters.
		if len(xff) > 256 {
			xff = xff[:256]
		}
		xff = strings.Map(func(c rune) rune {
			if c == ',' || c == ' ' || c == '.' || c == ':' || c == '[' || c == ']' ||
				'0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
				return c
			}
			return '?'
		}, xff)
		attrs = append(attrs, "forwarded_for", xff)
	}
	// Parameter names, not values: enough to see what was asked for
	// (sysparm_query, search) without logging the data in the query.
	if q := r.URL.Query(); len(q) > 0 {
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, s.engine.String(k, redact.Stats{}))
		}
		sort.Strings(keys)
		attrs = append(attrs, "query_keys", keys)
	}
	if len(st.stats) > 0 {
		attrs = append(attrs, "rules", map[string]int(st.stats))
	}
	if st.blocked != "" {
		attrs = append(attrs, "blocked", st.blocked)
	}
	if st.credentials != "" {
		attrs = append(attrs, "credentials", st.credentials)
	}
	if st.dest != "" {
		attrs = append(attrs, "destination", st.dest)
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
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		// ReverseProxy relays upstream 1xx responses (103 Early Hints) with
		// their headers, before ModifyResponse can redact anything. Drop
		// them; they are optional hints.
		return
	}
	if r.status == 0 {
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

// requestID keeps the caller's X-Request-Id (the relay sets one on every
// request) so one ID follows a request through the relay's and the
// proxy's logs and upstream. Anything that isn't a short plain token is
// replaced, so a caller can't write odd text into the audit log.
func requestID(in string) string {
	if len(in) == 0 || len(in) > 64 {
		return newRequestID()
	}
	for _, c := range in {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '-') {
			return newRequestID()
		}
	}
	return in
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ServerTLSConfig builds the listener's TLS config: TLS 1.2 or later, and
// with tls.client_ca_file, a required client certificate from that CA.
func ServerTLSConfig(t *config.TLS) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	c := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if t.ClientCAFile != "" {
		pem, err := os.ReadFile(t.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("tls.client_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls.client_ca_file: no certificates found in %s", t.ClientCAFile)
		}
		c.ClientCAs = pool
		c.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return c, nil
}
