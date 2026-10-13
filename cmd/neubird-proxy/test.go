package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/metrics"
	"github.com/neubirdai/neubird-proxy/internal/tunnel"
)

// cmdTest diagnoses each connection in the order things fail: name
// resolution, TCP, TLS, then a real request sent through the proxy's own
// handler exactly as NeuBird would send it. For an MCP connection the
// request is initialize + tools/list, and the server's tools are compared
// with mcp_tools.
func cmdTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	cf.register(fs)
	method := fs.String("method", "", "probe method (default: MCP handshake for MCP connections, else GET)")
	path := fs.String("path", "", "probe path after the connection prefix (default: the first literal entry in paths, else /)")
	data := fs.String("data", "", "probe request body")
	contentType := fs.String("content-type", "application/json", "probe request Content-Type, when -data is set")
	show := fs.Bool("show", false, "print the redacted response body (first 2000 bytes)")
	timeout := fs.Duration("timeout", 30*time.Second, "per-request timeout")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: neubird-proxy test [flags] [connection | https://host[:port] ...]")
		fmt.Fprintln(stderr, "\nTests every connection, or the ones named. A URL is checked as a")
		fmt.Fprintln(stderr, "neubird_destinations host: the host patterns, then DNS, TCP and TLS.")
		fmt.Fprintln(stderr, "Needs the real secrets: run it in a")
		fmt.Fprintln(stderr, "proxy pod (kubectl exec <pod> -- /neubird-proxy test) or pass -env-file.")
		fs.PrintDefaults()
	}
	if fs.Parse(args) != nil {
		return 2
	}

	sec, err := loadSecrets(cf.envFile, false)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	cfg, engine, err := loadConfig(cf.config, sec)
	if err != nil {
		fmt.Fprintf(stdout, "config invalid, run 'neubird-proxy validate' for details:\n")
		for _, l := range splitErrors(err) {
			fmt.Fprintf(stdout, "  error: %s\n", l)
		}
		return 1
	}
	p, err := newInProcess(cfg, engine)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	var conns []*config.Connection
	var dests []string
	if fs.NArg() == 0 {
		for i := range cfg.Connections {
			conns = append(conns, &cfg.Connections[i])
		}
	}
	for _, name := range fs.Args() {
		if strings.Contains(name, "://") {
			if cfg.NeubirdDestinations == nil {
				fmt.Fprintf(stderr, "error: %s: the config has no neubird_destinations\n", name)
				return 2
			}
			dests = append(dests, name)
			continue
		}
		c, err := findConnection(cfg, name)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		conns = append(conns, c)
	}

	t := &tester{cfg: cfg, p: p, out: stdout, timeout: *timeout, show: *show}
	failed := 0
	for _, d := range dests {
		if !t.destination(d) {
			failed++
		}
		fmt.Fprintln(stdout)
	}
	if cfg.Tunnel != nil && fs.NArg() == 0 {
		if !t.tunnel() {
			failed++
		}
		fmt.Fprintln(stdout)
	}
	for _, c := range conns {
		probe := probeSpec{method: *method, path: *path, data: *data, contentType: *contentType}
		if !t.connection(c, probe) {
			failed++
		}
		fmt.Fprintln(stdout)
	}
	if failed > 0 {
		fmt.Fprintf(stdout, "%d check(s) FAILED\n", failed)
		return 1
	}
	if len(dests) > 0 && len(conns) == 0 {
		fmt.Fprintf(stdout, "all %d destinations OK\n", len(dests))
		return 0
	}
	fmt.Fprintf(stdout, "all %d connections OK\n", len(conns))
	return 0
}

// destination checks a host NeuBird would name: that neubird_destinations
// allows it, then DNS, TCP and TLS. No request is sent: the credentials for
// these hosts are NeuBird's.
func (t *tester) destination(raw string) bool {
	t.ok = true
	fmt.Fprintf(t.out, "%s -> neubird_destinations\n", raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		t.line("FAIL", "hosts", "%s is not scheme://host[:port]", raw)
		return false
	}
	d := t.cfg.NeubirdDestinations
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	if !d.MatchDestination(strings.ToLower(u.Hostname()), port) {
		t.line("FAIL", "hosts", "%s:%s is not in neubird_destinations.hosts (%s)", u.Hostname(), port, strings.Join(d.Hosts, ", "))
		return false
	}
	t.line("ok", "hosts", "allowed by neubird_destinations.hosts")
	c := *d.Conn
	c.UpstreamURL = &url.URL{Scheme: u.Scheme, Host: u.Host}
	return t.network(&c) && t.ok
}

type probeSpec struct{ method, path, data, contentType string }

type tester struct {
	cfg     *config.Config
	p       *inProcess
	out     io.Writer
	timeout time.Duration
	show    bool
	ok      bool
}

func (t *tester) line(status, step, format string, a ...any) {
	if status == "FAIL" {
		t.ok = false
	}
	fmt.Fprintf(t.out, "  %-4s  %-10s %s\n", status, step, fmt.Sprintf(format, a...))
}

func (t *tester) connection(c *config.Connection, probe probeSpec) bool {
	t.ok = true
	mode := ""
	if c.Passthrough {
		mode = " (passthrough: responses are NOT redacted)"
	}
	fmt.Fprintf(t.out, "%s -> %s%s\n", c.Name, c.Upstream, mode)
	if !t.network(c) {
		return false
	}
	if probe.method == "" && probe.path == "" && probe.data == "" && isMCP(c) {
		t.mcp(c)
	} else {
		t.http(c, probe)
	}
	return t.ok
}

// network checks DNS, TCP and TLS to the upstream directly, so a failure
// names its layer instead of surfacing as a bare 502.
func (t *tester) network(c *config.Connection) bool {
	u := c.UpstreamURL
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	if v := proxyEnv(u.Scheme); v != "" {
		t.line("info", "network", "an outbound proxy is configured (%s); skipping direct DNS/TCP/TLS checks", v)
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		t.line("FAIL", "dns", "%s: %v", host, err)
		return false
	}
	t.line("ok", "dns", "%s -> %s", host, strings.Join(addrs, ", "))

	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.line("FAIL", "tcp", "%s:%s: %v (firewall, security group or wrong port?)", host, port, err)
		return false
	}
	t.line("ok", "tcp", "%s:%s connected in %s", host, port, time.Since(start).Round(time.Millisecond))

	if u.Scheme != "https" {
		conn.Close()
		t.line("warn", "tls", "plain http: traffic to this upstream is not encrypted")
		return true
	}
	roots, err := t.roots()
	if err != nil {
		conn.Close()
		t.line("FAIL", "tls", "%v", err)
		return false
	}
	tc := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12})
	defer tc.Close()
	if err := tc.HandshakeContext(ctx); err != nil {
		var unknown x509.UnknownAuthorityError
		hint := ""
		if errors.As(err, &unknown) {
			hint = " (signed by a CA the proxy doesn't trust: set upstream_ca_file)"
		}
		t.line("FAIL", "tls", "%v%s", err, hint)
		return false
	}
	cert := tc.ConnectionState().PeerCertificates[0]
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	status := "ok"
	if days < 14 {
		status = "warn"
	}
	t.line(status, "tls", "%s, certificate %q from %q, expires in %d days", tlsVersion(tc.ConnectionState().Version),
		cert.Subject.CommonName, cert.Issuer.CommonName, days)
	return true
}

func (t *tester) roots() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if t.cfg.UpstreamCAFile != "" {
		pem, err := os.ReadFile(t.cfg.UpstreamCAFile)
		if err != nil {
			return nil, fmt.Errorf("upstream_ca_file: %w", err)
		}
		pool.AppendCertsFromPEM(pem)
	}
	return pool, nil
}

// send runs one request through the proxy and reports it. It returns the
// response when the proxy and the upstream both accepted the request.
func (t *tester) send(step string, req *http.Request) *httptest.ResponseRecorder {
	ctx, cancel := context.WithTimeout(req.Context(), t.timeout)
	defer cancel()
	start := time.Now()
	rec, audit, cut := t.p.do(req.WithContext(ctx))
	took := time.Since(start).Round(time.Millisecond)

	if kind, reason, ok := proxyError(rec); ok {
		t.line("FAIL", step, "refused by the proxy: %s (%s)%s", kind, reason, proxyHint(kind, reason))
		return nil
	}
	summary := fmt.Sprintf("HTTP %d, %s, %d bytes, %s; redactions: %s", rec.Code, contentTypeOf(rec), rec.Body.Len(), took, rulesSummary(audit))
	if cut {
		reason, _ := audit["blocked"].(string)
		t.line("FAIL", step, "%s; stream cut by the proxy: %s", summary, reason)
		return nil
	}
	switch {
	case rec.Code == 401 || rec.Code == 403:
		t.line("FAIL", step, "%s; the upstream rejected the credentials the proxy sent (check headers / upstream_basic_auth and their secrets)", summary)
	case rec.Code == 404:
		t.line("warn", step, "%s; reached the backend, but it has nothing at this path", summary)
	case rec.Code >= 500:
		t.line("FAIL", step, "%s; upstream error", summary)
	case rec.Code >= 400:
		t.line("warn", step, "%s", summary)
	default:
		t.line("ok", step, "%s", summary)
	}
	if t.show {
		b := rec.Body.Bytes()
		if len(b) > 2000 {
			b = append(b[:2000:2000], "..."...)
		}
		fmt.Fprintf(t.out, "        %s\n", strings.ReplaceAll(string(b), "\n", "\n        "))
	}
	if rec.Code >= 400 {
		return nil
	}
	return rec
}

func (t *tester) http(c *config.Connection, probe probeSpec) {
	method, path := probe.method, probe.path
	if method == "" {
		method = http.MethodGet
		if !c.MethodSet[method] && len(c.MethodSet) > 0 {
			method = strings.Split(allowHeaderOf(c.MethodSet), ",")[0]
		}
	}
	if path == "" {
		if path = literalPath(c); path == "" {
			path = "/"
		}
	}
	var body []byte
	ct := ""
	if probe.data != "" {
		body, ct = []byte(probe.data), probe.contentType
	}
	t.send("request", clientRequest(c, method, path, body, ct))
}

// mcp runs the MCP handshake and lists the server's tools, then compares
// them with the tool allowlist.
func (t *tester) mcp(c *config.Connection) {
	path := literalPath(c)
	if path == "" {
		path = "/"
	}
	rpc := func(step string, sid string, msg string) (*httptest.ResponseRecorder, map[string]any) {
		req := clientRequest(c, http.MethodPost, path, []byte(msg), "application/json")
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		rec := t.send(step, req)
		if rec == nil {
			return nil, nil
		}
		reply := jsonRPCReply(rec)
		if e, ok := reply["error"].(map[string]any); ok {
			t.line("FAIL", step, "JSON-RPC error %v: %v", e["code"], e["message"])
			return nil, nil
		}
		return rec, reply
	}

	rec, reply := rpc("initialize", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"neubird-proxy-test","version":"`+version+`"}}}`)
	if rec == nil {
		return
	}
	if r, ok := reply["result"].(map[string]any); ok {
		if si, ok := r["serverInfo"].(map[string]any); ok {
			t.line("info", "server", "%v %v, protocol %v", si["name"], si["version"], r["protocolVersion"])
		}
	}
	sid := rec.Header().Get("Mcp-Session-Id")
	note := clientRequest(c, http.MethodPost, path, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), "application/json")
	if sid != "" {
		note.Header.Set("Mcp-Session-Id", sid)
	}
	t.p.do(note)

	rec, reply = rpc("tools/list", sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if rec == nil {
		return
	}
	var server []string
	if r, ok := reply["result"].(map[string]any); ok {
		if tools, ok := r["tools"].([]any); ok {
			for _, tl := range tools {
				if m, ok := tl.(map[string]any); ok {
					if n, ok := m["name"].(string); ok {
						server = append(server, n)
					}
				}
			}
		}
	}
	sort.Strings(server)
	t.compareTools(c, server)
}

func (t *tester) compareTools(c *config.Connection, server []string) {
	if len(c.MCPTools) == 0 {
		t.line("warn", "tools", "%d tools, all allowed (no mcp_tools): %s", len(server), strings.Join(server, ", "))
		return
	}
	allowed := map[string]bool{}
	for _, n := range c.MCPTools {
		allowed[n] = true
	}
	onServer := map[string]bool{}
	var ok, blocked, missing []string
	for _, n := range server {
		onServer[n] = true
		if allowed[n] {
			ok = append(ok, n)
		} else {
			blocked = append(blocked, n)
		}
	}
	for _, n := range c.MCPTools {
		if !onServer[n] {
			missing = append(missing, n)
		}
	}
	t.line("ok", "tools", "%d of %d server tools allowed: %s", len(ok), len(server), strings.Join(ok, ", "))
	if len(blocked) > 0 {
		t.line("info", "tools", "blocked by mcp_tools: %s", strings.Join(blocked, ", "))
	}
	if len(missing) > 0 {
		t.line("warn", "tools", "in mcp_tools but not offered by the server (typo or renamed?): %s", strings.Join(missing, ", "))
	}
}

// jsonRPCReply decodes a JSON-RPC response sent as JSON or as SSE (the last
// data payload wins, as MCP streams end with the reply).
func jsonRPCReply(rec *httptest.ResponseRecorder) map[string]any {
	body := rec.Body.String()
	if strings.HasPrefix(contentTypeOf(rec), "text/event-stream") {
		var data []string
		for _, l := range strings.Split(body, "\n") {
			if strings.HasPrefix(l, "data:") {
				data = append(data, strings.TrimSpace(strings.TrimPrefix(l, "data:")))
			}
		}
		if len(data) == 0 {
			return nil
		}
		body = data[len(data)-1]
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(body), &m)
	return m
}

func contentTypeOf(rec *httptest.ResponseRecorder) string {
	ct := rec.Header().Get("Content-Type")
	if ct == "" {
		return "no content type"
	}
	return strings.TrimSpace(strings.Split(ct, ";")[0])
}

func proxyHint(kind, reason string) string {
	switch kind {
	case "path_not_allowed":
		return "; the probe path isn't in this connection's paths: pass -path"
	case "method_not_allowed":
		return "; pass -method with an allowed method"
	case "upstream_unavailable":
		return "; the proxy could not complete the request to the upstream"
	case "redaction_blocked":
		return "; the response can't be redacted, so NeuBird would get this error too"
	case "request_denied":
		return "; the probe matched request_deny_patterns or mcp_tools"
	}
	return ""
}

func proxyEnv(scheme string) string {
	for _, k := range []string{strings.ToUpper(scheme) + "_PROXY", scheme + "_proxy"} {
		if v := os.Getenv(k); v != "" {
			return k
		}
	}
	return ""
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return fmt.Sprintf("TLS 0x%x", v)
}

// tunnel checks the tunnel identity, then DNS, TCP and the mutual-TLS
// handshake to each relay.
func (t *tester) tunnel() bool {
	t.ok = true
	tc := t.cfg.Tunnel
	fmt.Fprintf(t.out, "tunnel -> %s\n", strings.Join(tc.Relays, ", "))
	id, err := tunnel.Load(tc)
	if err != nil {
		t.line("FAIL", "identity", "%v", err)
		return false
	}
	status := "ok"
	if id.DaysLeft() < 30 {
		status = "warn"
	}
	if id.Minted {
		t.line(status, "identity", "tenant %s, proxy %s; key %s (NeuBird must have this fingerprint on record)", id.Tenant, id.Proxy, id.Fingerprint)
	} else {
		t.line(status, "identity", "tenant %s, proxy %s; key %s; certificate expires in %d days", id.Tenant, id.Proxy, id.Fingerprint, int(id.DaysLeft()))
	}
	client := tunnel.New(tc, id, http.NotFoundHandler(), discardLog, &metrics.Registry{})
	for _, relay := range tc.Relays {
		host, port, _ := net.SplitHostPort(relay)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if proxyEnv("https") == "" {
			if addrs, err := net.DefaultResolver.LookupHost(ctx, host); err != nil {
				t.line("FAIL", "dns", "%s: %v", host, err)
				cancel()
				continue
			} else {
				t.line("ok", "dns", "%s -> %s", host, strings.Join(addrs, ", "))
			}
		}
		start := time.Now()
		state, err := client.Check(ctx, relay)
		cancel()
		if err != nil {
			t.line("FAIL", "relay", "%s:%s: %v", host, port, err)
			if tc.JoinToken != "" {
				t.line("info", "relay", "test doesn't spend the join token; if this key isn't enrolled yet, the proxy enrolls it when it starts")
			}
			continue
		}
		cert := state.PeerCertificates[0]
		t.line("ok", "relay", "%s: mutual TLS and %s in %s; relay certificate %q expires in %d days", relay,
			state.NegotiatedProtocol, time.Since(start).Round(time.Millisecond), cert.Subject.CommonName,
			int(time.Until(cert.NotAfter).Hours()/24))
	}
	return t.ok
}
