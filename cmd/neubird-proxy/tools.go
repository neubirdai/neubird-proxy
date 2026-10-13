package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/proxy"
	"github.com/neubirdai/neubird-proxy/internal/redact"
)

// Shared by the tool subcommands. None of them prints a secret's value:
// secrets are read from the environment (or an env file) and only ever
// used, counted or reported as present or missing.

// secrets resolves environment variables for a config: from an env file
// first (KEY=VALUE lines, as for docker --env-file), then the process
// environment. In offline mode a missing variable gets a placeholder that
// passes validation, and its name is recorded, so a config can be checked
// on a laptop that holds none of the secrets.
type secrets struct {
	file    map[string]string
	offline bool
	missing map[string]bool
}

func loadSecrets(envFile string, offline bool) (*secrets, error) {
	s := &secrets{file: map[string]string{}, offline: offline, missing: map[string]bool{}}
	if envFile == "" {
		return s, nil
	}
	f, err := os.Open(envFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE", envFile, n)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		s.file[strings.TrimSpace(k)] = v
	}
	return s, sc.Err()
}

// placeholder satisfies every rule a secret is checked against: tokens need
// 32 characters, and a join token is nbjt_ and 43 more.
var placeholder = "nbjt_" + strings.Repeat("x", 43)

func (s *secrets) lookup(name string) (string, bool) {
	if v, ok := s.file[name]; ok && v != "" {
		return v, true
	}
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v, true
	}
	if s.offline {
		s.missing[name] = true
		return placeholder, true
	}
	return "", false
}

func (s *secrets) missingNames() []string {
	var out []string
	for k := range s.missing {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// loadConfig parses and fully validates a config: the YAML, the rules
// (as the redaction engine compiles them) and what the proxy checks when
// it starts (field allowlists, the upstream CA file).
func loadConfig(path string, sec *secrets) (*config.Config, *redact.Engine, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.Parse(raw, sec.lookup)
	if err != nil {
		return nil, nil, err
	}
	engine, err := redact.New(cfg.Redaction)
	if err != nil {
		return nil, nil, err
	}
	if _, err := proxy.New(cfg, engine, discardLog, nil); err != nil {
		return nil, nil, err
	}
	return cfg, engine, nil
}

var discardLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// inProcess is the real proxy handler with its audit log captured, so a
// tool can send a request exactly as NeuBird would and read what the proxy
// decided about it.
type inProcess struct {
	srv  *proxy.Server
	logs *bytes.Buffer
}

func newInProcess(cfg *config.Config, engine *redact.Engine) (*inProcess, error) {
	logs := &bytes.Buffer{}
	srv, err := proxy.New(cfg, engine, slog.New(slog.NewJSONHandler(logs, nil)), nil)
	if err != nil {
		return nil, err
	}
	return &inProcess{srv: srv, logs: logs}, nil
}

// do sends one request through the proxy and returns the response and the
// request's audit line. A stream the proxy cuts mid-body (it panics with
// http.ErrAbortHandler, as net/http expects) is returned as what arrived
// before the cut, with cut set.
func (p *inProcess) do(req *http.Request) (rec *httptest.ResponseRecorder, audit map[string]any, cut bool) {
	rec = httptest.NewRecorder()
	p.logs.Reset()
	func() {
		defer func() {
			if r := recover(); r != nil {
				if r != http.ErrAbortHandler {
					panic(r)
				}
				cut = true
			}
		}()
		p.srv.ServeHTTP(rec, req)
	}()
	for _, line := range strings.Split(p.logs.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "request" {
			audit = m
		}
	}
	return rec, audit, cut
}

// clientRequest builds a request to a connection as NeuBird would send it:
// to its path prefix, with the proxy token in the form the connection
// expects.
func clientRequest(c *config.Connection, method, path string, body []byte, contentType string) *http.Request {
	var r io.Reader = http.NoBody
	if body != nil {
		r = bytes.NewReader(body)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// Path routing works for every connection, including ones that also
	// claim a host.
	req := httptest.NewRequest(method, "/"+c.Name+path, r)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json, text/event-stream, */*")
	token := ""
	if len(c.ClientTokens) > 0 {
		token = c.ClientTokens[0]
	}
	switch c.ClientAuth {
	case config.AuthNone:
	case config.AuthBasic:
		req.SetBasicAuth("neubird", token)
	case config.AuthHeader:
		req.Header.Set(c.ClientAuthHeader, token)
	default:
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func findConnection(cfg *config.Config, name string) (*config.Connection, error) {
	var names []string
	for i := range cfg.Connections {
		if cfg.Connections[i].Name == name {
			return &cfg.Connections[i], nil
		}
		names = append(names, cfg.Connections[i].Name)
	}
	return nil, fmt.Errorf("no connection %q (have: %s)", name, strings.Join(names, ", "))
}

// isMCP guesses whether a connection fronts an MCP server: it has an MCP
// tool allowlist, or its upstream or allowed paths mention mcp.
func isMCP(c *config.Connection) bool {
	if len(c.MCPTools) > 0 || strings.Contains(strings.ToLower(c.Upstream), "mcp") {
		return true
	}
	for _, p := range c.Paths {
		if strings.Contains(strings.ToLower(p), "mcp") {
			return true
		}
	}
	return false
}

// literalPath returns the first allowed path that is a plain path rather
// than a pattern, for use as a default probe.
func literalPath(c *config.Connection) string {
	for _, p := range c.Paths {
		if regexp.QuoteMeta(p) == p {
			return p
		}
	}
	return ""
}

// proxyErrors are the error kinds the proxy itself returns; anything else
// in an error response came from the upstream.
var proxyErrors = map[string]bool{
	"unauthorized": true, "unknown_connection": true, "invalid_path": true, "upgrade_not_supported": true,
	"method_not_allowed": true, "path_not_allowed": true, "request_denied": true, "request_too_large": true,
	"rate_limited": true, "redaction_blocked": true, "upstream_unavailable": true, "overloaded": true, "bad_request": true,
}

// proxyError reports the proxy's own refusal in a response, if it is one.
func proxyError(rec *httptest.ResponseRecorder) (kind, reason string, ok bool) {
	if rec.Code < 400 {
		return "", "", false
	}
	var e struct{ Error, Reason string }
	if json.Unmarshal(rec.Body.Bytes(), &e) != nil || !proxyErrors[e.Error] {
		return "", "", false
	}
	return e.Error, e.Reason, true
}

// rulesSummary renders an audit line's per-rule counts, e.g. "email 2, ipv4 1".
func rulesSummary(audit map[string]any) string {
	rules, _ := audit["rules"].(map[string]any)
	if len(rules) == 0 {
		return "none"
	}
	var parts []string
	for k, v := range rules {
		parts = append(parts, fmt.Sprintf("%s %v", k, v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// commonFlags are shared by the commands that read a config.
type commonFlags struct {
	config  string
	envFile string
}

func (c *commonFlags) register(fs interface {
	StringVar(*string, string, string, string)
}) {
	fs.StringVar(&c.config, "config", "/etc/neubird-proxy/config.yaml", "path to the YAML config")
	fs.StringVar(&c.envFile, "env-file", "", "read secrets from this KEY=VALUE file, in addition to the environment")
}
