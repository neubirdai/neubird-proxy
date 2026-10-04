// Package config loads and validates the proxy's YAML configuration.
//
// Secrets never appear in the file. Fields ending in _env name an
// environment variable, and header values may reference ${VAR}. Every
// referenced variable must be set and non-empty or loading fails.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultMaxBodyBytes          = 20 << 20
	DefaultHMACKeyEnv            = "REDACTION_HMAC_KEY"
	DefaultMaxConcurrentRequests = 256
	DefaultMaxConcurrentBuffered = 4
	// MinTokenLength is the shortest accepted proxy token. 32 characters of
	// a random token is well past brute-force range at any request rate.
	MinTokenLength = 32
)

// DefaultMethods is the method allowlist when a connection sets none:
// read-only.
var DefaultMethods = []string{"GET", "HEAD"}

// DefaultRequestHeaders are the client request headers forwarded upstream.
// Everything else (cookies, APIM trace and debug headers, X-Forwarded-*,
// arbitrary X- headers) is dropped. Connections add to this list with
// request_headers.
var DefaultRequestHeaders = []string{
	"Accept", "Accept-Language", "Content-Type", "User-Agent",
	"If-None-Match", "If-Modified-Since", "Cache-Control",
	"Last-Event-ID", "Mcp-Session-Id", "Mcp-Protocol-Version",
}

// Client auth modes: where the connector puts the NeuBird proxy token.
const (
	AuthBearer = "bearer" // Authorization: Bearer <token>
	AuthBasic  = "basic"  // Authorization: Basic <any user>:<token>
	AuthHeader = "header" // <client_auth_header>: <token>
)

const (
	MaskLabel = "label"
	MaskHMAC  = "hmac"
)

// Config is the file shape. Resolved values (secrets, parsed URLs) live on
// the same structs in unexported-by-convention fields tagged yaml:"-".
type Config struct {
	Listen         string `yaml:"listen"`
	AdminListen    string `yaml:"admin_listen"`
	TLS            *TLS   `yaml:"tls"`
	UpstreamCAFile string `yaml:"upstream_ca_file"`
	ClientTokenEnv string `yaml:"client_token_env"`
	// ClientTokenPreviousEnv is accepted alongside the current token, so a
	// rotation needs no coordinated cutover. Unset it once rotation is done.
	ClientTokenPreviousEnv string       `yaml:"client_token_previous_env"`
	AllowHTTPUpstreams     bool         `yaml:"allow_http_upstreams"`
	MaxBodyBytes           int64        `yaml:"max_body_bytes"`
	MaxConcurrentRequests  int          `yaml:"max_concurrent_requests"`
	MaxConcurrentBuffered  int          `yaml:"max_concurrent_buffered"`
	UpstreamDefaults       Upstream     `yaml:"upstream_defaults"`
	Connections            []Connection `yaml:"connections"`
	Redaction              Redaction    `yaml:"redaction"`
}

type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// ClientCAFile turns on mutual TLS: clients must present a certificate
	// signed by a CA in this PEM bundle, in addition to the proxy token.
	ClientCAFile string `yaml:"client_ca_file"`
}

type Upstream struct {
	Headers map[string]string `yaml:"headers"`
}

type Connection struct {
	Name             string            `yaml:"name"`
	Upstream         string            `yaml:"upstream"`
	Host             string            `yaml:"host"`
	ClientAuth       string            `yaml:"client_auth"`
	ClientAuthHeader string            `yaml:"client_auth_header"`
	Passthrough      bool              `yaml:"passthrough"`
	Headers          map[string]string `yaml:"headers"`
	BasicAuth        *BasicAuth        `yaml:"upstream_basic_auth"`
	OAuth2           *OAuth2           `yaml:"upstream_oauth2"`
	// ClientTokenEnv scopes a token to this connection instead of the
	// top-level one, so one leaked token does not open every backend.
	ClientTokenEnv      string     `yaml:"client_token_env"`
	Methods             []string   `yaml:"methods"`
	Paths               []string   `yaml:"paths"`
	RequestHeaders      []string   `yaml:"request_headers"`
	RequestDenyPatterns []string   `yaml:"request_deny_patterns"`
	RateLimit           *RateLimit `yaml:"rate_limit"`
	// ResponseFields is a JSON field allowlist (see redact.Fields); every
	// other string or number is masked, and non-JSON responses are refused.
	ResponseFields []string `yaml:"response_fields"`
	// MCPTools allowlists the tools a tools/call request may name.
	MCPTools []string `yaml:"mcp_tools"`

	UpstreamURL *url.URL `yaml:"-"`
	// ClientTokens are the accepted tokens: this connection's own, or the
	// top-level current and previous ones.
	ClientTokens []string `yaml:"-"`
	// PathRes match the whole path after the connection prefix. Empty
	// means every path is allowed.
	PathRes        []*regexp.Regexp `yaml:"-"`
	RequestDenyRes []*regexp.Regexp `yaml:"-"`
	MethodSet      map[string]bool  `yaml:"-"`
	// HeaderSet holds canonical request header names forwarded upstream.
	HeaderSet map[string]bool `yaml:"-"`
	// ResolvedHeaders is upstream_defaults.headers overlaid with this
	// connection's headers, with ${VAR} references expanded.
	ResolvedHeaders map[string]string `yaml:"-"`
}

// RateLimit is a token bucket per connection and per pod, so the
// effective limit is this times the replica count.
type RateLimit struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

// BasicAuth injects a static Basic credential upstream, for a backend
// MetLife does not front with APIM.
type BasicAuth struct {
	UsernameEnv string `yaml:"username_env"`
	PasswordEnv string `yaml:"password_env"`

	Username string `yaml:"-"`
	Password string `yaml:"-"`
}

// OAuth2 gets the upstream credential with the OAuth 2.0 client credentials
// grant (RFC 6749 section 4.4), for a backend that takes short-lived bearer
// tokens rather than a static key. The proxy holds the client secret; NeuBird
// never sees it or the tokens minted from it.
type OAuth2 struct {
	TokenURL        string   `yaml:"token_url"`
	ClientIDEnv     string   `yaml:"client_id_env"`
	ClientSecretEnv string   `yaml:"client_secret_env"`
	Scopes          []string `yaml:"scopes"`
	// Params are extra form fields for the token request, such as audience
	// (Auth0, Okta) or resource (Azure AD v1, RFC 8707).
	Params map[string]string `yaml:"params"`
	// AuthStyle is how the client authenticates to the token endpoint:
	// basic (client_secret_basic, the RFC's default) or body
	// (client_secret_post), for providers that accept only one.
	AuthStyle string `yaml:"auth_style"`

	ClientID       string   `yaml:"-"`
	ClientSecret   string   `yaml:"-"`
	TokenURLParsed *url.URL `yaml:"-"`
}

const (
	OAuth2AuthBasic = "basic"
	OAuth2AuthBody  = "body"
)

// oauth2ReservedParams are the token request's own fields, which params must
// not override.
var oauth2ReservedParams = map[string]bool{
	"grant_type": true, "client_id": true, "client_secret": true, "scope": true,
}

type Redaction struct {
	// Builtins nil means all built-in rules; an explicit empty list means none.
	Builtins           *[]string    `yaml:"builtins"`
	BlockedKeyPatterns []string     `yaml:"blocked_key_patterns"`
	Custom             []CustomRule `yaml:"custom"`
	AllowedValues      []string     `yaml:"allowed_values"`
	Mask               string       `yaml:"mask"`
	HMACKeyEnv         string       `yaml:"hmac_key_env"`

	HMACKey []byte `yaml:"-"`
}

type CustomRule struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

var (
	connNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	envRefRe   = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	// Paths the proxy answers itself are not valid connection names.
	reservedNames = map[string]bool{"healthz": true, "readyz": true, "metrics": true}
)

// Load reads, parses, resolves and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw, os.LookupEnv)
}

// Parse is Load without the file read, with an injectable env lookup.
func Parse(raw []byte, lookupEnv func(string) (string, bool)) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.resolve(lookupEnv); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) resolve(lookupEnv func(string) (string, bool)) error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	env := func(field, name string) string {
		if name == "" {
			fail("%s is required", field)
			return ""
		}
		v, ok := lookupEnv(name)
		if !ok || v == "" {
			fail("%s: environment variable %s is not set", field, name)
		}
		return v
	}

	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if c.AdminListen == "" {
		c.AdminListen = ":9090"
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if c.MaxBodyBytes < 0 {
		fail("max_body_bytes must be positive")
	}
	if c.MaxConcurrentRequests == 0 {
		c.MaxConcurrentRequests = DefaultMaxConcurrentRequests
	}
	if c.MaxConcurrentBuffered == 0 {
		c.MaxConcurrentBuffered = DefaultMaxConcurrentBuffered
	}
	if c.MaxConcurrentRequests < 0 || c.MaxConcurrentBuffered < 0 {
		fail("max_concurrent_requests and max_concurrent_buffered must be positive")
	}
	if c.TLS != nil && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		fail("tls: cert_file and key_file are both required")
	}

	token := func(field, name string) string {
		v := env(field, name)
		if v != "" && len(v) < MinTokenLength {
			fail("%s: token in %s is %d characters; at least %d are required", field, name, len(v), MinTokenLength)
		}
		return v
	}
	var defaultTokens []string
	if c.ClientTokenEnv != "" {
		defaultTokens = append(defaultTokens, token("client_token_env", c.ClientTokenEnv))
	}
	if c.ClientTokenPreviousEnv != "" {
		defaultTokens = append(defaultTokens, token("client_token_previous_env", c.ClientTokenPreviousEnv))
	}

	if len(c.Connections) == 0 {
		fail("connections: at least one connection is required")
	}
	names := map[string]bool{}
	hosts := map[string]bool{}
	for i := range c.Connections {
		conn := &c.Connections[i]
		where := fmt.Sprintf("connections[%d] (%s)", i, conn.Name)

		switch {
		case !connNameRe.MatchString(conn.Name):
			fail("%s: name must match %s", where, connNameRe)
		case reservedNames[conn.Name]:
			fail("%s: name %q is reserved", where, conn.Name)
		case names[conn.Name]:
			fail("%s: duplicate name", where)
		}
		names[conn.Name] = true

		if conn.Host != "" {
			conn.Host = strings.ToLower(conn.Host)
			if hosts[conn.Host] {
				fail("%s: duplicate host %q", where, conn.Host)
			}
			hosts[conn.Host] = true
		}

		switch {
		case conn.ClientTokenEnv != "":
			conn.ClientTokens = []string{token(where+": client_token_env", conn.ClientTokenEnv)}
		case len(defaultTokens) > 0:
			conn.ClientTokens = defaultTokens
		default:
			fail("%s: no client token; set client_token_env here or at the top level", where)
		}

		u, err := url.Parse(conn.Upstream)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			fail("%s: upstream must be an absolute http(s) URL", where)
		} else if u.Scheme == "http" && !c.AllowHTTPUpstreams {
			fail("%s: upstream is plain http; use https or set allow_http_upstreams", where)
		} else if u.RawQuery != "" || u.Fragment != "" {
			fail("%s: upstream must not have a query or fragment", where)
		} else {
			u.Path = strings.TrimSuffix(u.Path, "/")
			u.RawPath = ""
			conn.UpstreamURL = u
		}

		if conn.ClientAuth == "" {
			conn.ClientAuth = AuthBearer
		}
		switch conn.ClientAuth {
		case AuthBearer, AuthBasic:
			if conn.ClientAuthHeader != "" {
				fail("%s: client_auth_header only applies to client_auth: header", where)
			}
		case AuthHeader:
			if conn.ClientAuthHeader == "" {
				fail("%s: client_auth: header needs client_auth_header", where)
			}
		default:
			fail("%s: client_auth must be bearer, basic or header", where)
		}

		conn.ResolvedHeaders = map[string]string{}
		for k, v := range c.UpstreamDefaults.Headers {
			conn.ResolvedHeaders[k] = v
		}
		for k, v := range conn.Headers {
			conn.ResolvedHeaders[k] = v
		}
		for k, v := range conn.ResolvedHeaders {
			conn.ResolvedHeaders[k] = expandEnv(v, lookupEnv, func(name string) {
				fail("%s: header %s: environment variable %s is not set", where, k, name)
			})
		}

		if conn.BasicAuth != nil {
			conn.BasicAuth.Username = env(where+": upstream_basic_auth.username_env", conn.BasicAuth.UsernameEnv)
			conn.BasicAuth.Password = env(where+": upstream_basic_auth.password_env", conn.BasicAuth.PasswordEnv)
		}

		if o := conn.OAuth2; o != nil {
			if conn.BasicAuth != nil {
				fail("%s: upstream_oauth2 and upstream_basic_auth both set the upstream Authorization header; use one", where)
			}
			for k := range conn.ResolvedHeaders {
				if http.CanonicalHeaderKey(k) == "Authorization" {
					fail("%s: upstream_oauth2 sets the upstream Authorization header; remove it from headers", where)
				}
			}
			tu, err := url.Parse(o.TokenURL)
			switch {
			case o.TokenURL == "":
				fail("%s: upstream_oauth2.token_url is required", where)
			case err != nil || (tu.Scheme != "https" && tu.Scheme != "http") || tu.Host == "":
				fail("%s: upstream_oauth2.token_url must be an absolute http(s) URL", where)
			case tu.Scheme == "http" && !c.AllowHTTPUpstreams:
				// The client secret travels in this request.
				fail("%s: upstream_oauth2.token_url is plain http; use https or set allow_http_upstreams", where)
			default:
				o.TokenURLParsed = tu
			}
			o.ClientID = env(where+": upstream_oauth2.client_id_env", o.ClientIDEnv)
			o.ClientSecret = env(where+": upstream_oauth2.client_secret_env", o.ClientSecretEnv)
			if o.AuthStyle == "" {
				o.AuthStyle = OAuth2AuthBasic
			}
			if o.AuthStyle != OAuth2AuthBasic && o.AuthStyle != OAuth2AuthBody {
				fail("%s: upstream_oauth2.auth_style must be basic or body", where)
			}
			for k := range o.Params {
				if oauth2ReservedParams[k] {
					fail("%s: upstream_oauth2.params: %s is set by the proxy", where, k)
				}
			}
		}

		methods := conn.Methods
		if len(methods) == 0 {
			methods = DefaultMethods
		}
		conn.MethodSet = map[string]bool{}
		for _, m := range methods {
			m = strings.ToUpper(m)
			switch m {
			case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
				conn.MethodSet[m] = true
			default:
				fail("%s: methods: unsupported method %q", where, m)
			}
		}
		conn.PathRes = nil
		for j, p := range conn.Paths {
			re, err := regexp.Compile(`^(?:` + p + `)$`)
			if err != nil {
				fail("%s: paths[%d]: %v", where, j, err)
				continue
			}
			conn.PathRes = append(conn.PathRes, re)
		}
		conn.RequestDenyRes = nil
		for j, p := range conn.RequestDenyPatterns {
			re, err := regexp.Compile(p)
			if err != nil {
				fail("%s: request_deny_patterns[%d]: %v", where, j, err)
				continue
			}
			conn.RequestDenyRes = append(conn.RequestDenyRes, re)
		}
		conn.HeaderSet = map[string]bool{}
		for _, h := range append(append([]string{}, DefaultRequestHeaders...), conn.RequestHeaders...) {
			ch := http.CanonicalHeaderKey(h)
			switch ch {
			case "Authorization", "Proxy-Authorization", "Cookie", "Ocp-Apim-Subscription-Key", "Ocp-Apim-Trace", "Apim-Debug-Authorization":
				fail("%s: request_headers: %s cannot be forwarded", where, ch)
			}
			conn.HeaderSet[ch] = true
		}
		for j, p := range conn.ResponseFields {
			for _, seg := range strings.Split(p, ".") {
				if seg == "" {
					fail("%s: response_fields[%d]: empty segment in %q", where, j, p)
					break
				}
			}
		}
		if len(conn.MCPTools) > 0 && !conn.MethodSet["POST"] {
			fail("%s: mcp_tools needs POST in methods", where)
		}
		if rl := conn.RateLimit; rl != nil && (rl.RequestsPerSecond <= 0 || rl.Burst <= 0) {
			fail("%s: rate_limit needs positive requests_per_second and burst", where)
		}
	}

	c.Redaction.resolve(env, fail)
	// Regex compilation and builtin names are validated by the redact
	// package when the engine is built, so there is one source of truth.

	return errors.Join(errs...)
}

func (r *Redaction) resolve(env func(field, name string) string, fail func(string, ...any)) {
	if r.Mask == "" {
		r.Mask = MaskLabel
	}
	switch r.Mask {
	case MaskLabel:
	case MaskHMAC:
		if r.HMACKeyEnv == "" {
			r.HMACKeyEnv = DefaultHMACKeyEnv
		}
		r.HMACKey = []byte(env("redaction.hmac_key_env", r.HMACKeyEnv))
	default:
		fail("redaction.mask must be label or hmac")
	}
	for i, cr := range r.Custom {
		if !connNameRe.MatchString(cr.Name) {
			fail("redaction.custom[%d]: name must match %s", i, connNameRe)
		}
		if cr.Regex == "" {
			fail("redaction.custom[%d] (%s): regex is required", i, cr.Name)
		}
	}
}

// LoadRedaction reads only the redaction section of a config file, for
// running the rules offline (neubird-proxy -redact) without connection
// secrets.
func LoadRedaction(path string, lookupEnv func(string) (string, bool)) (*Redaction, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	env := func(field, name string) string {
		v, ok := lookupEnv(name)
		if !ok || v == "" {
			fail("%s: environment variable %s is not set", field, name)
		}
		return v
	}
	c.Redaction.resolve(env, fail)
	return &c.Redaction, errors.Join(errs...)
}

func expandEnv(s string, lookupEnv func(string) (string, bool), missing func(string)) string {
	return envRefRe.ReplaceAllStringFunc(s, func(ref string) string {
		name := envRefRe.FindStringSubmatch(ref)[1]
		v, ok := lookupEnv(name)
		if !ok || v == "" {
			missing(name)
		}
		return v
	})
}
