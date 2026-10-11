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
	"net"
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

// Credential sources: who supplies the credential the backend sees.
const (
	// CredentialsCustomer: the proxy injects it from its own Secret
	// (headers, upstream_basic_auth); anything NeuBird sends is refused.
	CredentialsCustomer = "customer"
	// CredentialsNeuBird: NeuBird holds it, as for a direct connection, and
	// sends it in X-Neubird-Upstream-<Header>; the proxy moves it to <Header>.
	CredentialsNeuBird = "neubird"
)

// UpstreamCredentialPrefix marks a request header carrying a NeuBird-held
// backend credential: X-Neubird-Upstream-Authorization becomes Authorization.
const UpstreamCredentialPrefix = "X-Neubird-Upstream-"

// DefaultCredentialHeaders is what credentials: neubird may set when the
// connection lists no credential_headers.
var DefaultCredentialHeaders = []string{"Authorization"}

// credentialHeaderDenied are headers NeuBird may never set, whatever
// credential_headers says: they steer the transport, APIM or the audit trail.
var credentialHeaderDenied = map[string]bool{
	"Host": true, "Cookie": true, "Proxy-Authorization": true,
	"Content-Length": true, "Transfer-Encoding": true, "Connection": true,
	"Upgrade": true, "Te": true, "Trailer": true, "X-Request-Id": true,
	"Ocp-Apim-Trace": true, "Apim-Debug-Authorization": true,
	"Accept-Encoding": true, "Range": true, "If-Range": true,
}

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
	// DisableStatusAPI turns off GET /_neubird/status, which tells a token
	// holder the names and settings of the connections that token opens.
	DisableStatusAPI bool `yaml:"disable_status_api"`
	// Tunnel, when set, makes the proxy also (or, with listen: "off",
	// only) serve NeuBird through outbound connections to a NeuBird relay.
	// See docs/tunnel-protocol.md.
	Tunnel *Tunnel `yaml:"tunnel"`
}

// ListenOff turns the inbound listener off, for a proxy reached only
// through its tunnel.
const ListenOff = "off"

// Tunnel configures outbound connections to a NeuBird relay. The files are
// read and checked by the tunnel package when the proxy starts (and by
// `validate` unless -offline), not here, so a config can be checked on a
// machine that doesn't hold them.
type Tunnel struct {
	// Relays are host:port addresses; every pod keeps tunnels to each.
	Relays []string `yaml:"relays"`
	// Tenant and Proxy name this proxy (DNS labels NeuBird gives you). With
	// them, the proxy mints its own self-signed certificate from KeyFile on
	// every connect; NeuBird pins the key's fingerprint, so nothing is ever
	// signed or renewed.
	Tenant string `yaml:"tenant"`
	Proxy  string `yaml:"proxy"`
	// KeyFile is the proxy's private key, made here with `neubird-proxy
	// keygen`; it never leaves the cluster.
	KeyFile string `yaml:"key_file"`
	// CertFile is optional: a certificate for KeyFile to present instead of
	// minting one (a proxy set up before keys were pinned).
	CertFile string `yaml:"cert_file"`
	// CAFile pins the CA that signs the relays' server certificates.
	CAFile string `yaml:"ca_file"`
	// ConnectionsPerRelay is how many tunnels each pod keeps to each relay.
	ConnectionsPerRelay int `yaml:"connections_per_relay"`
	// JoinTokenEnv names an environment variable holding a join token from
	// NeuBird. When it's set, the proxy enrolls its key with the relay on
	// its first connection, so nothing needs sending back to NeuBird. It's
	// optional, unlike other _env fields: once enrolled, the token can be
	// removed (the relay then knows the key).
	JoinTokenEnv string `yaml:"join_token_env"`
	// JoinToken is JoinTokenEnv's value, "" if unset.
	JoinToken string `yaml:"-"`
}

// JoinTokenRE is a well-formed join token (docs/tunnel-protocol.md).
var JoinTokenRE = regexp.MustCompile(`^nbjt_[A-Za-z0-9_-]{43}$`)

const (
	DefaultTunnelConnectionsPerRelay = 1
	MaxTunnelConnectionsPerRelay     = 8
)

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
	// Credentials is customer (default) or neubird; see CredentialsCustomer.
	Credentials string `yaml:"credentials"`
	// CredentialHeaders are the upstream headers NeuBird may set with
	// credentials: neubird. Default: Authorization.
	CredentialHeaders []string `yaml:"credential_headers"`

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
	// CredentialHeaderSet holds the canonical upstream header names NeuBird
	// may set (credentials: neubird only).
	CredentialHeaderSet map[string]bool `yaml:"-"`
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
	connNameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	envRefRe     = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	headerNameRe = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
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
		// A Secret made with --from-file keeps the file's trailing newline,
		// which would make every token or credential silently wrong.
		v = strings.TrimRight(v, "\r\n")
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

	if t := c.Tunnel; t != nil {
		if len(t.Relays) == 0 {
			fail("tunnel.relays: at least one relay is required")
		}
		for i, r := range t.Relays {
			host, port, err := net.SplitHostPort(r)
			if err != nil || host == "" || port == "" {
				fail("tunnel.relays[%d]: %q is not host:port", i, r)
			}
		}
		if t.KeyFile == "" || t.CAFile == "" {
			fail("tunnel: key_file and ca_file are required")
		}
		if t.CertFile == "" && (t.Tenant == "" || t.Proxy == "") {
			fail("tunnel: tenant and proxy are required (or a cert_file naming them)")
		}
		if t.ConnectionsPerRelay == 0 {
			t.ConnectionsPerRelay = DefaultTunnelConnectionsPerRelay
		}
		if t.ConnectionsPerRelay < 1 || t.ConnectionsPerRelay > MaxTunnelConnectionsPerRelay {
			fail("tunnel.connections_per_relay must be 1 to %d", MaxTunnelConnectionsPerRelay)
		}
		if t.JoinTokenEnv != "" {
			t.JoinToken, _ = lookupEnv(t.JoinTokenEnv)
			t.JoinToken = strings.TrimSpace(t.JoinToken)
			if t.JoinToken != "" && !JoinTokenRE.MatchString(t.JoinToken) {
				fail("tunnel.join_token_env: %s doesn't hold a join token (nbjt_ and 43 characters)", t.JoinTokenEnv)
			}
		}
	}
	if c.Listen == ListenOff {
		if c.Tunnel == nil {
			fail("listen: off needs a tunnel section; otherwise nothing would reach the proxy")
		}
		if c.TLS != nil {
			fail("tls configures the inbound listener, which listen: off turns off")
		}
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
			if strings.HasPrefix(ch, UpstreamCredentialPrefix) {
				fail("%s: request_headers: %s is a credential header; use credentials: neubird", where, ch)
			}
			conn.HeaderSet[ch] = true
		}

		if conn.Credentials == "" {
			conn.Credentials = CredentialsCustomer
		}
		switch conn.Credentials {
		case CredentialsCustomer:
			if len(conn.CredentialHeaders) > 0 {
				fail("%s: credential_headers only applies to credentials: neubird", where)
			}
		case CredentialsNeuBird:
			if conn.BasicAuth != nil {
				fail("%s: credentials: neubird and upstream_basic_auth both set the backend credential", where)
			}
			hs := conn.CredentialHeaders
			if len(hs) == 0 {
				hs = DefaultCredentialHeaders
			}
			conn.CredentialHeaderSet = map[string]bool{}
			for _, h := range hs {
				ch := http.CanonicalHeaderKey(h)
				switch {
				case !headerNameRe.MatchString(h):
					fail("%s: credential_headers: %q is not a header name", where, h)
				case credentialHeaderDenied[ch], strings.HasPrefix(ch, "X-Forwarded-"), strings.HasPrefix(ch, UpstreamCredentialPrefix):
					fail("%s: credential_headers: %s cannot be set by NeuBird", where, ch)
				case conn.HeaderSet[ch]:
					fail("%s: credential_headers: %s is also in request_headers", where, ch)
				}
				for k := range conn.ResolvedHeaders {
					if http.CanonicalHeaderKey(k) == ch {
						fail("%s: credential_headers: %s is already set from the proxy's own config", where, ch)
					}
				}
				conn.CredentialHeaderSet[ch] = true
			}
		default:
			fail("%s: credentials must be customer or neubird", where)
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
