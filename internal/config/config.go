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
	"slices"
	"strconv"
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

// AllMethods are the methods a connection may allow; "*" allows them all.
// CONNECT and TRACE never cross the proxy.
var AllMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

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
	// AuthNone takes no proxy token: only for a tunnel-only proxy
	// (listen: off), where every request arrives over a tunnel the proxy
	// opened itself to its NeuBird relay, with mutual TLS.
	AuthNone = "none"
)

// UpstreamCredentialPrefix marks a request header carrying a NeuBird-held
// backend credential in open mode: X-Neubird-Upstream-Authorization becomes
// Authorization.
const UpstreamCredentialPrefix = "X-Neubird-Upstream-"

// DefaultCredentialHeaders is what NeuBird may set in open mode when
// neubird_destinations lists no credential_headers: "*", any header
// CredentialHeaderAllowed allows, as hosts defaults to any host.
var DefaultCredentialHeaders = []string{"*"}

// credentialHeaderDenied are headers NeuBird may never set, whatever
// credential_headers says: they steer the transport, APIM or the audit trail.
var credentialHeaderDenied = map[string]bool{
	"Host": true, "Cookie": true, "Proxy-Authorization": true,
	"Content-Length": true, "Transfer-Encoding": true, "Connection": true,
	"Upgrade": true, "Te": true, "Trailer": true, "X-Request-Id": true,
	"Ocp-Apim-Trace": true, "Apim-Debug-Authorization": true,
	"Accept-Encoding": true, "Range": true, "If-Range": true,
}

// CredentialHeaderAllowed reports whether NeuBird may set the canonical
// header name ch upstream: never a denied header, X-Forwarded-* or one of
// NeuBird's own X-Neubird-* headers, whatever credential_headers lists.
func CredentialHeaderAllowed(ch string) bool {
	return !credentialHeaderDenied[ch] && !strings.HasPrefix(ch, "X-Forwarded-") && !strings.HasPrefix(ch, "X-Neubird-")
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
	// NeubirdDestinations ("open mode"), when set, lets NeuBird name the
	// destination host of a request instead of a configured connection, within
	// the host patterns listed here. No per-backend entries; credentials are
	// always NeuBird's. See the README, "Open mode".
	NeubirdDestinations *NeubirdDestinations `yaml:"neubird_destinations"`
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
	// NeuBirdCredentials is set on open mode's shared policy only: NeuBird
	// sends the backend credential (X-Neubird-Upstream-<Header>) and the
	// proxy forwards it as <Header>, for the headers in CredentialHeaders.
	// Named connections always use the customer's credentials.
	NeuBirdCredentials bool     `yaml:"-"`
	CredentialHeaders  []string `yaml:"-"`

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
	// may set (open mode only).
	CredentialHeaderSet map[string]bool `yaml:"-"`
	// CredentialHeaderAny: credential_headers is "*", so NeuBird may set
	// any header CredentialHeaderAllowed allows (open mode only).
	CredentialHeaderAny bool `yaml:"-"`
}

// NeubirdDestinations is open mode: requests to /_neubird/dest/<path> carry
// X-Neubird-Destination (scheme://host[:port]) and go there if the host
// matches Hosts. Everything a connection applies applies here too, from one
// shared policy.
type NeubirdDestinations struct {
	// Hosts are patterns (default "*"): "*" (any host name), "*.example.com" (any name
	// under it), "host.example.com", or an IP address; each may end in
	// ":port". An IP address is reached only when listed exactly; "*" and
	// "*.domain" match names, never IP literals.
	Hosts               []string   `yaml:"hosts"`
	ClientAuth          string     `yaml:"client_auth"`
	ClientAuthHeader    string     `yaml:"client_auth_header"`
	ClientTokenEnv      string     `yaml:"client_token_env"`
	Methods             []string   `yaml:"methods"`
	RequestHeaders      []string   `yaml:"request_headers"`
	RequestDenyPatterns []string   `yaml:"request_deny_patterns"`
	RateLimit           *RateLimit `yaml:"rate_limit"`
	ResponseFields      []string   `yaml:"response_fields"`
	CredentialHeaders   []string   `yaml:"credential_headers"`
	// HostMethods narrows methods for some hosts: the first rule whose hosts
	// match the destination replaces methods for it (a subset of methods),
	// e.g. read-only ServiceNow next to a Splunk that needs POST.
	HostMethods []HostMethods `yaml:"host_methods"`

	// Conn is the shared policy as a connection, resolved like any other;
	// the proxy sets its upstream per request. Not routable by name.
	Conn *Connection `yaml:"-"`
	// Patterns are the parsed Hosts.
	Patterns []HostPattern `yaml:"-"`
}

// HostMethods is one neubird_destinations.host_methods rule.
type HostMethods struct {
	Hosts   []string `yaml:"hosts"`
	Methods []string `yaml:"methods"`

	Patterns  []HostPattern   `yaml:"-"`
	MethodSet map[string]bool `yaml:"-"`
}

// MethodsFor is the method set for a destination: the first host_methods
// rule matching host:port, else the shared methods.
func (d *NeubirdDestinations) MethodsFor(host, port string) map[string]bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	isIP := net.ParseIP(host) != nil
	if isIP {
		host = net.ParseIP(host).String()
	}
	for _, r := range d.HostMethods {
		for _, p := range r.Patterns {
			if p.Match(host, port, isIP) {
				return r.MethodSet
			}
		}
	}
	return d.Conn.MethodSet
}

// DestinationsConnName labels open-mode requests in metrics and audit lines.
// It can't collide with a connection: names start with [a-z0-9].
const DestinationsConnName = "_destinations"

// HostPattern is one parsed neubird_destinations.hosts entry.
type HostPattern struct {
	Any    bool   // "*"
	Suffix string // "*.example.com" -> ".example.com"
	Exact  string // a host name or IP literal
	Port   string // "" means any port
	IP     bool   // Exact is an IP literal
}

// Match reports whether host (lower-case, no trailing dot) and port (never
// empty: the scheme's default filled in) match the pattern.
func (p HostPattern) Match(host, port string, hostIsIP bool) bool {
	if p.Port != "" && p.Port != port {
		return false
	}
	switch {
	case p.Exact != "":
		return host == p.Exact
	case hostIsIP:
		return false // wildcards never cover IP literals
	case p.Any:
		return true
	default:
		return strings.HasSuffix(host, p.Suffix) && len(host) > len(p.Suffix)
	}
}

var hostLabelsRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

func parseHostPattern(raw string) (HostPattern, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	var p HostPattern
	host := v
	if h, port, err := net.SplitHostPort(v); err == nil {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return p, fmt.Errorf("%q: bad port", raw)
		}
		host, p.Port = h, port
	}
	host = strings.TrimSuffix(host, ".")
	switch {
	case host == "*":
		p.Any = true
	case strings.HasPrefix(host, "*."):
		if !hostLabelsRe.MatchString(host[2:]) || !strings.Contains(host[2:], ".") {
			return p, fmt.Errorf("%q: a wildcard needs a domain of two or more labels, e.g. *.example.com", raw)
		}
		p.Suffix = host[1:]
	case net.ParseIP(host) != nil:
		p.Exact, p.IP = net.ParseIP(host).String(), true
	case hostLabelsRe.MatchString(host):
		p.Exact = host
	default:
		return p, fmt.Errorf("%q: not \"*\", \"*.domain\", a host name or an IP address", raw)
	}
	return p, nil
}

// MatchDestination reports whether any pattern allows host:port.
func (d *NeubirdDestinations) MatchDestination(host, port string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	isIP := net.ParseIP(host) != nil
	if isIP {
		host = net.ParseIP(host).String()
	}
	for _, p := range d.Patterns {
		if p.Match(host, port, isIP) {
			return true
		}
	}
	return false
}

// AnyHost reports whether a bare "*" pattern is listed.
func (d *NeubirdDestinations) AnyHost() bool {
	for _, p := range d.Patterns {
		if p.Any {
			return true
		}
	}
	return false
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
	// The top-level tokens are read only if a connection uses them, so a
	// proxy whose connections all take client_auth: none needs no token in
	// its environment.
	var defaultTokens []string
	defaultsRead := false
	readDefaultTokens := func() []string {
		if !defaultsRead {
			defaultsRead = true
			if c.ClientTokenEnv != "" {
				defaultTokens = append(defaultTokens, token("client_token_env", c.ClientTokenEnv))
			}
			if c.ClientTokenPreviousEnv != "" {
				defaultTokens = append(defaultTokens, token("client_token_previous_env", c.ClientTokenPreviousEnv))
			}
		}
		return defaultTokens
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
		// Optional: the relay knows the proxy by its key (and, enrolling, by
		// its join token's record). Set, they're named in the certificate
		// and the relay checks its records agree.
		if (t.Tenant == "") != (t.Proxy == "") {
			fail("tunnel: set both tenant and proxy, or neither (the relay then names the proxy from its records)")
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
	if len(c.Connections) == 0 && c.NeubirdDestinations == nil {
		fail("connections: at least one connection (or neubird_destinations) is required")
	}
	type target struct {
		conn  *Connection
		where string
		dest  bool
	}
	var targets []target
	for i := range c.Connections {
		targets = append(targets, target{&c.Connections[i], fmt.Sprintf("connections[%d] (%s)", i, c.Connections[i].Name), false})
	}
	if d := c.NeubirdDestinations; d != nil {
		if len(d.Hosts) == 0 {
			// Not restricting is the customer's call: any host name, with
			// the same guard rails (no IP literals, no internal addresses).
			d.Hosts = []string{"*"}
		}
		d.Patterns = nil
		for i, h := range d.Hosts {
			p, err := parseHostPattern(h)
			if err != nil {
				fail("neubird_destinations.hosts[%d]: %v", i, err)
				continue
			}
			d.Patterns = append(d.Patterns, p)
		}
		// The shared policy, resolved below like a connection. Its upstream
		// is a placeholder the proxy replaces per request.
		d.Conn = &Connection{
			Name:                DestinationsConnName,
			Upstream:            "https://neubird-destination.invalid",
			ClientAuth:          d.ClientAuth,
			ClientAuthHeader:    d.ClientAuthHeader,
			ClientTokenEnv:      d.ClientTokenEnv,
			Methods:             d.Methods,
			RequestHeaders:      d.RequestHeaders,
			RequestDenyPatterns: d.RequestDenyPatterns,
			RateLimit:           d.RateLimit,
			ResponseFields:      d.ResponseFields,
			NeuBirdCredentials:  true,
			CredentialHeaders:   d.CredentialHeaders,
		}
		targets = append(targets, target{d.Conn, "neubird_destinations", true})
	}
	names := map[string]bool{}
	hosts := map[string]bool{}
	for _, tg := range targets {
		conn, where := tg.conn, tg.where

		if !tg.dest {
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
		if conn.ClientAuth == AuthNone {
			switch {
			case c.Listen != ListenOff || c.Tunnel == nil:
				fail("%s: client_auth: none is only for a tunnel-only proxy (listen: off with a tunnel section); an inbound listener always needs a token", where)
			case conn.ClientTokenEnv != "" || conn.ClientAuthHeader != "":
				fail("%s: client_auth: none takes no client_token_env or client_auth_header", where)
			}
		} else {
			switch {
			case conn.ClientTokenEnv != "":
				conn.ClientTokens = []string{token(where+": client_token_env", conn.ClientTokenEnv)}
			case len(readDefaultTokens()) > 0:
				conn.ClientTokens = defaultTokens
			default:
				fail("%s: no client token; set client_token_env here or at the top level (or client_auth: none on a tunnel-only proxy)", where)
			}
		}
		switch conn.ClientAuth {
		case AuthNone:
		case AuthBearer, AuthBasic:
			if conn.ClientAuthHeader != "" {
				fail("%s: client_auth_header only applies to client_auth: header", where)
			}
		case AuthHeader:
			ch := http.CanonicalHeaderKey(conn.ClientAuthHeader)
			switch {
			case conn.ClientAuthHeader == "":
				fail("%s: client_auth: header needs client_auth_header", where)
			case strings.HasPrefix(ch, UpstreamCredentialPrefix), strings.HasPrefix(ch, "X-Forwarded-"),
				credentialHeaderDenied[ch], ch == "Authorization", ch == "Proxy-Authorization":
				// The proxy token must arrive in a header of its own: one
				// that is forwarded (or turned into a credential) would carry
				// it upstream.
				fail("%s: client_auth_header %s can't carry the proxy token", where, ch)
			}
		default:
			fail("%s: client_auth must be bearer, basic, header or none", where)
		}

		conn.ResolvedHeaders = map[string]string{}
		// upstream_defaults.headers (an APIM subscription key, say) are for
		// the configured upstreams; open mode reaches other hosts, which must
		// never receive them.
		if !tg.dest {
			for k, v := range c.UpstreamDefaults.Headers {
				conn.ResolvedHeaders[k] = v
			}
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
			switch {
			case m == "*" && len(methods) > 1:
				fail("%s: methods: \"*\" already allows every method; list it alone", where)
			case m == "*":
				for _, a := range AllMethods {
					conn.MethodSet[a] = true
				}
			case slices.Contains(AllMethods, m):
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
			case "Authorization", "Ocp-Apim-Subscription-Key":
				fail("%s: request_headers: %s cannot be forwarded", where, ch)
			}
			// Framing, hop-by-hop, compression and range headers would let
			// a body arrive in a form redaction can't read whole. Only a
			// passthrough connection, which reads nothing, may upgrade.
			upgrade := conn.Passthrough && (ch == "Upgrade" || ch == "Connection")
			if (credentialHeaderDenied[ch] || strings.HasPrefix(ch, "X-Forwarded-")) && !upgrade {
				fail("%s: request_headers: %s cannot be forwarded", where, ch)
			}
			if strings.HasPrefix(ch, UpstreamCredentialPrefix) {
				fail("%s: request_headers: %s is a credential header", where, ch)
			}
			if conn.ClientAuth == AuthHeader && strings.EqualFold(ch, conn.ClientAuthHeader) {
				// It carries the proxy token, which must never go upstream.
				fail("%s: request_headers: %s carries the proxy token (client_auth_header)", where, ch)
			}
			conn.HeaderSet[ch] = true
		}

		if conn.NeuBirdCredentials {
			hs := conn.CredentialHeaders
			if len(hs) == 0 {
				hs = DefaultCredentialHeaders
			}
			conn.CredentialHeaderSet = map[string]bool{}
			for _, h := range hs {
				ch := http.CanonicalHeaderKey(h)
				switch {
				case h == "*" && len(hs) > 1:
					fail("%s: credential_headers: \"*\" already allows every header; list it alone", where)
				case h == "*":
					conn.CredentialHeaderAny = true
					continue
				case !headerNameRe.MatchString(h):
					fail("%s: credential_headers: %q is not a header name", where, h)
				case !CredentialHeaderAllowed(ch):
					fail("%s: credential_headers: %s cannot be set by NeuBird", where, ch)
				case conn.HeaderSet[ch]:
					fail("%s: credential_headers: %s is also in request_headers", where, ch)
				}
				conn.CredentialHeaderSet[ch] = true
			}
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

	if d := c.NeubirdDestinations; d != nil {
		for i := range d.HostMethods {
			r := &d.HostMethods[i]
			where := fmt.Sprintf("neubird_destinations.host_methods[%d]", i)
			if len(r.Hosts) == 0 || len(r.Methods) == 0 {
				fail("%s: hosts and methods are required", where)
				continue
			}
			r.Patterns = nil
			for j, h := range r.Hosts {
				p, err := parseHostPattern(h)
				if err != nil {
					fail("%s.hosts[%d]: %v", where, j, err)
					continue
				}
				r.Patterns = append(r.Patterns, p)
			}
			r.MethodSet = map[string]bool{}
			for _, m := range r.Methods {
				m = strings.ToUpper(m)
				if !d.Conn.MethodSet[m] {
					// Only narrowing: a rule can't allow what methods doesn't.
					fail("%s: method %q is not in neubird_destinations.methods", where, m)
					continue
				}
				r.MethodSet[m] = true
			}
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
		// The masks are 64 bits of HMAC: with a short key, one known value
		// and its mask give the key away, and then low-entropy values
		// (SSNs, phone numbers) can be recovered from their masks.
		if n := len(r.HMACKey); n > 0 && n < MinTokenLength {
			fail("redaction.hmac_key_env: the key in %s is %d characters; at least %d are required", r.HMACKeyEnv, n, MinTokenLength)
		}
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
