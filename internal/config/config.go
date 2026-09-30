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
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultMaxBodyBytes = 20 << 20
	DefaultHMACKeyEnv   = "REDACTION_HMAC_KEY"
)

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
	Listen           string       `yaml:"listen"`
	AdminListen      string       `yaml:"admin_listen"`
	TLS              *TLS         `yaml:"tls"`
	UpstreamCAFile   string       `yaml:"upstream_ca_file"`
	ClientTokenEnv   string       `yaml:"client_token_env"`
	MaxBodyBytes     int64        `yaml:"max_body_bytes"`
	UpstreamDefaults Upstream     `yaml:"upstream_defaults"`
	Connections      []Connection `yaml:"connections"`
	Redaction        Redaction    `yaml:"redaction"`

	ClientToken string `yaml:"-"`
}

type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
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

	UpstreamURL *url.URL `yaml:"-"`
	// ResolvedHeaders is upstream_defaults.headers overlaid with this
	// connection's headers, with ${VAR} references expanded.
	ResolvedHeaders map[string]string `yaml:"-"`
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
	if c.TLS != nil && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		fail("tls: cert_file and key_file are both required")
	}
	c.ClientToken = env("client_token_env", c.ClientTokenEnv)

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

		u, err := url.Parse(conn.Upstream)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			fail("%s: upstream must be an absolute http(s) URL", where)
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
	}

	r := &c.Redaction
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
	// Regex compilation and builtin names are validated by the redact
	// package when the engine is built, so there is one source of truth.

	return errors.Join(errs...)
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
