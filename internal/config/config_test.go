package config

import (
	"strings"
	"testing"
)

const tok = "0123456789abcdef0123456789abcdef"

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

const valid = `
client_token_env: TOKEN
upstream_defaults:
  headers:
    Ocp-Apim-Subscription-Key: ${APIM_KEY}
connections:
  - name: splunk
    upstream: https://int.apis.example.com/splunk/
  - name: servicenow
    upstream: https://int.apis.example.com/servicenow
    client_auth: basic
    headers:
      X-Extra: fixed-${SUFFIX}
  - name: direct
    upstream: https://sn.example.com
    client_auth: header
    client_auth_header: X-Api-Key
    upstream_basic_auth:
      username_env: SN_USER
      password_env: SN_PASS
redaction:
  builtins: [email]
`

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(valid), env(map[string]string{
		"TOKEN": tok, "APIM_KEY": "k", "SUFFIX": "s", "SN_USER": "u", "SN_PASS": "p",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8443" || c.AdminListen != ":9090" || c.MaxBodyBytes != DefaultMaxBodyBytes || c.Connections[0].ClientTokens[0] != tok {
		t.Fatalf("defaults not applied: %+v", c)
	}
	sp := c.Connections[0]
	if sp.ClientAuth != AuthBearer || sp.UpstreamURL.Path != "/splunk" || sp.ResolvedHeaders["Ocp-Apim-Subscription-Key"] != "k" {
		t.Fatalf("splunk: %+v", sp)
	}
	sn := c.Connections[1]
	if sn.ResolvedHeaders["X-Extra"] != "fixed-s" || sn.ResolvedHeaders["Ocp-Apim-Subscription-Key"] != "k" {
		t.Fatalf("servicenow headers: %v", sn.ResolvedHeaders)
	}
	if d := c.Connections[2]; d.BasicAuth.Username != "u" || d.BasicAuth.Password != "p" {
		t.Fatalf("direct basic auth: %+v", d.BasicAuth)
	}
	if c.Redaction.Builtins == nil || len(*c.Redaction.Builtins) != 1 || c.Redaction.Mask != MaskLabel {
		t.Fatalf("redaction: %+v", c.Redaction)
	}
}

func TestParseErrors(t *testing.T) {
	base := map[string]string{"TOKEN": tok, "APIM_KEY": "k", "SUFFIX": "s", "SN_USER": "u", "SN_PASS": "p"}
	cases := map[string]struct {
		yaml string
		env  map[string]string
		want string
	}{
		"missing token env":   {valid, without(base, "TOKEN"), "TOKEN is not set"},
		"missing header env":  {valid, without(base, "APIM_KEY"), "APIM_KEY is not set"},
		"missing basic env":   {valid, without(base, "SN_PASS"), "SN_PASS is not set"},
		"unknown field":       {valid + "bogus: 1\n", base, "field bogus not found"},
		"reserved name":       {"client_token_env: TOKEN\nconnections: [{name: metrics, upstream: 'https://x'}]", base, "reserved"},
		"duplicate name":      {"client_token_env: TOKEN\nconnections: [{name: a, upstream: 'https://x'}, {name: a, upstream: 'https://y'}]", base, "duplicate name"},
		"bad name":            {"client_token_env: TOKEN\nconnections: [{name: A/B, upstream: 'https://x'}]", base, "name must match"},
		"relative upstream":   {"client_token_env: TOKEN\nconnections: [{name: a, upstream: '/x'}]", base, "absolute http(s) URL"},
		"upstream query":      {"client_token_env: TOKEN\nconnections: [{name: a, upstream: 'https://x/?a=1'}]", base, "query"},
		"bad auth mode":       {"client_token_env: TOKEN\nconnections: [{name: a, upstream: 'https://x', client_auth: magic}]", base, "client_auth must be"},
		"header without name": {"client_token_env: TOKEN\nconnections: [{name: a, upstream: 'https://x', client_auth: header}]", base, "needs client_auth_header"},
		"no connections":      {"client_token_env: TOKEN\n", base, "at least one connection"},
		"hmac without key":    {"client_token_env: TOKEN\nconnections: [{name: a, upstream: 'https://x'}]\nredaction: {mask: hmac}", base, "REDACTION_HMAC_KEY is not set"},
		"bad mask":            {"client_token_env: TOKEN\nconnections: [{name: a, upstream: 'https://x'}]\nredaction: {mask: blur}", base, "mask must be"},
		"short hmac key":      {"client_token_env: TOKEN\nneubird_destinations: {}\nredaction: {mask: hmac, hmac_key_env: APIM_KEY}", base, "at least 32 are required"},
		"range header":        {"client_token_env: TOKEN\nneubird_destinations: {request_headers: [range]}", base, "Range cannot be forwarded"},
		"encoding header":     {"client_token_env: TOKEN\nneubird_destinations: {request_headers: [Accept-Encoding]}", base, "Accept-Encoding cannot be forwarded"},
		"forwarded header":    {"client_token_env: TOKEN\nneubird_destinations: {request_headers: [X-Forwarded-Host]}", base, "X-Forwarded-Host cannot be forwarded"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.yaml), env(c.env))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want containing %q", err, c.want)
			}
		})
	}
}

func without(m map[string]string, k string) map[string]string {
	out := map[string]string{}
	for kk, v := range m {
		if kk != k {
			out[kk] = v
		}
	}
	return out
}

func TestTunnelConfig(t *testing.T) {
	lookup := env(map[string]string{"TOKEN": tok})
	ok := "client_token_env: TOKEN\nlisten: \"off\"\nconnections: [{name: a, upstream: 'https://x'}]\n" +
		"tunnel: {relays: [tunnel-0.neubird.ai:443], cert_file: c, key_file: k, ca_file: ca}\n"
	c, err := Parse([]byte(ok), lookup)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ListenOff || c.Tunnel.ConnectionsPerRelay != 1 {
		t.Fatalf("%+v", c.Tunnel)
	}
	for name, tc := range map[string]struct{ yaml, want string }{
		"off without tunnel": {"client_token_env: TOKEN\nlisten: \"off\"\nconnections: [{name: a, upstream: 'https://x'}]\n", "needs a tunnel"},
		"no relays":          {"client_token_env: TOKEN\nconnections: [{name: a, upstream: 'https://x'}]\ntunnel: {cert_file: c, key_file: k, ca_file: ca}\n", "at least one relay"},
		"bad relay":          {"client_token_env: TOKEN\nconnections: [{name: a, upstream: 'https://x'}]\ntunnel: {relays: [tunnel.neubird.ai], cert_file: c, key_file: k, ca_file: ca}\n", "not host:port"},
		"missing files":      {"client_token_env: TOKEN\nconnections: [{name: a, upstream: 'https://x'}]\ntunnel: {relays: ['r:443']}\n", "key_file and ca_file are required"},
		"no identity":        {"client_token_env: TOKEN\nconnections: [{name: a, upstream: 'https://x'}]\ntunnel: {relays: ['r:443'], key_file: k, ca_file: ca}\n", "tenant and proxy are required"},
		"too many":           {"client_token_env: TOKEN\nconnections: [{name: a, upstream: 'https://x'}]\ntunnel: {relays: ['r:443'], cert_file: c, key_file: k, ca_file: ca, connections_per_relay: 9}\n", "1 to 8"},
		"off with tls":       {"client_token_env: TOKEN\nlisten: \"off\"\ntls: {cert_file: a, key_file: b}\nconnections: [{name: a, upstream: 'https://x'}]\ntunnel: {relays: ['r:443'], cert_file: c, key_file: k, ca_file: ca}\n", "listen: off turns off"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml), lookup)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// join_token_env is optional: unset or empty means no enrollment (the token
// is removed after install), but a value must look like a join token.
func TestTunnelJoinToken(t *testing.T) {
	const jt = "nbjt_Eqsj3YL4mQ0Su35QzRZS4KjcVHYOfWDnFMrVo_NgHZQ"
	base := "client_token_env: TOKEN\nlisten: \"off\"\nconnections: [{name: a, upstream: 'https://x'}]\n" +
		"tunnel: {relays: ['r:443'], tenant: swift, proxy: p, key_file: k, ca_file: ca, join_token_env: NEUBIRD_JOIN_TOKEN}\n"
	for name, tc := range map[string]struct {
		env  map[string]string
		want string // "" = valid
		tok  string
	}{
		"set":       {map[string]string{"TOKEN": tok, "NEUBIRD_JOIN_TOKEN": jt + "\n"}, "", jt},
		"unset":     {map[string]string{"TOKEN": tok}, "", ""},
		"empty":     {map[string]string{"TOKEN": tok, "NEUBIRD_JOIN_TOKEN": ""}, "", ""},
		"malformed": {map[string]string{"TOKEN": tok, "NEUBIRD_JOIN_TOKEN": "hunter2"}, "doesn't hold a join token", ""},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := Parse([]byte(base), env(tc.env))
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "hunter2") {
					t.Fatalf("err = %v, want %q (and never the value)", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.Tunnel.JoinToken != tc.tok {
				t.Fatalf("join token %q, want %q", c.Tunnel.JoinToken, tc.tok)
			}
		})
	}
}

// Values from a Secret made with --from-file end in a newline; it's not
// part of the token.
func TestEnvTrailingNewlineTrimmed(t *testing.T) {
	c, err := Parse([]byte("client_token_env: TOKEN\nconnections: [{name: a, upstream: 'https://x'}]\n"),
		env(map[string]string{"TOKEN": tok + "\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Connections[0].ClientTokens[0]; got != tok {
		t.Fatalf("token %q, want %q", got, tok)
	}
}

func TestNeubirdDestinations(t *testing.T) {
	e := env(map[string]string{"TOKEN": tok, "APIM_KEY": "k"})
	base := "client_token_env: TOKEN\nupstream_defaults:\n  headers:\n    Ocp-Apim-Subscription-Key: ${APIM_KEY}\n"

	// Open mode alone is a complete config; connections are optional.
	c, err := Parse([]byte(base+"neubird_destinations:\n  hosts: ['*', '*.acme.internal', 'splunk.acme.com:8089', '10.1.2.3']\n  methods: [GET, POST]\n"), e)
	if err != nil {
		t.Fatal(err)
	}
	d := c.NeubirdDestinations
	if !d.Conn.NeuBirdCredentials || !d.Conn.CredentialHeaderSet["Authorization"] || !d.AnyHost() {
		t.Fatalf("template: %+v", d.Conn)
	}
	// upstream_defaults.headers (the APIM key) must never reach other hosts.
	if len(d.Conn.ResolvedHeaders) != 0 {
		t.Fatalf("open mode got upstream_defaults headers: %v", d.Conn.ResolvedHeaders)
	}
	for _, tc := range []struct {
		host, port string
		want       bool
	}{
		{"anything.example.org", "443", true}, // "*"
		{"jira.acme.internal", "443", true},   // *.acme.internal
		{"acme.internal", "443", true},        // still "*"
		{"splunk.acme.com", "8089", true},     // exact host:port
		{"10.1.2.3", "443", true},             // listed IP
		{"10.9.9.9", "443", false},            // "*" never covers IPs
		{"169.254.169.254", "80", false},      // nor metadata
	} {
		if got := d.MatchDestination(tc.host, tc.port); got != tc.want {
			t.Errorf("%s:%s = %v, want %v", tc.host, tc.port, got, tc.want)
		}
	}

	// hosts is optional: omitted means any host name.
	c, err = Parse([]byte(base+"neubird_destinations: {}\n"), e)
	if err != nil {
		t.Fatal(err)
	}
	if d := c.NeubirdDestinations; !d.AnyHost() || !d.MatchDestination("jira.acme.internal", "443") || d.MatchDestination("10.1.2.3", "443") {
		t.Fatalf("default hosts: %v", d.Hosts)
	}

	c, err = Parse([]byte(base+"neubird_destinations:\n  hosts: ['*.acme.internal', 'splunk.acme.com:8089']\n"), e)
	if err != nil {
		t.Fatal(err)
	}
	d = c.NeubirdDestinations
	for _, tc := range []struct {
		host, port string
		want       bool
	}{
		{"jira.acme.internal", "443", true},
		{"acme.internal", "443", false}, // the wildcard needs a label
		{"jira.acme.internal.evil.com", "443", false},
		{"evilacme.internal", "443", false},
		{"splunk.acme.com", "443", false}, // wrong port
		{"10.1.2.3", "443", false},
	} {
		if got := d.MatchDestination(tc.host, tc.port); got != tc.want {
			t.Errorf("%s:%s = %v, want %v", tc.host, tc.port, got, tc.want)
		}
	}

	for name, tc := range map[string]struct{ cfg, want string }{
		"tld wildcard":    {"neubird_destinations:\n  hosts: ['*.internal']\n", "two or more labels"},
		"bad pattern":     {"neubird_destinations:\n  hosts: ['ac me']\n", "not \"*\""},
		"bad port":        {"neubird_destinations:\n  hosts: ['x.y:99999']\n", "bad port"},
		"nothing at all":  {"", "at least one connection (or neubird_destinations)"},
		"customer header": {"neubird_destinations:\n  hosts: ['*']\n  credential_headers: [Cookie]\n", "cannot be set by NeuBird"},
	} {
		_, err := Parse([]byte(base+tc.cfg), e)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
}

// client_auth: none is for a tunnel-only proxy only, and then needs no token
// in the environment (even with client_token_env set, as the chart does).
func TestClientAuthNone(t *testing.T) {
	tunnel := "listen: \"off\"\ntunnel: {relays: ['r:443'], tenant: a, proxy: p, key_file: k, ca_file: ca}\n"
	noEnv := env(map[string]string{})
	for name, y := range map[string]string{
		"destinations":            tunnel + "neubird_destinations: {client_auth: none}\n",
		"connection":              tunnel + "connections: [{name: a, upstream: 'https://x', client_auth: none}]\n",
		"unused client_token_env": tunnel + "client_token_env: NEUBIRD_PROXY_TOKEN\nneubird_destinations: {client_auth: none}\n",
	} {
		t.Run(name, func(t *testing.T) {
			c, err := Parse([]byte(y), noEnv)
			if err != nil {
				t.Fatal(err)
			}
			for _, conn := range c.Connections {
				if conn.ClientAuth != AuthNone || len(conn.ClientTokens) != 0 {
					t.Fatalf("%+v", conn)
				}
			}
		})
	}
	for name, tc := range map[string]struct{ yaml, want string }{
		"inbound listener":         {"neubird_destinations: {client_auth: none}\n", "only for a tunnel-only proxy"},
		"inbound + tunnel":         {"tunnel: {relays: ['r:443'], tenant: a, proxy: p, key_file: k, ca_file: ca}\nneubird_destinations: {client_auth: none}\n", "only for a tunnel-only proxy"},
		"with token env":           {tunnel + "neubird_destinations: {client_auth: none, client_token_env: T}\n", "takes no client_token_env"},
		"with header":              {tunnel + "neubird_destinations: {client_auth: none, client_auth_header: X-T}\n", "takes no client_token_env or client_auth_header"},
		"other conn needs a token": {tunnel + "neubird_destinations: {client_auth: none}\nconnections: [{name: a, upstream: 'https://x'}]\n", "no client token"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml), noEnv)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// host_methods narrows methods per destination host and can't widen them.
func TestHostMethods(t *testing.T) {
	e := env(map[string]string{"TOKEN": tok})
	base := "client_token_env: TOKEN\nneubird_destinations:\n  hosts: ['splunk.acme.com:8089', 'acme.service-now.com']\n  methods: [GET, HEAD, POST]\n"
	c, err := Parse([]byte(base+"  host_methods:\n    - {hosts: ['*.service-now.com'], methods: [get, head]}\n"), e)
	if err != nil {
		t.Fatal(err)
	}
	d := c.NeubirdDestinations
	if ms := d.MethodsFor("acme.service-now.com", "443"); ms["POST"] || !ms["GET"] || !ms["HEAD"] {
		t.Fatalf("service-now: %v", ms)
	}
	if ms := d.MethodsFor("splunk.acme.com", "8089"); !ms["POST"] {
		t.Fatalf("splunk keeps the shared methods: %v", ms)
	}
	for _, bad := range []string{
		"  host_methods:\n    - {hosts: ['*.service-now.com'], methods: [DELETE]}\n", // wider than methods
		"  host_methods:\n    - {hosts: ['*.service-now.com']}\n",                    // no methods
		"  host_methods:\n    - {methods: [GET]}\n",                                  // no hosts
		"  host_methods:\n    - {hosts: ['bad name'], methods: [GET]}\n",
	} {
		if _, err := Parse([]byte(base+bad), e); err == nil {
			t.Errorf("want an error for %q", bad)
		}
	}
}
