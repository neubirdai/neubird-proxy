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
