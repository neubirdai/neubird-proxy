package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/redact"
	"github.com/neubirdai/neubird-proxy/internal/tunnel"
	"gopkg.in/yaml.v3"
)

func contains(list []string, s string) bool { return slices.Contains(list, s) }

func cmdValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	cf.register(fs)
	offline := fs.Bool("offline", false, "don't require secrets: missing environment variables get placeholders and are listed")
	asTunnel := fs.Bool("tunnel", false, "check the config as the Helm chart runs it in mode tunnel: adds listen: off, a placeholder tunnel section, and neubird_destinations.client_auth: none when unset")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: neubird-proxy validate [-config path] [-env-file file] [-offline] [-tunnel]")
		fmt.Fprintln(stderr, "\nChecks everything the proxy checks at startup, prints its warnings, and summarizes each connection.")
		fs.PrintDefaults()
	}
	if fs.Parse(args) != nil {
		return 2
	}

	sec, err := loadSecrets(cf.envFile, *offline)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	raw, err := os.ReadFile(cf.config)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if *asTunnel {
		if raw, err = chartTunnel(raw); err != nil {
			fmt.Fprintf(stdout, "INVALID %s\n  error: %v\n", cf.config, err)
			return 1
		}
	}
	cfg, engine, err := loadConfigBytes(raw, sec)
	if err != nil {
		fmt.Fprintf(stdout, "INVALID %s\n", cf.config)
		lines := splitErrors(err)
		// The rules compile only after the rest of the config parses;
		// check them on their own too, so one run reports everything.
		if rc, rerr := config.LoadRedaction(cf.config, (&secrets{offline: true, missing: map[string]bool{}}).lookup); rerr == nil {
			if _, rerr := redact.New(*rc); rerr != nil {
				for _, l := range splitErrors(rerr) {
					if !contains(lines, l) {
						lines = append(lines, l)
					}
				}
			}
		}
		for _, line := range lines {
			fmt.Fprintf(stdout, "  error: %s\n", line)
		}
		if !*offline && strings.Contains(err.Error(), "is not set") {
			fmt.Fprintln(stdout, "\n  hint: run with -offline to check the config without its secrets")
		}
		return 1
	}

	fmt.Fprintf(stdout, "VALID %s\n\n", cf.config)
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CONNECTION\tUPSTREAM\tAUTH\tMETHODS\tPATHS\tMCP TOOLS\tFIELDS\tMODE")
	for _, c := range cfg.Connections {
		methods := allowHeaderOf(c.MethodSet)
		paths := "any"
		if len(c.Paths) > 0 {
			paths = fmt.Sprint(len(c.Paths))
		}
		tools, fields := "-", "all"
		if len(c.MCPTools) > 0 {
			tools = fmt.Sprint(len(c.MCPTools))
		}
		if len(c.ResponseFields) > 0 {
			fields = fmt.Sprintf("%d allowed", len(c.ResponseFields))
		}
		mode := "redact"
		if c.Passthrough {
			mode = "PASSTHROUGH"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.Name, c.Upstream, c.ClientAuth, methods, paths, tools, fields, mode)
	}
	if d := cfg.NeubirdDestinations; d != nil {
		tools, fields := "-", "all"
		if len(d.Conn.MCPTools) > 0 {
			tools = fmt.Sprint(len(d.Conn.MCPTools))
		}
		if len(d.Conn.ResponseFields) > 0 {
			fields = fmt.Sprintf("%d allowed", len(d.Conn.ResponseFields))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", "neubird_destinations", strings.Join(d.Hosts, ","), d.Conn.ClientAuth,
			allowHeaderOf(d.Conn.MethodSet), "any", tools, fields, "NeuBird credentials")
		for _, r := range d.HostMethods {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", "  host_methods", strings.Join(r.Hosts, ","), d.Conn.ClientAuth,
				allowHeaderOf(r.MethodSet), "any", tools, fields, "NeuBird credentials")
		}
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\nredaction: mask=%s, rules: %s\n", cfg.Redaction.Mask, strings.Join(engine.RuleNames(), ", "))
	if t := cfg.Tunnel; t != nil {
		inbound := "inbound listener on " + cfg.Listen
		if cfg.Listen == config.ListenOff {
			inbound = "no inbound listener"
		}
		fmt.Fprintf(stdout, "\ntunnel: %d relay(s) x %d connection(s), %s\n", len(t.Relays), t.ConnectionsPerRelay, inbound)
		switch {
		case t.JoinToken != "":
			fmt.Fprintf(stdout, "  join token: set (%s); the key enrolls itself on first connect\n", t.JoinTokenEnv)
		case t.JoinTokenEnv != "":
			fmt.Fprintf(stdout, "  join token: %s is empty; the key must already be recorded or enrolled\n", t.JoinTokenEnv)
		}
		if *asTunnel {
			fmt.Fprintln(stdout, "  tunnel section added as the Helm chart adds it (relay, tenant and key come from its values)")
		} else if *offline {
			fmt.Fprintln(stdout, "  certificate, key and CA files not checked (offline)")
		} else if id, err := tunnel.Load(t); err != nil {
			fmt.Fprintf(stdout, "INVALID tunnel: %v\n", err)
			return 1
		} else {
			fmt.Fprintf(stdout, "  identity: %s; key %s; certificate expires in %d days\n", identityText(id), id.Fingerprint, int(id.DaysLeft()))
			if id.DaysLeft() < 30 {
				fmt.Fprintln(stdout, "  warning: renew the tunnel certificate soon")
			}
		}
	}

	if ws := warnings(cfg); len(ws) > 0 {
		fmt.Fprintln(stdout, "\nwarnings:")
		for _, w := range ws {
			fmt.Fprintf(stdout, "  - %s\n", w)
		}
	}
	if m := sec.missingNames(); len(m) > 0 {
		fmt.Fprintf(stdout, "\nnot checked (offline, placeholders used): %s\n", strings.Join(m, ", "))
	}
	return 0
}

// splitErrors flattens errors.Join output into one line per problem.
func splitErrors(err error) []string {
	var lines []string
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		for _, e := range joined.Unwrap() {
			lines = append(lines, splitErrors(e)...)
		}
		return lines
	}
	for _, l := range strings.Split(err.Error(), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func allowHeaderOf(set map[string]bool) string {
	var ms []string
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		if set[m] {
			ms = append(ms, m)
		}
	}
	return strings.Join(ms, ",")
}

// chartTunnel adds to a config what the Helm chart adds in mode tunnel:
// listen: off, a tunnel section (placeholders here: the chart fills it from
// its values), and, with a neubird_destinations that names no token
// (client_auth, client_token_env, client_auth_header), client_auth: none. It refuses a config that already sets listen or tunnel, as the chart
// does.
func chartTunnel(raw []byte) ([]byte, error) {
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	for _, k := range []string{"listen", "tunnel"} {
		if _, ok := m[k]; ok {
			return nil, fmt.Errorf("%s: leave it out with -tunnel (the chart sets it)", k)
		}
	}
	m["listen"] = config.ListenOff
	m["tunnel"] = map[string]any{
		"relays": []string{"relay.invalid:443"}, "tenant": "tenant", "proxy": "proxy",
		"key_file": "tunnel.key", "ca_file": "relay-ca.crt",
	}
	if d, ok := m["neubird_destinations"].(map[string]any); ok {
		// As the chart: only when the section names no token at all.
		unset := true
		for _, k := range []string{"client_auth", "client_token_env", "client_auth_header"} {
			if v, _ := d[k].(string); v != "" {
				unset = false
			}
		}
		if unset {
			d["client_auth"] = "none"
		}
	}
	return yaml.Marshal(m)
}
