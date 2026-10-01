package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/redact"
)

func contains(list []string, s string) bool { return slices.Contains(list, s) }

func cmdValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	cf.register(fs)
	offline := fs.Bool("offline", false, "don't require secrets: missing environment variables get placeholders and are listed")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: neubird-proxy validate [-config path] [-env-file file] [-offline]")
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
	cfg, engine, err := loadConfig(cf.config, sec)
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
	tw.Flush()
	fmt.Fprintf(stdout, "\nredaction: mask=%s, rules: %s\n", cfg.Redaction.Mask, strings.Join(engine.RuleNames(), ", "))

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
