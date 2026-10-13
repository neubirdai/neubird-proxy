package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/redact"
)

// cmdPreview shows a response next to what NeuBird would receive for it.
// The sample goes through the proxy's real handler (a copy of the
// connection pointed at a local stand-in upstream that serves the sample),
// so the output is exactly what the proxy would send, including refusals.
func cmdPreview(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("preview", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	cf.register(fs)
	connName := fs.String("connection", "", "connection whose rules apply (required when the config has several)")
	ct := fs.String("content-type", "", "Content-Type of the sample (default: application/json if it parses as JSON, else text/plain)")
	live := fs.Bool("live", false, "capture a real response through the connection instead of reading a sample (needs secrets)")
	method := fs.String("method", "GET", "with -live: request method")
	path := fs.String("path", "/", "with -live: path after the connection prefix")
	data := fs.String("data", "", "with -live: request body (sent as application/json)")
	htmlOut := fs.String("html", "", "write a side-by-side HTML report to this file; - writes only the report to stdout")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: neubird-proxy preview [flags] [sample-file | -]")
		fmt.Fprintln(stderr, "       neubird-proxy preview -live -connection splunk -path /services/server/info")
		fmt.Fprintln(stderr, "\nShows a response next to what NeuBird would receive. Without -live, secrets are")
		fmt.Fprintln(stderr, "not needed (except mask: hmac, whose codes then differ from production).")
		fmt.Fprintln(stderr, "The original data is printed or written to the report: treat both as sensitive.")
		fs.PrintDefaults()
	}
	if fs.Parse(args) != nil {
		return 2
	}
	if !*live && fs.NArg() != 1 {
		fs.Usage()
		return 2
	}

	sec, err := loadSecrets(cf.envFile, !*live)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	cfg, engine, err := loadConfig(cf.config, sec)
	if err != nil {
		for _, l := range splitErrors(err) {
			fmt.Fprintln(stderr, "error:", l)
		}
		return 1
	}
	conn, err := pickConnection(cfg, *connName)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	var sample []byte
	sampleType := *ct
	source := ""
	if *live {
		if conn.Name == config.DestinationsConnName {
			fmt.Fprintln(stderr, "error: -live needs a connection; for neubird_destinations, capture a response and preview the file")
			return 2
		}
		sample, sampleType, err = capture(cfg, engine, conn, *method, *path, *data)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		source = fmt.Sprintf("live %s %s%s", *method, conn.Upstream, *path)
	} else {
		name := fs.Arg(0)
		if name == "-" {
			sample, err = io.ReadAll(os.Stdin)
			name = "stdin"
		} else {
			sample, err = os.ReadFile(name)
		}
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		source = name
	}
	if sampleType == "" {
		sampleType = "text/plain"
		if _, err := splitJSON(sample); err == nil {
			sampleType = "application/json"
		}
	}

	res, err := redactSample(cfg, engine, conn, sample, sampleType)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	res.source, res.connection, res.mask = source, conn.Name, cfg.Redaction.Mask
	if conn.Name == config.DestinationsConnName {
		res.connection = "neubird_destinations"
	}
	if cfg.Redaction.Mask == config.MaskHMAC && sec.missing[cfg.Redaction.HMACKeyEnv] {
		res.notes = append(res.notes, "mask: hmac with a placeholder key: codes differ from production (pass the real key with -env-file)")
	}

	if *htmlOut == "-" {
		// Only the report on stdout, for kubectl exec ... > report.html
		// (a proxy pod has a read-only filesystem).
		if err := renderReport(stdout, res); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		return 0
	}
	printPreview(stdout, res)
	if *htmlOut != "" {
		if err := writeReport(*htmlOut, res); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		fmt.Fprintf(stdout, "\nreport written to %s (contains the original data: handle as sensitive)\n", *htmlOut)
	}
	return 0
}

func pickConnection(cfg *config.Config, name string) (*config.Connection, error) {
	if name != "" {
		return findConnection(cfg, name)
	}
	if len(cfg.Connections) == 1 {
		return &cfg.Connections[0], nil
	}
	if len(cfg.Connections) == 0 && cfg.NeubirdDestinations != nil {
		// The rules for every destination NeuBird names.
		return cfg.NeubirdDestinations.Conn, nil
	}
	var names []string
	for _, c := range cfg.Connections {
		names = append(names, c.Name)
	}
	return nil, fmt.Errorf("pick a connection with -connection (%s)", strings.Join(names, ", "))
}

// capture fetches one raw response through the connection, with redaction
// turned off for this request only: same routing, credentials and request
// allowlists as NeuBird's traffic.
func capture(cfg *config.Config, engine *redact.Engine, conn *config.Connection, method, path, data string) ([]byte, string, error) {
	raw := *cfg
	raw.Connections = append([]config.Connection(nil), cfg.Connections...)
	for i := range raw.Connections {
		if raw.Connections[i].Name == conn.Name {
			raw.Connections[i].Passthrough = true
		}
	}
	p, err := newInProcess(&raw, engine)
	if err != nil {
		return nil, "", err
	}
	c, _ := findConnection(&raw, conn.Name)
	var body []byte
	ct := ""
	if data != "" {
		body, ct = []byte(data), "application/json"
	}
	rec, _, _ := p.do(clientRequest(c, method, path, body, ct))
	if kind, reason, ok := proxyError(rec); ok {
		return nil, "", fmt.Errorf("the proxy refused the capture request: %s (%s)", kind, reason)
	}
	if rec.Code >= 400 {
		return nil, "", fmt.Errorf("upstream returned HTTP %d: %.300s", rec.Code, rec.Body.String())
	}
	return rec.Body.Bytes(), rec.Header().Get("Content-Type"), nil
}

type previewResult struct {
	source, connection, mask, contentType string
	original, redacted                    []byte
	refused                               string // why the proxy would refuse this response, if it would
	cut                                   bool
	rules                                 string
	notes                                 []string
}

// redactSample serves sample from a local stand-in upstream and fetches it
// through a copy of the connection, keeping its redaction settings and
// dropping its request allowlists (they apply to NeuBird's request, not to
// the response being previewed).
func redactSample(cfg *config.Config, engine *redact.Engine, conn *config.Connection, sample []byte, contentType string) (*previewResult, error) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Write(sample)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)

	local := *cfg
	local.Connections = append([]config.Connection(nil), cfg.Connections...)
	if conn.Name == config.DestinationsConnName {
		// Serve neubird_destinations' rules as a connection, so the sample
		// comes from the local stand-in rather than a named destination.
		local.Connections = append(local.Connections, *conn)
		local.NeubirdDestinations = nil
	}
	var target *config.Connection
	for i := range local.Connections {
		if local.Connections[i].Name != conn.Name {
			continue
		}
		c := &local.Connections[i]
		c.UpstreamURL = u
		c.MethodSet = map[string]bool{http.MethodGet: true}
		c.PathRes, c.RequestDenyRes, c.MCPTools, c.RateLimit = nil, nil, nil, nil
		c.Headers, c.ResolvedHeaders, c.BasicAuth = nil, nil, nil
		target = c
	}
	p, err := newInProcess(&local, engine)
	if err != nil {
		return nil, err
	}
	rec, audit, cut := p.do(clientRequest(target, http.MethodGet, "/", nil, ""))

	res := &previewResult{contentType: contentType, original: sample, cut: cut, rules: rulesSummary(audit)}
	if kind, reason, ok := proxyError(rec); ok {
		res.refused = kind + ": " + reason
		return res, nil
	}
	res.redacted = rec.Body.Bytes()
	if cut {
		reason, _ := audit["blocked"].(string)
		res.refused = "stream cut mid-way: " + reason
	}
	if conn.Passthrough {
		res.notes = append(res.notes, "this connection is passthrough: NeuBird receives the response unredacted")
	}
	return res, nil
}

// --- presentation ---

type row struct {
	n         int
	orig, red string
	changed   bool
	gap       bool // stands for unchanged lines left out
}

// rows pairs the two versions line by line. JSON is pretty-printed first,
// so values sit on their own lines. Redaction keeps structure, so the line
// counts match except when a multi-line value (a PEM key) collapses into
// one mask; then an LCS diff aligns them.
func rows(res *previewResult) []row {
	orig, red := prettyLines(res.original), prettyLines(res.redacted)
	var all []row
	if len(orig) == len(red) {
		for i := range orig {
			all = append(all, row{n: i + 1, orig: orig[i], red: red[i], changed: orig[i] != red[i]})
		}
	} else {
		all = lcsRows(orig, red)
	}
	// Keep changed lines with 2 lines of context; fold the rest.
	keep := make([]bool, len(all))
	for i, r := range all {
		if r.changed {
			for j := max(0, i-2); j <= min(len(all)-1, i+2); j++ {
				keep[j] = true
			}
		}
	}
	var out []row
	for i, r := range all {
		if keep[i] {
			out = append(out, r)
		} else if len(out) == 0 || !out[len(out)-1].gap {
			out = append(out, row{gap: true})
		}
	}
	return out
}

func prettyLines(b []byte) []string {
	if docs, err := splitJSON(b); err == nil {
		var buf bytes.Buffer
		for i, d := range docs {
			if i > 0 {
				buf.WriteByte('\n')
			}
			json.Indent(&buf, d, "", "  ")
		}
		b = buf.Bytes()
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

// splitJSON splits concatenated JSON documents, keeping each one's bytes.
func splitJSON(b []byte) ([]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var docs []json.RawMessage
	for {
		var d json.RawMessage
		if err := dec.Decode(&d); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		docs = append(docs, d)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("empty")
	}
	return docs, nil
}

func lcsRows(a, b []string) []row {
	if len(a)*len(b) > 4_000_000 {
		// Too large to align; show the redacted version alone.
		var out []row
		for i, l := range b {
			out = append(out, row{n: i + 1, red: l, changed: true})
		}
		return out
	}
	dp := make([][]int, len(a)+1)
	for i := range dp {
		dp[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	var out []row
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			out = append(out, row{n: i + 1, orig: a[i], red: b[j]})
			i, j = i+1, j+1
		case j < len(b) && (i == len(a) || dp[i][j+1] >= dp[i+1][j]):
			out = append(out, row{n: i + 1, red: b[j], changed: true})
			j++
		default:
			out = append(out, row{n: i + 1, orig: a[i], changed: true})
			i++
		}
	}
	return out
}

func printPreview(w io.Writer, res *previewResult) {
	fmt.Fprintf(w, "connection %s, %s, mask: %s, sample: %s (%d bytes)\n", res.connection, res.contentType, res.mask, res.source, len(res.original))
	for _, n := range res.notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
	if res.refused != "" && !res.cut {
		fmt.Fprintf(w, "\nREFUSED: the proxy would not send this response to NeuBird (%s).\nNeuBird would get a 502 instead.\n", res.refused)
		return
	}
	if res.refused != "" {
		fmt.Fprintf(w, "\nCUT: %s. NeuBird would receive the part shown below, then a broken stream.\n", res.refused)
	}
	fmt.Fprintf(w, "redactions: %s\n", res.rules)
	if strings.Contains(res.rules, "field_not_allowed") {
		fmt.Fprintln(w, "            (field_not_allowed: a field not in response_fields, masked whole as [REDACTED:FIELD] before any other rule)")
	}
	fmt.Fprint(w, "legend:     - returned by the system   + received by NeuBird\n\n")
	rs := rows(res)
	changed := 0
	for _, r := range rs {
		switch {
		case r.gap:
			fmt.Fprintln(w, "  ...")
		case r.changed:
			changed++
			if r.orig != "" {
				fmt.Fprintf(w, "%5d - %s\n", r.n, r.orig)
			}
			if r.red != "" {
				fmt.Fprintf(w, "      + %s\n", r.red)
			}
		default:
			fmt.Fprintf(w, "%5d   %s\n", r.n, r.orig)
		}
	}
	if changed == 0 {
		fmt.Fprintln(w, "no changes: NeuBird would receive the sample as is")
	}
}

var maskRe = regexp.MustCompile(`\[REDACTED:[A-Z0-9_]+(?::[0-9a-f]{16})?\]`)

type segment struct {
	Text string
	Mask bool
}

func segments(s string) []segment {
	var out []segment
	pos := 0
	for _, loc := range maskRe.FindAllStringIndex(s, -1) {
		if loc[0] > pos {
			out = append(out, segment{Text: s[pos:loc[0]]})
		}
		out = append(out, segment{Text: s[loc[0]:loc[1]], Mask: true})
		pos = loc[1]
	}
	if pos < len(s) {
		out = append(out, segment{Text: s[pos:]})
	}
	return out
}

func writeReport(path string, res *previewResult) error {
	// The report holds the unredacted responses: readable by the owner only.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := renderReport(f, res); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func renderReport(w io.Writer, res *previewResult) error {
	type viewRow struct {
		N       int
		Orig    string
		Red     []segment
		Changed bool
		Gap     bool
	}
	var vr []viewRow
	changed := 0
	if res.refused == "" || res.cut {
		for _, r := range rows(res) {
			if r.changed {
				changed++
			}
			vr = append(vr, viewRow{N: r.n, Orig: r.orig, Red: segments(r.red), Changed: r.changed, Gap: r.gap})
		}
	}
	return reportTmpl.Execute(w, map[string]any{
		"Connection": res.connection, "Source": res.source, "ContentType": res.contentType, "Mask": res.mask,
		"Rules": res.rules, "Notes": res.notes, "Refused": res.refused, "Cut": res.cut,
		"Rows": vr, "Changed": changed, "Generated": time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		"Version": version, "Bytes": len(res.original),
	})
}

var reportTmpl = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Redaction preview</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--line:#e3e3e3;--chg:#fff6db;--mask-bg:#e2ecff;--mask-fg:#123c8c;--warn:#8a5a00;--warn-bg:#fff3d6;--bad:#9b1c1c;--bad-bg:#fde8e8}
@media (prefers-color-scheme:dark){:root{--bg:#141414;--fg:#e8e8e8;--muted:#a0a0a0;--line:#2c2c2c;--chg:#2f2a17;--mask-bg:#1d2f52;--mask-fg:#b9cdff;--warn:#f0c46a;--warn-bg:#33290f;--bad:#f5a3a3;--bad-bg:#3a1717}}
body{background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;padding:24px 16px}
main{max-width:1400px;margin:0 auto}
h1{font-size:20px;margin:0 0 4px}
.meta{color:var(--muted);margin-bottom:16px}
.banner{background:var(--warn-bg);color:var(--warn);padding:10px 12px;border-radius:6px;margin:12px 0}
.refused{background:var(--bad-bg);color:var(--bad);padding:10px 12px;border-radius:6px;margin:12px 0;font-weight:600}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0 0 16px}
dt{color:var(--muted)}dd{margin:0}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:6px}
table{border-collapse:collapse;width:100%;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;table-layout:fixed}
th{position:sticky;top:0;background:var(--bg);text-align:left;font:600 13px -apple-system,sans-serif;padding:8px;border-bottom:1px solid var(--line)}
td{padding:1px 8px;vertical-align:top;white-space:pre-wrap;word-break:break-all;border-bottom:1px solid var(--line)}
td.n{width:48px;color:var(--muted);text-align:right;white-space:nowrap}
tr.chg td{background:var(--chg)}
tr.gap td{color:var(--muted);text-align:center}
.m{background:var(--mask-bg);color:var(--mask-fg);border-radius:3px;padding:0 2px;font-weight:600}
</style></head><body><main>
<h1>Redaction preview</h1>
<div class="meta">Generated {{.Generated}} by neubird-proxy {{.Version}}</div>
<div class="banner">This report contains the original, unredacted data in the left column. Handle and share it as sensitive.</div>
<dl>
<dt>Connection</dt><dd>{{.Connection}}</dd>
<dt>Sample</dt><dd>{{.Source}} ({{.Bytes}} bytes, {{.ContentType}})</dd>
<dt>Masking</dt><dd>{{.Mask}}</dd>
<dt>Redactions</dt><dd>{{.Rules}}</dd>
{{range .Notes}}<dt>Note</dt><dd>{{.}}</dd>{{end}}
</dl>
{{if and .Refused (not .Cut)}}<div class="refused">The proxy would refuse this response ({{.Refused}}). NeuBird would receive a 502 instead of any of this data.</div>
{{else}}{{if .Cut}}<div class="refused">{{.Refused}}. NeuBird would receive the redacted part shown, then a broken stream.</div>{{end}}
<p>{{.Changed}} changed lines, shown with 2 lines of context; unchanged runs are folded.</p>
<div class="wrap"><table>
<thead><tr><th class="n">#</th><th>Returned by the system</th><th>Received by NeuBird</th></tr></thead>
<tbody>
{{range .Rows}}{{if .Gap}}<tr class="gap"><td class="n"></td><td colspan="2">…</td></tr>
{{else}}<tr{{if .Changed}} class="chg"{{end}}><td class="n">{{.N}}</td><td>{{.Orig}}</td><td>{{range .Red}}{{if .Mask}}<span class="m">{{.Text}}</span>{{else}}{{.Text}}{{end}}{{end}}</td></tr>
{{end}}{{end}}</tbody></table></div>{{end}}
</main></body></html>
`))
