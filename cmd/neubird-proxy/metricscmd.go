package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// cmdMetrics sums the Prometheus text output of one or more proxy pods
// and prints it as tables. Sources are URLs, files, or - for stdin, e.g.:
//
//	kubectl get --raw /api/v1/namespaces/NS/pods/POD:9090/proxy/metrics | neubird-proxy metrics -
func cmdMetrics(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("metrics", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: neubird-proxy metrics <url | file | -> ...")
		fmt.Fprintln(stderr, "\nSums /metrics output from one or more pods. Inside the cluster:")
		fmt.Fprintln(stderr, "  for p in $(kubectl -n NS get pods -l app=neubird-proxy -o name); do")
		fmt.Fprintln(stderr, "    kubectl get --raw /api/v1/namespaces/NS/${p/pod\\//pods/}:9090/proxy/metrics; done | neubird-proxy metrics -")
	}
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	totals := map[string]float64{}
	client := &http.Client{Timeout: 10 * time.Second}
	for _, src := range fs.Args() {
		var r io.ReadCloser
		var err error
		switch {
		case src == "-":
			r = io.NopCloser(os.Stdin)
		case strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://"):
			var resp *http.Response
			if resp, err = client.Get(src); err == nil {
				if resp.StatusCode != 200 {
					resp.Body.Close()
					err = fmt.Errorf("HTTP %d", resp.StatusCode)
				}
				r = resp.Body
			}
		default:
			r, err = os.Open(src)
		}
		if err != nil {
			fmt.Fprintf(stderr, "error: %s: %v\n", src, err)
			return 1
		}
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}
			i := strings.LastIndexByte(line, ' ')
			v, err := strconv.ParseFloat(line[i+1:], 64)
			if i < 0 || err != nil {
				continue
			}
			totals[line[:i]] += v
		}
		r.Close()
	}

	sections := []struct{ metric, title, label string }{
		{"neubird_proxy_requests_total", "Requests", "code"},
		{"neubird_proxy_redactions_total", "Redactions", "rule"},
		{"neubird_proxy_blocked_total", "Blocked", "reason"},
		{"neubird_proxy_response_bytes_total", "Response bytes", ""},
	}
	for _, sec := range sections {
		type cell struct {
			conn, key string
			v         float64
		}
		var cells []cell
		sum := 0.0
		for series, v := range totals {
			if !strings.HasPrefix(series, sec.metric+"{") && series != sec.metric {
				continue
			}
			labels := parseLabels(series[len(sec.metric):])
			cells = append(cells, cell{labels["connection"], labels[sec.label], v})
			sum += v
		}
		fmt.Fprintf(stdout, "%s (total %g)\n", sec.title, sum)
		if len(cells) == 0 {
			fmt.Fprintln(stdout, "  none")
		}
		sort.Slice(cells, func(i, j int) bool {
			if cells[i].conn != cells[j].conn {
				return cells[i].conn < cells[j].conn
			}
			return cells[i].v > cells[j].v
		})
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
		for _, c := range cells {
			fmt.Fprintf(tw, "  %g\t %s\t %s\t\n", c.v, c.conn, c.key)
		}
		tw.Flush()
		fmt.Fprintln(stdout)
	}
	return 0
}

// parseLabels reads {a="x",b="y"} as written by the proxy's exporter.
func parseLabels(s string) map[string]string {
	out := map[string]string{}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")
	for s != "" {
		k, rest, ok := strings.Cut(s, `="`)
		if !ok {
			break
		}
		var v strings.Builder
		i := 0
		for ; i < len(rest); i++ {
			if rest[i] == '\\' && i+1 < len(rest) {
				i++
				if rest[i] == 'n' {
					v.WriteByte('\n')
				} else {
					v.WriteByte(rest[i]) // \\ or \"
				}
				continue
			}
			if rest[i] == '"' {
				break
			}
			v.WriteByte(rest[i])
		}
		out[k] = v.String()
		s = strings.TrimPrefix(rest[min(i+1, len(rest)):], ",")
	}
	return out
}
