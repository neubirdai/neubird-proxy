// Package metrics is a minimal Prometheus text exporter for labeled
// counters and gauges. It avoids the client library to keep the dependency
// list, and customers' image scans, short.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type Counter struct {
	name   string
	help   string
	kind   string // "counter" or "gauge"
	labels []string

	mu     sync.Mutex
	values map[string]float64 // key: label values joined by \xff
}

type Registry struct {
	mu       sync.Mutex
	counters []*Counter
}

func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	return r.add(&Counter{name: name, help: help, kind: "counter", labels: labels, values: map[string]float64{}})
}

// Gauge is a value that goes up and down (tunnels connected, days until a
// certificate expires). It shares Counter's methods; Set replaces a value.
func (r *Registry) Gauge(name, help string, labels ...string) *Counter {
	return r.add(&Counter{name: name, help: help, kind: "gauge", labels: labels, values: map[string]float64{}})
}

func (r *Registry) add(c *Counter) *Counter {
	r.mu.Lock()
	r.counters = append(r.counters, c)
	r.mu.Unlock()
	return c
}

// Set replaces a gauge's value.
func (c *Counter) Set(v float64, labelValues ...string) {
	if len(labelValues) != len(c.labels) {
		panic(fmt.Sprintf("metrics: %s wants %d labels, got %d", c.name, len(c.labels), len(labelValues)))
	}
	c.mu.Lock()
	c.values[strings.Join(labelValues, "\xff")] = v
	c.mu.Unlock()
}

func (c *Counter) Add(v float64, labelValues ...string) {
	if len(labelValues) != len(c.labels) {
		panic(fmt.Sprintf("metrics: %s wants %d labels, got %d", c.name, len(c.labels), len(labelValues)))
	}
	k := strings.Join(labelValues, "\xff")
	c.mu.Lock()
	c.values[k] += v
	c.mu.Unlock()
}

func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// Value is for tests.
func (c *Counter) Value(labelValues ...string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.values[strings.Join(labelValues, "\xff")]
}

func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	counters := append([]*Counter(nil), r.counters...)
	r.mu.Unlock()
	for _, c := range counters {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", c.name, c.help, c.name, c.kind)
		c.mu.Lock()
		keys := make([]string, 0, len(c.values))
		for k := range c.values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "%s%s %g\n", c.name, c.labelString(k), c.values[k])
		}
		c.mu.Unlock()
	}
}

// labelEscaper applies the text format's label escaping, which differs
// from Go's %q for control and non-ASCII characters.
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func (c *Counter) labelString(key string) string {
	if len(c.labels) == 0 {
		return ""
	}
	vals := strings.Split(key, "\xff")
	parts := make([]string, len(c.labels))
	for i, l := range c.labels {
		parts[i] = l + `="` + labelEscaper.Replace(vals[i]) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.Write(w)
	})
}
