package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := &Registry{}
	c := r.Counter("reqs_total", "Requests.", "conn", "code")
	c.Inc("splunk", "200")
	c.Add(2, "splunk", "200")
	c.Inc("a\"b\\c\nd\té", "500")
	u := r.Counter("up_total", "No labels.")
	u.Inc()

	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	got := rec.Body.String()
	want := `# HELP reqs_total Requests.
# TYPE reqs_total counter
reqs_total{conn="a\"b\\c\nd	é",code="500"} 1
reqs_total{conn="splunk",code="200"} 3
# HELP up_total No labels.
# TYPE up_total counter
up_total 1
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	if c.Value("splunk", "200") != 3 {
		t.Fatal("Value")
	}
}

func TestWrongLabelCountPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	(&Registry{}).Counter("x", "x", "a").Inc()
}

func TestGauge(t *testing.T) {
	r := &Registry{}
	g := r.Gauge("tunnels", "Tunnels up.", "relay")
	g.Set(2, "r1")
	g.Add(-1, "r1")
	var b strings.Builder
	r.Write(&b)
	if !strings.Contains(b.String(), "# TYPE tunnels gauge\ntunnels{relay=\"r1\"} 1\n") {
		t.Fatalf("got:\n%s", b.String())
	}
}
