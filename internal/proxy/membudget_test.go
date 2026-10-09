package proxy

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMemBudgetWaitsAndCancels(t *testing.T) {
	b := newMemBudget(100)
	if err := b.acquire(context.Background(), 60); err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() { got <- b.acquire(context.Background(), 60) }()
	select {
	case <-got:
		t.Fatal("second reservation didn't wait for room")
	case <-time.After(50 * time.Millisecond):
	}
	b.release(60)
	if err := <-got; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.acquire(ctx, 60); err == nil {
		t.Fatal("reservation over the free budget didn't give up on cancel")
	}
}

// With a memory limit too small for max_body_bytes, bodies are capped to
// what fits and larger ones fail closed instead of exhausting memory.
func TestMemoryLimitCapsBufferedBodies(t *testing.T) {
	body := func(n int) string { return `{"x":"` + strings.Repeat("a", n) + `"}` }
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, r *http.Request) {
		n := 1000
		if strings.HasSuffix(r.URL.Path, "/big") {
			n = 3000
		}
		jsonHandler(body(n))(w, r)
	})
	// Three quarters of 32 KiB, divided by bufferFactor: 2 KiB per body.
	if got := f.srv.SetMemoryLimit(32 << 10); got != 2<<10 {
		t.Fatalf("max buffered body %d, want 2048", got)
	}
	if resp, b := f.do(t, "GET", "/splunk/small", bearer); resp.StatusCode != 200 {
		t.Fatalf("small body: %d %s", resp.StatusCode, b)
	}
	if resp, b := f.do(t, "GET", "/splunk/big", bearer); resp.StatusCode != 502 || !strings.Contains(b, "body_too_large") {
		t.Fatalf("body over the memory cap: %d %s", resp.StatusCode, b)
	}
	if free := f.srv.mem.free; free != f.srv.mem.total {
		t.Fatalf("budget not released: %d of %d free", free, f.srv.mem.total)
	}
}
