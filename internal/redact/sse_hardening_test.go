package redact

import (
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

type countingBudget struct {
	mu        sync.Mutex
	held, max int64
}

func (b *countingBudget) Acquire(n int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.held += n
	if b.held > b.max {
		b.max = b.held
	}
	return nil
}

func (b *countingBudget) Release(n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.held -= n
}

// A partly received event is buffered within the budget, and everything is
// returned once the stream ends.
func TestSSEPendingInputIsBudgeted(t *testing.T) {
	e := engine(t, config.Redaction{})
	big := "data: " + strings.Repeat("x", 3<<20) + "\n\n"
	b := &countingBudget{}
	r := NewSSEReader(io.NopCloser(strings.NewReader(big)), e, Stats{}, 8<<20).WithBudget(b)
	if _, err := io.ReadAll(r); err != nil {
		t.Fatal(err)
	}
	r.Close()
	if b.max < 3<<20 {
		t.Fatalf("peak reservation %d, want at least the event's size", b.max)
	}
	if b.held != 0 {
		t.Fatalf("%d bytes still held after Close", b.held)
	}
}

// retry passes only as a number; under an allowlist, event names that
// aren't short names are masked.
func TestSSERetryAndEventLines(t *testing.T) {
	e := engine(t, config.Redaction{})
	in := "retry: jane.doe@example.com 4111111111111111\nevent: message\ndata: {}\n\nretry: 3000\nevent: Jane Smith diabetic\ndata: {}\n\n"
	out, _ := io.ReadAll(NewSSEReader(io.NopCloser(strings.NewReader(in)), e, Stats{}, 1<<20))
	if strings.Contains(string(out), "jane") || !strings.Contains(string(out), "retry: 3000") {
		t.Fatalf("no allowlist: %q", out)
	}
	f, _ := NewFields([]string{"jsonrpc"})
	out, _ = io.ReadAll(NewSSEReader(io.NopCloser(strings.NewReader(in)), e, Stats{}, 1<<20).WithFields(f))
	if strings.Contains(string(out), "Jane") || !strings.Contains(string(out), "event: message") {
		t.Fatalf("allowlist: %q", out)
	}
}
