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

type strictBudget struct{ held, total int64 }

func (b *strictBudget) Acquire(n int64) error {
	if b.held+n > b.total {
		return io.ErrShortBuffer // would wait forever: nobody else releases
	}
	b.held += n
	return nil
}
func (b *strictBudget) Release(n int64) { b.held -= n }

// The stream never holds its input's reservation while it asks for the
// event's, so an event as large as the budget allows still goes through
// with no other traffic.
func TestSSENoHoldAndWait(t *testing.T) {
	e := engine(t, config.Redaction{})
	ev := "data: " + strings.Repeat("x", 1<<20) + "\n\n"
	b := &strictBudget{total: int64(len(ev)) * sseFactor}
	out, err := io.ReadAll(NewSSEReader(io.NopCloser(strings.NewReader(ev)), e, Stats{}, 2<<20).WithBudget(b))
	if err != nil || len(out) == 0 {
		t.Fatalf("err %v, %d bytes", err, len(out))
	}
}

// After a large document, a stream idling for the next one doesn't keep
// the buffers that document grew.
func TestJSONStreamShrinksAfterLargeDocument(t *testing.T) {
	e := engine(t, config.Redaction{})
	big := `{"a":"` + strings.Repeat("x", 3<<20) + `"}` + "\n"
	pr, pw := io.Pipe()
	go func() { io.WriteString(pw, `{"first":1}`+"\n"+big) }() // then idles
	s, _, _, err := NewJSONStream(pr, e, Stats{}, 8<<20, nil, -1)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	got := 0
	for got < len(big)+len(`{"first":1}`+"\n") {
		n, err := s.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got += n
	}
	if s.out != nil || s.w.out.Cap() > largeBuffer || s.w.scratch.Cap() > largeBuffer || s.base == 0 {
		t.Fatalf("kept: out %d, w.out %d, scratch %d, decoder replaced %v", cap(s.out), s.w.out.Cap(), s.w.scratch.Cap(), s.base != 0)
	}
	pw.Close()
}

func TestJSONStreamShrinksAfterLargeFirstDocument(t *testing.T) {
	e := engine(t, config.Redaction{})
	pr, pw := io.Pipe()
	go func() { io.WriteString(pw, `{"a":"`+strings.Repeat("x", 3<<20)+`"}`+"\n") }() // then idles
	s, single, _, err := NewJSONStream(pr, e, Stats{}, 8<<20, nil, -1)
	if err != nil || single {
		t.Fatal(err, single)
	}
	if s.w.scratch.Cap() > largeBuffer || s.base == 0 {
		t.Fatalf("kept: scratch %d, decoder replaced %v", s.w.scratch.Cap(), s.base != 0)
	}
	pw.Close()
}

// Once an event is complete and nothing is partly received, the deadline
// is off while the output is written.
func TestSSEDeadlineOffAfterCompleteEvent(t *testing.T) {
	e := engine(t, config.Redaction{})
	var busy bool
	r := NewSSEReader(io.NopCloser(strings.NewReader("data: x\n\n")), e, Stats{}, 1<<20).WithActivity(func(b bool) { busy = b })
	if _, err := r.Read(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if busy {
		t.Fatal("deadline still armed after a complete event")
	}
}

// Whitespace between stream documents is capped: it would otherwise be
// buffered, unbudgeted, while the stream waits for the next document.
func TestJSONStreamWhitespaceGapCapped(t *testing.T) {
	e := engine(t, config.Redaction{})
	in := `{"a":1}` + "\n" + `{"b":2}` + "\n" + strings.Repeat(" ", 1<<20) + `{"c":3}`
	s, _, _, err := NewJSONStream(io.NopCloser(strings.NewReader(in)), e, Stats{}, 8<<20, nil, -1)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(s)
	if s.Err() == nil || strings.Contains(string(out), `"c"`) {
		t.Fatalf("gap not refused: err %v, out %q", s.Err(), out)
	}
	if !strings.Contains(string(out), `{"b":2}`) {
		t.Fatalf("documents before the gap lost: %q", out)
	}
}

// Numbers alone don't make a JSON document: as text they get every rule.
func TestScalarDocumentsRedactedAsText(t *testing.T) {
	e := engine(t, config.Redaction{})
	out, _ := io.ReadAll(NewSSEReader(io.NopCloser(strings.NewReader("data: 4111 1111 1111 1111\n\n")), e, Stats{}, 1<<20))
	if strings.Contains(string(out), "4111") {
		t.Fatalf("SSE: %q", out)
	}
	got, err := e.JSON([]byte(`{"s":"[1] 4111 1111 1111 1111","t":"{} 4111111111111111"}`), Stats{})
	if err != nil || strings.Contains(string(got), "4111") {
		t.Fatalf("JSON in strings: %s %v", got, err)
	}
	if _, err := e.JSON([]byte(`4111111111111111`), Stats{}); err == nil {
		t.Fatal("bare number accepted as a JSON document")
	}
}
