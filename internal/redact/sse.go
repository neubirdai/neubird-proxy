package redact

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync/atomic"
)

// ErrEventTooLarge ends a stream whose single event exceeds the size cap.
// Headers are already sent by then, so failing closed means cutting the
// stream, not returning a 502.
var ErrEventTooLarge = errors.New("redact: SSE event exceeds max_body_bytes")

// ErrNotText ends a stream carrying bytes that are not UTF-8 text, such as
// a compressed payload the upstream did not declare. Regex over compressed
// bytes would pass the plaintext through.
var ErrNotText = errors.New("redact: SSE stream is not UTF-8 text")

// SSEReader redacts a text/event-stream body event by event. Each event is
// buffered to its terminating blank line, its data payload is redacted (as
// JSON when it parses, which covers MCP JSON-RPC messages, else as text),
// and it is released to the reader immediately so streaming still streams.
type SSEReader struct {
	src    io.ReadCloser
	e      *Engine
	st     Stats
	max    int
	fields *Fields
	budget Budget

	reserved int64       // budget held for in's capacity
	pending  atomic.Bool // part of an event is buffered; read from other goroutines
	activity func(busy bool)
	progress bool // an event completed since the activity was last reported
	scan     int  // where eventEnd resumes in in: the start of a line

	in    []byte
	out   []byte
	chunk []byte
	err   error
}

func NewSSEReader(src io.ReadCloser, e *Engine, st Stats, maxEvent int64) *SSEReader {
	return &SSEReader{src: src, e: e, st: st, max: int(maxEvent), chunk: make([]byte, 32<<10)}
}

// WithFields applies a field allowlist to JSON data payloads. A data
// payload that is not JSON is masked whole, since it cannot be checked.
func (r *SSEReader) WithFields(f *Fields) *SSEReader {
	r.fields = f
	return r
}

// Budget is shared memory accounting: Acquire blocks until n bytes are
// free (or fails), Release returns them.
type Budget interface {
	Acquire(n int64) error
	Release(n int64)
}

var eventNameRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// sseFactor is how many times its size redacting an event takes.
const sseFactor = 12

// pendingChunk is the granularity of reservations for buffered input.
const pendingChunk = 1 << 20

// WithBudget accounts for the reader's memory: the input buffered while an
// event arrives, and redacting each event.
func (r *SSEReader) WithBudget(b Budget) *SSEReader {
	r.budget = b
	return r
}

// reserveIn makes sure in's capacity is covered by the budget.
func (r *SSEReader) reserveIn() error {
	if r.budget == nil {
		return nil
	}
	want := (int64(cap(r.in)) + pendingChunk - 1) / pendingChunk * pendingChunk
	if want <= r.reserved {
		return nil
	}
	// Give back what's held before waiting for the larger amount, so the
	// stream never holds memory while it waits.
	if r.reserved > 0 {
		r.budget.Release(r.reserved)
		r.reserved = 0
	}
	if err := r.budget.Acquire(want); err != nil {
		return err
	}
	r.reserved = want
	return nil
}

// compactIn drops consumed input: in starts over (and its reservation is
// returned) when empty, else the rest moves to a buffer of its own size.
func (r *SSEReader) compactIn(consumed int) {
	r.in = r.in[consumed:]
	r.scan = 0
	if len(r.in) == 0 {
		r.in = nil
	} else {
		r.in = append([]byte(nil), r.in...)
	}
	if r.budget != nil && r.reserved > 0 && len(r.in) == 0 {
		r.budget.Release(r.reserved)
		r.reserved = 0
	}
}

// redactEvent is event, within the memory budget when one is set.
func (r *SSEReader) redactEvent(ev []byte) ([]byte, error) {
	if r.budget != nil {
		// The input's reservation goes first, so the stream never holds
		// memory while it waits for more (the event's reservation covers
		// the input too). reserveIn takes it again on the next read.
		if r.reserved > 0 {
			r.budget.Release(r.reserved)
			r.reserved = 0
		}
		n := int64(len(ev)) * sseFactor
		if err := r.budget.Acquire(n); err != nil {
			return nil, err
		}
		defer r.budget.Release(n)
	}
	return r.event(ev), nil
}

func (r *SSEReader) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		r.pending.Store(len(r.in) > 0)
		if r.activity != nil {
			// The deadline covers one event: it starts over whenever an
			// event completes.
			if r.progress {
				r.activity(false)
				r.progress = false
			}
			r.activity(len(r.in) > 0)
		}
		n, err := r.src.Read(r.chunk)
		r.in = append(r.in, r.chunk[:n]...)
		derr := r.reserveIn()
		if derr == nil {
			derr = r.drain()
		}
		if derr == nil {
			// What's left of a partial event stays reserved while the
			// next read waits.
			derr = r.reserveIn()
		}
		switch {
		case derr != nil:
			// Complete events already in out are released; the offending
			// event never is.
			r.in = nil
			r.err = derr
		case len(r.in) > r.max:
			r.in = nil
			r.err = ErrEventTooLarge
		case err == io.EOF:
			if len(r.in) > 0 {
				if !IsText(r.in) {
					r.in = nil
					r.err = ErrNotText
					break
				}
				out, err := r.redactEvent(r.in)
				r.compactIn(len(r.in))
				if err != nil {
					r.err = err
					break
				}
				r.out = append(r.out, out...)
			}
			r.err = io.EOF
		case err != nil:
			r.err = err
		}
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *SSEReader) Close() error {
	err := r.src.Close()
	r.in = nil
	if r.budget != nil && r.reserved > 0 {
		r.budget.Release(r.reserved)
		r.reserved = 0
	}
	return err
}

// WithActivity reports when part of an event is buffered (busy) and when
// none is, so the caller can bound how long an event may take to arrive.
func (r *SSEReader) WithActivity(f func(busy bool)) *SSEReader {
	r.activity = f
	return r
}

// Pending reports whether part of an event is buffered, waiting for the
// rest.
// It's safe to call while Read runs.
func (r *SSEReader) Pending() bool { return r.pending.Load() }

// Err is the error that ended the stream, if any, other than io.EOF.
func (r *SSEReader) Err() error {
	if r.err == io.EOF {
		return nil
	}
	return r.err
}

// drain moves every complete event from in to out. It stops at the first
// event over the cap or not text, so the checks hold whether an event
// arrives in pieces or in a single read.
func (r *SSEReader) drain() error {
	for {
		end, next, resume := eventEnd(r.in, r.scan)
		if end < 0 {
			r.scan = resume
			return nil
		}
		if end > r.max {
			return ErrEventTooLarge
		}
		if !IsText(r.in[:end]) {
			return ErrNotText
		}
		out, err := r.redactEvent(r.in[:end])
		if err != nil {
			return err
		}
		r.out = append(r.out, out...)
		r.out = append(r.out, '\n')
		r.compactIn(next)
		r.progress = true
	}
}

// eventEnd finds the blank line that ends the first event in b. It returns
// the length of the event's lines and the offset just past the blank line,
// or -1 if no complete event is buffered. A trailing \r is ambiguous (it
// may start \r\n) until more input arrives; at EOF the leftover is
// flushed as a partial event, which splitLines handles.
//
// Scanning starts at from, a line start already known not to end an event;
// resume is where the next call can start.
func eventEnd(b []byte, from int) (end, next, resume int) {
	lineStart := from
	for i := from; i < len(b); i++ {
		c := b[i]
		if c != '\n' && c != '\r' {
			continue
		}
		term := 1
		if c == '\r' {
			if i+1 == len(b) {
				return -1, -1, lineStart
			}
			if i+1 < len(b) && b[i+1] == '\n' {
				term = 2
			}
		}
		if i == lineStart {
			return lineStart, i + term, 0
		}
		lineStart = i + term
		i += term - 1
	}
	return -1, -1, lineStart
}

// event rewrites one event's lines, each terminated by \n.
func (r *SSEReader) event(ev []byte) []byte {
	lines := splitLines(ev)
	var data []string
	dataAt := -1
	var out bytes.Buffer

	type line struct {
		text   string
		isData bool
	}
	var kept []line
	for _, l := range lines {
		field, value, hasColon := strings.Cut(l, ":")
		if hasColon {
			value = strings.TrimPrefix(value, " ")
		}
		switch {
		case field == "data":
			if dataAt < 0 {
				dataAt = len(kept)
				kept = append(kept, line{isData: true})
			}
			data = append(data, value)
		case field == "retry":
			// A reconnection delay in milliseconds; anything else is
			// dropped, as clients ignore it.
			if v := strings.TrimSpace(value); v != "" && strings.Trim(v, "0123456789") == "" && len(v) <= 10 {
				kept = append(kept, line{text: "retry: " + v})
			}
		case r.fields != nil && field != "" && field != "event" && field != "id":
			// Unknown fields carry data the allowlist can't check; clients
			// ignore them anyway.
			r.st["field_not_allowed"]++
		case field == "" && hasColon:
			// Comment line; clients ignore it, but it still leaves MetLife.
			if r.fields != nil {
				r.st["field_not_allowed"]++
				kept = append(kept, line{text: ":"})
				break
			}
			kept = append(kept, line{text: ":" + r.e.String(l[1:], r.st)})
		case r.fields != nil && field == "event" && !eventNameRe.MatchString(value):
			// Event types are short names (message, ping); anything else is
			// data the allowlist didn't approve.
			kept = append(kept, line{text: "event: " + r.e.mask("FIELD", value)})
			r.st["field_not_allowed"]++
		case r.fields != nil && field == "id":
			// The id is opaque to the agent; only resumption uses it.
			kept = append(kept, line{text: "id: " + r.e.mask("FIELD", value)})
		default:
			// event, id and unknown fields. A redacted id breaks resumption
			// via Last-Event-ID for that event, which is the safe failure.
			kept = append(kept, line{text: r.e.String(l, r.st)})
		}
	}

	for _, l := range kept {
		if !l.isData {
			out.WriteString(l.text)
			out.WriteByte('\n')
			continue
		}
		payload := strings.Join(data, "\n")
		redacted, err := r.e.JSONFields([]byte(payload), r.st, r.fields)
		switch {
		case err == nil:
		case r.fields != nil:
			r.st["field_not_allowed"]++
			redacted = []byte(r.e.mask("FIELD", payload))
		default:
			redacted = []byte(r.e.String(payload, r.st))
		}
		for _, d := range strings.Split(string(redacted), "\n") {
			out.WriteString("data: ")
			out.WriteString(d)
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}

func splitLines(b []byte) []string {
	var lines []string
	start := 0
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '\n':
			lines = append(lines, string(b[start:i]))
			start = i + 1
		case '\r':
			lines = append(lines, string(b[start:i]))
			if i+1 < len(b) && b[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, string(b[start:]))
	}
	return lines
}
