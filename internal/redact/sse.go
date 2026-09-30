package redact

import (
	"bytes"
	"errors"
	"io"
	"strings"
)

// ErrEventTooLarge ends a stream whose single event exceeds the size cap.
// Headers are already sent by then, so failing closed means cutting the
// stream, not returning a 502.
var ErrEventTooLarge = errors.New("redact: SSE event exceeds max_body_bytes")

// SSEReader redacts a text/event-stream body event by event. Each event is
// buffered to its terminating blank line, its data payload is redacted (as
// JSON when it parses, which covers MCP JSON-RPC messages, else as text),
// and it is released to the reader immediately so streaming still streams.
type SSEReader struct {
	src io.ReadCloser
	e   *Engine
	st  Stats
	max int

	in    []byte
	out   []byte
	chunk []byte
	err   error
}

func NewSSEReader(src io.ReadCloser, e *Engine, st Stats, maxEvent int64) *SSEReader {
	return &SSEReader{src: src, e: e, st: st, max: int(maxEvent), chunk: make([]byte, 32<<10)}
}

func (r *SSEReader) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		n, err := r.src.Read(r.chunk)
		r.in = append(r.in, r.chunk[:n]...)
		tooLarge := r.drain()
		switch {
		case tooLarge || len(r.in) > r.max:
			// Complete events already in out are released; the oversized
			// partial event never is.
			r.in = nil
			r.err = ErrEventTooLarge
		case err == io.EOF:
			if len(r.in) > 0 {
				r.out = append(r.out, r.event(r.in)...)
				r.in = nil
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

func (r *SSEReader) Close() error { return r.src.Close() }

// Err is the error that ended the stream, if any, other than io.EOF.
func (r *SSEReader) Err() error {
	if r.err == io.EOF {
		return nil
	}
	return r.err
}

// drain moves every complete event from in to out. It stops and reports
// true at the first event over the cap, so the cap holds whether an event
// arrives in pieces or in a single read.
func (r *SSEReader) drain() (tooLarge bool) {
	for {
		end, next := eventEnd(r.in)
		if end < 0 {
			return false
		}
		if end > r.max {
			return true
		}
		r.out = append(r.out, r.event(r.in[:end])...)
		r.out = append(r.out, '\n')
		r.in = r.in[next:]
	}
}

// eventEnd finds the blank line that ends the first event in b. It returns
// the length of the event's lines and the offset just past the blank line,
// or -1 if no complete event is buffered. A trailing \r is ambiguous (it
// may start \r\n) until more input arrives; at EOF the leftover is
// flushed as a partial event, which splitLines handles.
func eventEnd(b []byte) (end, next int) {
	lineStart := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c != '\n' && c != '\r' {
			continue
		}
		term := 1
		if c == '\r' {
			if i+1 == len(b) {
				return -1, -1
			}
			if i+1 < len(b) && b[i+1] == '\n' {
				term = 2
			}
		}
		if i == lineStart {
			return lineStart, i + term
		}
		lineStart = i + term
		i += term - 1
	}
	return -1, -1
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
			kept = append(kept, line{text: l})
		case field == "" && hasColon:
			// Comment line; clients ignore it, but it still leaves MetLife.
			kept = append(kept, line{text: ":" + r.e.String(l[1:], r.st)})
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
		redacted, err := r.e.JSON([]byte(payload), r.st)
		if err != nil {
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
