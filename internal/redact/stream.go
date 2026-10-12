package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// ErrDocTooLarge ends a JSON stream whose single document exceeds the cap.
var ErrDocTooLarge = errors.New("redact: JSON document exceeds max_body_bytes")

// ErrStreamNotJSON ends a JSON stream whose later content does not parse.
// (A first document that does not parse is reported by NewJSONStream, while
// the caller can still refuse the response or fall back to text.)
var ErrStreamNotJSON = errors.New("redact: JSON stream has invalid content")

// JSONStream redacts a body of one or more concatenated JSON documents
// (Splunk export's newline-delimited results) one document at a time, so
// each is released as soon as it is complete and memory is bounded by the
// largest document rather than the whole body.
type JSONStream struct {
	src    io.ReadCloser
	cr     *countingReader
	dec    *json.Decoder
	w      *jsonWriter
	st     Stats
	max    int64
	fields *Fields

	out      []byte
	err      error
	lastDoc  int64 // input size of the last document, for batching
	budget   Budget
	activity func(busy bool)
}

// WithActivity reports when a later document starts arriving (busy) and
// when it's done, so the caller can bound how long one may take.
func (s *JSONStream) WithActivity(f func(busy bool)) *JSONStream {
	s.activity = f
	return s
}

// jsonFactor is how many times its size decoding and redacting a document
// may take.
const jsonFactor = 12

// WithBudget accounts for each later document while it's decoded: the
// stream waits for a document's first byte outside the budget, then
// reserves for the largest document it may be.
func (s *JSONStream) WithBudget(b Budget) *JSONStream {
	s.budget = b
	return s
}

// countingReader fails once the decoder has read far past the start of the
// current document, which bounds its internal buffer while a huge document
// is still arriving. The exact per-document cap is checked after each
// document decodes (a read can run into the next document, so the reader
// cannot tell where one ends).
type countingReader struct {
	r        io.Reader
	n        int64
	docStart int64
	max      int64
}

// readSlack is how far past a document's limit the decoder may read ahead
// (into the next document of a stream) before reads are refused.
const readSlack = 64 << 10

// Read never returns bytes beyond docStart+max+readSlack: a document over
// the limit fails as soon as the decoder needs those bytes, instead of
// being read, decoded and redacted in full first. Redacting a buffered
// document takes several times its size in memory.
func (c *countingReader) Read(p []byte) (int, error) {
	left := c.docStart + c.max + readSlack - c.n
	if left <= 0 {
		return 0, ErrDocTooLarge
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// NewJSONStream decodes and redacts the first document before returning,
// so the caller learns whether the body is JSON before any response header
// is sent.
//
// knownLen is the body's length when the upstream declared one, else -1.
// With a known length the body is bounded and committed, so NewJSONStream
// checks whether anything follows the first document; if not, single is
// true and Bytes returns the whole redacted body, exactly as the buffered
// path would write it. With no known length (a chunked Splunk export) it
// never waits for more input: the first document is ready to send at once,
// and later ones stream as they arrive. In streaming mode every document is
// followed by a newline, so a line reader never waits on the next one.
//
// On error, nothing has been emitted: raw holds every byte read from src so
// far, for a caller that wants to fall back to other handling, and src has
// not been closed.
func NewJSONStream(src io.ReadCloser, e *Engine, st Stats, maxDoc int64, fields *Fields, knownLen int64) (s *JSONStream, single bool, raw []byte, err error) {
	var head bytes.Buffer
	if knownLen > 0 && knownLen <= maxDoc+readSlack {
		head.Grow(int(knownLen))
	}
	cr := &countingReader{r: io.TeeReader(src, &head), max: maxDoc}
	dec := json.NewDecoder(cr)
	dec.UseNumber()
	w := &jsonWriter{e: e, fields: fields}
	w.enc = json.NewEncoder(&w.scratch)
	w.enc.SetEscapeHTML(false)
	s = &JSONStream{src: src, cr: cr, dec: dec, w: w, st: st, max: maxDoc, fields: fields}

	// Counts for the first document are committed only if it parses, so a
	// fallback to text does not double count.
	local := Stats{}
	w.st = local
	tok, err := dec.Token()
	if err == nil {
		err = w.value(dec, tok, nil)
	}
	if err != nil {
		if errors.Is(err, ErrDocTooLarge) {
			return nil, false, nil, err
		}
		return nil, false, head.Bytes(), err
	}
	if dec.InputOffset() > maxDoc {
		return nil, false, nil, ErrDocTooLarge
	}
	for k, v := range local {
		st[k] += v
	}
	w.st = st
	s.out = w.out.Bytes() // owned from here; w.out starts over for the next document
	w.out = bytes.Buffer{}

	// Raw bytes are only needed for the first document.
	cr.r = src
	cr.docStart = dec.InputOffset()
	s.lastDoc = dec.InputOffset()
	// More peeks past whitespace, reading if it must: only safe when the
	// body is bounded, or it would hold the first document back until the
	// upstream sends the next.
	if knownLen >= 0 && !dec.More() {
		// A single document comes out exactly as the buffered path wrote it.
		s.err = io.EOF
		return s, true, nil, nil
	}
	// Newline-delimited from here on: every document ends with \n.
	s.out = append(s.out, '\n')
	return s, false, nil, nil
}

// Read returns at least one whole document when one is ready, batching in
// further documents while they fit in p and the next one has probably
// arrived already (at least as many bytes are buffered as the last
// document took). The batching matters: a streamed response is flushed on
// every write, and one write per small Splunk result costs more than the
// redaction. The check keeps a batch from ever waiting on the upstream for
// long.
func (s *JSONStream) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		s.next()
	}
	for s.err == nil && len(s.out) < len(p) && s.probablyBuffered() {
		s.next()
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

// probablyBuffered reports whether the decoder holds at least as much
// unconsumed input as the last document took, and some input at all.
func (s *JSONStream) probablyBuffered() bool {
	b := s.cr.n - s.dec.InputOffset()
	return b > 0 && b >= s.lastDoc
}

func (s *JSONStream) next() {
	start := s.dec.InputOffset()
	s.cr.docStart = start
	if (s.budget != nil || s.activity != nil) && s.dec.More() {
		if s.budget != nil {
			n := s.max * jsonFactor
			if err := s.budget.Acquire(n); err != nil {
				s.err = err
				return
			}
			defer s.budget.Release(n)
		}
		// The deadline starts once the memory is held: waiting for it
		// isn't the upstream's time.
		if s.activity != nil {
			s.activity(true)
			defer s.activity(false)
		}
	}
	tok, err := s.dec.Token()
	switch {
	case err == io.EOF:
		s.err = io.EOF
		return
	case errors.Is(err, ErrDocTooLarge):
		s.err = ErrDocTooLarge
		return
	case err != nil:
		s.err = ErrStreamNotJSON
		return
	}
	s.w.out.Reset()
	if err := s.w.value(s.dec, tok, nil); err != nil {
		if errors.Is(err, ErrDocTooLarge) {
			s.err = ErrDocTooLarge
		} else {
			s.err = ErrStreamNotJSON
		}
		return
	}
	if s.dec.InputOffset()-start > s.max {
		s.err = ErrDocTooLarge
		return
	}
	s.lastDoc = s.dec.InputOffset() - start
	s.out = append(append(s.out, s.w.out.Bytes()...), '\n')
}

// Bytes returns the redacted output of a single-document body in full.
func (s *JSONStream) Bytes() []byte { return s.out }

func (s *JSONStream) Close() error { return s.src.Close() }

// Err is the error that ended the stream, if any, other than io.EOF.
func (s *JSONStream) Err() error {
	if s.err == io.EOF {
		return nil
	}
	return s.err
}
