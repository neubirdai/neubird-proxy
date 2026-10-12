package redact

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
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
	base     int64 // input consumed by decoders replaced (see shrink)
	budget   Budget
	activity func(busy bool)
}

// WithActivity reports when a later document starts arriving (busy) and
// when it's done, so the caller can bound how long one may take.
func (s *JSONStream) WithActivity(f func(busy bool)) *JSONStream {
	s.activity = f
	return s
}

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
	hit      bool   // a Read was refused at the limit
	carry    []byte // the start of a UTF-8 sequence split across reads
	bad      bool   // invalid UTF-8 was seen; every Read fails from then on
}

// readSlack is how far past a document's limit the decoder may read ahead
// (into the next document of a stream) before reads are refused.
const readSlack = 64 << 10

// Read never returns bytes beyond docStart+max+readSlack: a document over
// the limit fails as soon as the decoder needs those bytes, instead of
// being read, decoded and redacted in full first. Redacting a buffered
// document takes several times its size in memory.
func (c *countingReader) Read(p []byte) (int, error) {
	if c.bad {
		return 0, ErrNotText
	}
	left := c.docStart + c.max + readSlack - c.n
	if left <= 0 {
		c.hit = true
		return 0, ErrDocTooLarge
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	// JSON must be UTF-8, as text and SSE bodies must: the decoder would
	// turn each invalid byte into U+FFFD, three bytes, and normalize then
	// costs several times that.
	// The decoder keeps bytes that come with an error and may never read
	// again, so invalid input is withheld, not just reported.
	if verr := c.validate(p[:n], err == io.EOF); verr != nil {
		c.bad = true
		return 0, verr
	}
	return n, err
}

// validate checks that b continues valid UTF-8, keeping an incomplete
// sequence at its end for the next call; at EOF none may be left.
func (c *countingReader) validate(b []byte, eof bool) error {
	i := 0
	for len(c.carry) > 0 && i < len(b) {
		c.carry = append(c.carry, b[i])
		i++
		if utf8.FullRune(c.carry) {
			if r, size := utf8.DecodeRune(c.carry); r == utf8.RuneError && size <= 1 {
				return ErrNotText
			}
			c.carry = c.carry[:0]
		}
	}
	rest := b[i:]
	cut := len(rest)
	for k := 1; k <= utf8.UTFMax-1 && k <= len(rest); k++ {
		if s := rest[len(rest)-k]; utf8.RuneStart(s) {
			if !utf8.FullRune(rest[len(rest)-k:]) {
				cut = len(rest) - k
			}
			break
		}
	}
	if !utf8.Valid(rest[:cut]) {
		return ErrNotText
	}
	c.carry = append(c.carry, rest[cut:]...)
	if eof && len(c.carry) > 0 {
		return ErrNotText
	}
	return nil
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
		err = w.document(dec, tok)
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
	s.shrink() // s.lastDoc is the first document's size
	return s, false, nil, nil
}

// Read returns at least one whole document when one is ready, batching in
// further documents while they fit in p and the next one has probably
// arrived already (at least as many bytes are buffered as the last
// document took). The batching matters: a streamed response is flushed on
// every write, and one write per small Splunk result costs more than the
// redaction. The check keeps a batch from ever waiting on the upstream for
// long.
// offset is the input consumed so far, across decoders.
func (s *JSONStream) offset() int64 { return s.base + s.dec.InputOffset() }

// largeBuffer is the capacity above which buffers are dropped after a
// document rather than kept for the next: a stream may idle between
// documents for long, and only the document's work is in the budget.
const largeBuffer = 1 << 20

// shrink lets go of buffers a large document grew: the writer's, and the
// decoder's (a new decoder takes over what the old one had read ahead).
func (s *JSONStream) shrink() {
	if s.w.out.Cap() > largeBuffer {
		s.w.out = bytes.Buffer{}
	}
	if s.w.scratch.Cap() > largeBuffer {
		s.w.scratch = bytes.Buffer{}
	}
	if s.lastDoc > largeBuffer {
		ahead, _ := io.ReadAll(s.dec.Buffered())
		s.base = s.offset()
		s.dec = json.NewDecoder(io.MultiReader(bytes.NewReader(ahead), s.cr))
		s.dec.UseNumber()
	}
}

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
	if len(s.out) == 0 {
		s.out = nil // don't keep a large document's output while idle
	}
	return n, nil
}

// probablyBuffered reports whether the decoder holds at least as much
// unconsumed input as the last document took, and some input at all.
//
// Whitespace doesn't count: a run of it would send Read into next(), to wait
// there for a document that hasn't arrived while finished ones are held back.
func (s *JSONStream) probablyBuffered() bool {
	b := s.cr.n - s.offset()
	if b <= 0 || b < s.lastDoc {
		return false
	}
	// Only up to the first non-whitespace byte is looked at.
	ahead := bufio.NewReaderSize(s.dec.Buffered(), 16)
	for {
		c, err := ahead.ReadByte()
		if err != nil {
			return false
		}
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return true
		}
	}
}

func (s *JSONStream) next() {
	start := s.offset()
	s.cr.docStart = start
	// Between documents only whitespace may come, and only readSlack of it:
	// the decoder buffers it all while it looks for the next document,
	// outside the budget and with no deadline (the stream may idle here).
	max := s.cr.max
	s.cr.max, s.cr.hit = 0, false
	more := s.dec.More()
	s.cr.max = max
	if s.cr.hit {
		// The decoder doesn't keep a read error from More: stop here, or
		// Token would read on under the document's limit.
		s.err = ErrStreamNotJSON
		return
	}
	if (s.budget != nil || s.activity != nil) && more {
		if s.budget != nil {
			n := s.max * s.w.e.BufferFactor()
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
	if err := s.w.document(s.dec, tok); err != nil {
		if errors.Is(err, ErrDocTooLarge) {
			s.err = ErrDocTooLarge
		} else {
			s.err = ErrStreamNotJSON
		}
		return
	}
	if s.offset()-start > s.max {
		s.err = ErrDocTooLarge
		return
	}
	s.lastDoc = s.offset() - start
	s.out = append(append(s.out, s.w.out.Bytes()...), '\n')
	s.shrink()
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
