package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

func openStream(t *testing.T, e *Engine, in io.Reader, max int64) (*JSONStream, bool, []byte, error) {
	t.Helper()
	return NewJSONStream(io.NopCloser(in), e, Stats{}, max, nil, -1)
}

func TestJSONStreamSingleDocumentMatchesBuffered(t *testing.T) {
	e := engine(t, config.Redaction{})
	in := "  {\"a\":\"jane@example.com\",\"n\":[1,2,{\"b\":\"219-09-9999\"}]}\n\n"
	want, _ := e.JSON([]byte(in), Stats{})
	s, single, _, err := NewJSONStream(io.NopCloser(iotest.OneByteReader(strings.NewReader(in))), e, Stats{}, 1<<20, nil, int64(len(in)))
	if err != nil || !single {
		t.Fatalf("single=%v err=%v", single, err)
	}
	if got := s.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestJSONStreamMultiDocumentMatchesBuffered(t *testing.T) {
	e := engine(t, config.Redaction{})
	in := `{"result":{"_raw":"a@b.io"}}` + "\n" + `{"result":{"_raw":"ok"}}` + "\n\n" + `[1,"c@d.io"]` + "\n"
	buffered, _ := e.JSON([]byte(in), Stats{})
	st := Stats{}
	s, single, _, err := NewJSONStream(io.NopCloser(iotest.OneByteReader(strings.NewReader(in))), e, st, 1<<20, nil, int64(len(in)))
	if err != nil || single {
		t.Fatalf("single=%v err=%v", single, err)
	}
	out, err := io.ReadAll(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(buffered)+"\n" {
		t.Fatalf("got %q\nwant %q", out, string(buffered)+"\n")
	}
	if st["email"] != 2 {
		t.Fatalf("stats %v", st)
	}
}

func TestJSONStreamFirstDocumentInvalid(t *testing.T) {
	e := engine(t, config.Redaction{})
	in := `{"a": jane@example.com is not json`
	st := Stats{}
	_, _, raw, err := NewJSONStream(io.NopCloser(strings.NewReader(in)), e, st, 1<<20, nil, -1)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.HasPrefix(in, string(raw)) || len(raw) == 0 {
		t.Fatalf("raw %q is not a prefix of the input", raw)
	}
	if len(st) != 0 {
		t.Fatalf("stats counted for a failed parse: %v", st)
	}
}

func TestJSONStreamCaps(t *testing.T) {
	e := engine(t, config.Redaction{})
	big := `{"x":"` + strings.Repeat("secret-bob@example.com ", 50) + `"}`
	if _, _, _, err := openStream(t, e, strings.NewReader(big), 200); !errors.Is(err, ErrDocTooLarge) {
		t.Fatalf("first document over cap: %v", err)
	}
	// A later document over the cap ends the stream after the earlier ones.
	in := `{"ok":1}` + "\n" + big + "\n" + `{"after":1}` + "\n"
	s, _, _, err := openStream(t, e, strings.NewReader(in), 200)
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(s)
	if !errors.Is(err, ErrDocTooLarge) || string(out) != "{\"ok\":1}\n" {
		t.Fatalf("out %q err %v", out, err)
	}
	// Small documents never trip the cap, however many arrive per read.
	many := strings.Repeat(`{"a":"x"}`+"\n", 1000)
	s, _, _, err = openStream(t, e, strings.NewReader(many), 64)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := io.ReadAll(s); err != nil || len(out) != len(many) {
		t.Fatalf("len %d err %v", len(out), err)
	}
}

func TestJSONStreamLaterInvalid(t *testing.T) {
	e := engine(t, config.Redaction{})
	s, _, _, err := openStream(t, e, strings.NewReader(`{"ok":1}`+"\n"+`{"bad": jane@example.com}`), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(s)
	if !errors.Is(err, ErrStreamNotJSON) || strings.Contains(string(out), "jane") {
		t.Fatalf("out %q err %v", out, err)
	}
}

// Each document is released as soon as it is complete, before the next
// one arrives.
func TestJSONStreamReleasesEagerly(t *testing.T) {
	e := engine(t, config.Redaction{})
	pr, pw := io.Pipe()
	go pw.Write([]byte(`{"a":"jane@example.com"}` + "\n" + `{"b":`))
	s, single, _, err := NewJSONStream(pr, e, Stats{}, 1<<20, nil, -1)
	if err != nil || single {
		t.Fatalf("single=%v err=%v", single, err)
	}
	buf := make([]byte, 100)
	n, err := s.Read(buf)
	if err != nil || string(buf[:n]) != "{\"a\":\"[REDACTED:EMAIL]\"}\n" {
		t.Fatalf("got %q, %v", buf[:n], err)
	}
	pw.Close()
}

func TestJSONStreamFields(t *testing.T) {
	e := engine(t, config.Redaction{})
	f, _ := NewFields([]string{"result._time"})
	in := `{"result":{"_time":"t1","_raw":"Dana Whitfield"}}` + "\n" + `{"result":{"_time":"t2","_raw":"x"}}`
	s, _, _, err := NewJSONStream(io.NopCloser(strings.NewReader(in)), e, Stats{}, 1<<20, f, -1)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(s)
	want := `{"result":{"_time":"t1","_raw":"[REDACTED:FIELD]"}}` + "\n" + `{"result":{"_time":"t2","_raw":"[REDACTED:FIELD]"}}` + "\n"
	if string(out) != want {
		t.Fatalf("got %q", out)
	}
}

// The stream and the buffered path agree on every valid input.
func FuzzJSONStream(f *testing.F) {
	e := fuzzEngine(f)
	f.Add(`{"a":"jane@example.com"}` + "\n" + `[1,{"secret":"x"}]`)
	f.Add(`"just a string" 12 null`)
	f.Fuzz(func(t *testing.T, in string) {
		buffered, err := e.JSON([]byte(in), Stats{})
		if err != nil || !json.Valid([]byte(strings.SplitN(in, "\n", 2)[0])) {
			return
		}
		for _, knownLen := range []int64{int64(len(in)), -1} {
			s, single, _, err := NewJSONStream(io.NopCloser(strings.NewReader(in)), e, Stats{}, 1<<20, nil, knownLen)
			if err != nil {
				t.Fatalf("stream rejected what JSON accepted: %v", err)
			}
			var got []byte
			if single {
				got = s.Bytes()
			} else if got, err = io.ReadAll(s); err != nil {
				t.Fatalf("stream error %v on %q", err, in)
			} else {
				got = bytes.TrimSuffix(got, []byte("\n"))
			}
			if !bytes.Equal(got, buffered) {
				t.Fatalf("knownLen %d: stream %q != buffered %q for %q", knownLen, got, buffered, in)
			}
		}
	})
}

// With no declared length, the first document is ready without waiting for
// the upstream to send more or close.
func TestJSONStreamUnknownLengthDoesNotPeek(t *testing.T) {
	e := engine(t, config.Redaction{})
	pr, pw := io.Pipe()
	defer pw.Close()
	go pw.Write([]byte(`{"a":"jane@example.com"}` + "\n"))
	done := make(chan error, 1)
	go func() {
		_, single, _, err := NewJSONStream(pr, e, Stats{}, 1<<20, nil, -1)
		if single {
			err = errors.New("single without a known length")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("NewJSONStream blocked waiting for input after the first document")
	}
}

// Batching joins documents that have already arrived, and never waits on
// the upstream for the next one.
func TestJSONStreamBatching(t *testing.T) {
	e := engine(t, config.Redaction{})
	in := strings.Repeat(`{"a":"x"}`+"\n", 100)
	s, _, _, err := openStream(t, e, strings.NewReader(in), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32<<10)
	n, _ := s.Read(buf)
	if docs := strings.Count(string(buf[:n]), "\n"); docs < 50 {
		t.Fatalf("first Read returned %d documents; want them batched", docs)
	}

	pr, pw := io.Pipe()
	defer pw.Close()
	go pw.Write([]byte(`{"a":1}` + "\n" + `{"b":2}` + "\n" + `{"c":`))
	s, _, _, err = NewJSONStream(pr, e, Stats{}, 1<<20, nil, -1)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	go func() { n, _ := s.Read(buf); got <- string(buf[:n]) }()
	select {
	case out := <-got:
		if out != "{\"a\":1}\n{\"b\":2}\n" {
			t.Fatalf("got %q", out)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read waited on a partial document")
	}
}
