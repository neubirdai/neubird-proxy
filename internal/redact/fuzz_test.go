package redact

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

// Run longer with: go test ./internal/redact -run '^$' -fuzz FuzzX -fuzztime 5m

func fuzzEngine(f *testing.F) *Engine {
	e, err := New(config.Redaction{Mask: config.MaskLabel, BlockedKeyPatterns: []string{`(?i)secret`}})
	if err != nil {
		f.Fatal(err)
	}
	return e
}

// A known SSN surrounded by arbitrary text, separated by spaces, is never
// emitted.
func FuzzStringMasksEmbeddedPII(f *testing.F) {
	e := fuzzEngine(f)
	f.Add("prefix", "suffix")
	f.Add("%40&#64;", "​２")
	f.Add("4111", "1111")
	f.Fuzz(func(t *testing.T, pre, post string) {
		in := pre + " 219-09-9999 " + post
		if out := e.String(in, Stats{}); strings.Contains(out, "219-09-9999") {
			t.Fatalf("SSN survived: %q -> %q", in, out)
		}
	})
}

func FuzzNormalize(f *testing.F) {
	f.Add("a%40b&#64;c​２")
	f.Add("%%4&#x;&#99999999;&amp")
	f.Fuzz(func(t *testing.T, s string) {
		n, off := normalize(s)
		if off == nil {
			if n != s {
				t.Fatal("nil offsets but changed string")
			}
			return
		}
		if len(off) != len(n)+1 || off[len(n)] != len(s) {
			t.Fatalf("offsets %v for %q -> %q", off, s, n)
		}
		for i := 1; i < len(off); i++ {
			if off[i] < off[i-1] || off[i] > len(s) {
				t.Fatalf("offsets not monotonic: %v", off)
			}
		}
	})
}

// Valid JSON in means valid JSON out.
func FuzzJSON(f *testing.F) {
	e := fuzzEngine(f)
	f.Add(`{"a":"jane@example.com","secret":{"x":[1,"y"]},"n":1.5e3}`)
	f.Add(`[{"t":"{\"dob\":\"1980-01-01\"}"}]` + "\n" + `{"k":null}`)
	f.Add(`{"jane@example.com":true}`)
	f.Fuzz(func(t *testing.T, in string) {
		if !json.Valid([]byte(in)) {
			return
		}
		out, err := e.JSON([]byte(in), Stats{})
		if err != nil {
			return // e.g. numbers encoding/json accepts but Token rejects
		}
		if !json.Valid(out) && !validNDJSON(out) {
			t.Fatalf("invalid JSON out: %q -> %q", in, out)
		}
	})
}

func validNDJSON(b []byte) bool {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	for {
		var v any
		if err := dec.Decode(&v); err == io.EOF {
			return true
		} else if err != nil {
			return false
		}
	}
}

// Any input either streams out as UTF-8 text or ends the stream with an
// error; it never panics.
func FuzzSSE(f *testing.F) {
	e := fuzzEngine(f)
	f.Add("data: {\"a\":\"jane@example.com\"}\n\n: c\r\n\r\nid: 1\ndata: x")
	f.Add("\r\r\n\n\x00data")
	f.Fuzz(func(t *testing.T, in string) {
		out, err := io.ReadAll(NewSSEReader(io.NopCloser(strings.NewReader(in)), e, Stats{}, 1<<16))
		if err == nil && !utf8.Valid(out) {
			t.Fatalf("non-UTF-8 output without error: %q", out)
		}
	})
}
