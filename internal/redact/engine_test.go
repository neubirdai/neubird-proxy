package redact

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

func engine(t *testing.T, r config.Redaction) *Engine {
	t.Helper()
	if r.Mask == "" {
		r.Mask = config.MaskLabel
	}
	e, err := New(r)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestBuiltins(t *testing.T) {
	e := engine(t, config.Redaction{})
	cases := []struct {
		in, want string
	}{
		{"contact jane.doe@example.com now", "contact [REDACTED:EMAIL] now"},
		{"ssn 219-09-9999.", "ssn [REDACTED:US_SSN]."},
		{"ssn 219 09 9999", "ssn [REDACTED:US_SSN]"},
		{"not an ssn 000-12-3456 or 666-12-3456 or 900-12-3456", "not an ssn 000-12-3456 or 666-12-3456 or 900-12-3456"},
		{"not an ssn 219-00-9999 or 219-09-0000", "not an ssn 219-00-9999 or 219-09-0000"},
		{"card 4111 1111 1111 1111 ok", "card [REDACTED:CREDIT_CARD] ok"},
		{"card 4111-1111-1111-1111", "card [REDACTED:CREDIT_CARD]"},
		{"card 4111111111111111", "card [REDACTED:CREDIT_CARD]"},
		{"luhn fails 4111111111111112", "luhn fails 4111111111111112"},
		{"call (212) 555-0147 or 212-555-0147 or +1 212.555.0147", "call [REDACTED:PHONE_US] or [REDACTED:PHONE_US] or [REDACTED:PHONE_US]"},
		{"host 10.20.30.40 down", "host [REDACTED:IPV4] down"},
		// Things that must survive: epoch ms, ISO dates, sys_ids, versions over 255.
		{"_time=1727700000123 date=2026-09-30 sys_id=6816f79cc0a8016401c5a33be04be441 v=1.2.300.4",
			"_time=1727700000123 date=2026-09-30 sys_id=6816f79cc0a8016401c5a33be04be441 v=1.2.300.4"},
	}
	for _, c := range cases {
		st := Stats{}
		if got := e.String(c.in, st); got != c.want {
			t.Errorf("String(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestCustomAllowedAndOrder(t *testing.T) {
	builtins := []string{"email"}
	e := engine(t, config.Redaction{
		Builtins:      &builtins,
		Custom:        []config.CustomRule{{Name: "member_id", Regex: `\bMET[0-9]{9}\b`}},
		AllowedValues: []string{`(?i)[a-z0-9._-]+@metlife\.com`},
	})
	st := Stats{}
	got := e.String("svc-splunk@metlife.com paged jane@gmail.com about MET123456789", st)
	want := "svc-splunk@metlife.com paged [REDACTED:EMAIL] about [REDACTED:MEMBER_ID]"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if st["email"] != 1 || st["member_id"] != 1 {
		t.Fatalf("stats %v", st)
	}
	// Allowed values must cover the whole match, not a substring of it.
	if got := e.String("x@metlife.com.evil.io", Stats{}); got != "[REDACTED:EMAIL]" {
		t.Fatalf("partial allowed match exempted: %q", got)
	}
}

func TestEmptyBuiltinsMeansNone(t *testing.T) {
	none := []string{}
	e := engine(t, config.Redaction{Builtins: &none})
	if got := e.String("jane@example.com", Stats{}); got != "jane@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestNewRejectsBadRules(t *testing.T) {
	bad := []config.Redaction{
		{Mask: "label", Builtins: &[]string{"nope"}},
		{Mask: "label", Custom: []config.CustomRule{{Name: "x", Regex: `(?=lookahead)`}}},
		{Mask: "label", Custom: []config.CustomRule{{Name: "x", Regex: `a*`}}},
		{Mask: "label", Custom: []config.CustomRule{{Name: "email", Regex: `x`}}},
		{Mask: "label", BlockedKeyPatterns: []string{`(`}},
		{Mask: "label", AllowedValues: []string{`\1`}},
		{Mask: "hmac"},
	}
	for i, r := range bad {
		if _, err := New(r); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestHMACMaskIsStableAndKeyed(t *testing.T) {
	a := engine(t, config.Redaction{Mask: config.MaskHMAC, HMACKey: []byte("k1")})
	b := engine(t, config.Redaction{Mask: config.MaskHMAC, HMACKey: []byte("k2")})
	x1 := a.String("jane@example.com", Stats{})
	x2 := a.String("jane@example.com", Stats{})
	y := b.String("jane@example.com", Stats{})
	if x1 != x2 || x1 == y || !strings.HasPrefix(x1, "[REDACTED:EMAIL:") || len(x1) != len("[REDACTED:EMAIL:]")+16 {
		t.Fatalf("x1=%q x2=%q y=%q", x1, x2, y)
	}
}

func TestJSONPreservesShape(t *testing.T) {
	e := engine(t, config.Redaction{BlockedKeyPatterns: []string{`(?i).*password.*`}})
	in := `{"z":1,"a":{"email":"jane@example.com","n":12345678901234567890,"ok":true,"nil":null},` +
		`"list":["<b>219-09-9999</b>",2.50],"user_password":{"x":"hunter2","y":42,"z":false},"DOB":"1980-01-02","dob_empty":""}`
	st := Stats{}
	out, err := e.JSON([]byte(in), st)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"z":1,"a":{"email":"[REDACTED:EMAIL]","n":12345678901234567890,"ok":true,"nil":null},` +
		`"list":["<b>[REDACTED:US_SSN]</b>",2.50],"user_password":{"x":"[REDACTED:KEY]","y":"[REDACTED:KEY]","z":false},"DOB":"[REDACTED:DATE_OF_BIRTH]","dob_empty":""}`
	if string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
	if !json.Valid(out) {
		t.Fatal("output is not valid JSON")
	}
	if st["blocked_key"] != 2 || st["date_of_birth"] != 1 || st["email"] != 1 || st["us_ssn"] != 1 {
		t.Fatalf("stats %v", st)
	}
}

func TestJSONMultiDocument(t *testing.T) {
	e := engine(t, config.Redaction{})
	in := "{\"result\":{\"_raw\":\"user=a@b.io\"}}\n{\"result\":{\"_raw\":\"ok\"}}\n"
	out, err := e.JSON([]byte(in), Stats{})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"result\":{\"_raw\":\"user=[REDACTED:EMAIL]\"}}\n{\"result\":{\"_raw\":\"ok\"}}"
	if string(out) != want {
		t.Fatalf("got %q", out)
	}
}

func TestJSONInvalidDoesNotCount(t *testing.T) {
	e := engine(t, config.Redaction{})
	st := Stats{}
	if _, err := e.JSON([]byte(`{"a":"x@y.io"} trailing`), st); err == nil {
		t.Fatal("expected error")
	}
	if len(st) != 0 {
		t.Fatalf("stats leaked from failed parse: %v", st)
	}
}

func TestSSE(t *testing.T) {
	e := engine(t, config.Redaction{})
	in := ": ping from ops@corp.io\r\n\r\n" +
		"event: message\nid: 7\ndata: {\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"caller 212-555-0147\"}]}}\n\n" +
		"data: line one a@b.io\ndata: line two\n\n" +
		"data: trailing c@d.io"
	st := Stats{}
	// One byte per read exercises events split across reads, including \r\n.
	r := NewSSEReader(io.NopCloser(iotest.OneByteReader(strings.NewReader(in))), e, st, 1<<20)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	want := ": ping from [REDACTED:EMAIL]\n\n" +
		"event: message\nid: 7\ndata: {\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"caller [REDACTED:PHONE_US]\"}]}}\n\n" +
		"data: line one [REDACTED:EMAIL]\ndata: line two\n\n" +
		"data: trailing [REDACTED:EMAIL]\n"
	if string(out) != want {
		t.Fatalf("got  %q\nwant %q", out, want)
	}
	if st["email"] != 3 || st["phone_us"] != 1 {
		t.Fatalf("stats %v", st)
	}
}

// Each event must be released as soon as it is complete, before the next
// one arrives, or MCP streaming stalls.
func TestSSEReleasesEventsEagerly(t *testing.T) {
	e := engine(t, config.Redaction{})
	pr, pw := io.Pipe()
	r := NewSSEReader(pr, e, Stats{}, 1<<20)
	go pw.Write([]byte("data: first\n\ndata: sec"))
	buf := make([]byte, 100)
	n, err := r.Read(buf)
	if err != nil || string(buf[:n]) != "data: first\n\n" {
		t.Fatalf("got %q, %v", buf[:n], err)
	}
	pw.Close()
}

func TestSSEEventTooLarge(t *testing.T) {
	e := engine(t, config.Redaction{})
	in := "data: ok\n\ndata: " + strings.Repeat("x", 100)
	r := NewSSEReader(io.NopCloser(strings.NewReader(in)), e, Stats{}, 50)
	out, err := io.ReadAll(r)
	if err != ErrEventTooLarge {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(string(out), "xxx") {
		t.Fatalf("oversized event leaked: %q", out)
	}
}

// dataEOFReader returns all its data together with io.EOF in one Read,
// which http bodies are allowed to do.
type dataEOFReader struct{ b []byte }

func (d *dataEOFReader) Read(p []byte) (int, error) {
	n := copy(p, d.b)
	d.b = d.b[n:]
	if len(d.b) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func TestSSEEventTooLargeAtEOF(t *testing.T) {
	e := engine(t, config.Redaction{})
	in := "data: ok\n\ndata: " + strings.Repeat("x", 100)
	r := NewSSEReader(io.NopCloser(&dataEOFReader{[]byte(in)}), e, Stats{}, 50)
	out, err := io.ReadAll(r)
	if err != ErrEventTooLarge {
		t.Fatalf("err = %v", err)
	}
	if string(out) != "data: ok\n\n" {
		t.Fatalf("got %q", out)
	}
}

func TestSSEDataWithEOF(t *testing.T) {
	e := engine(t, config.Redaction{})
	r := NewSSEReader(io.NopCloser(&dataEOFReader{[]byte("data: a@b.io\n\ndata: c@d.io\r")}), e, Stats{}, 1<<20)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if want := "data: [REDACTED:EMAIL]\n\ndata: [REDACTED:EMAIL]\n"; string(out) != want {
		t.Fatalf("got %q", out)
	}
}

func TestSSECompleteEventTooLarge(t *testing.T) {
	e := engine(t, config.Redaction{})
	in := "data: ok\n\ndata: " + strings.Repeat("x", 100) + "\n\ndata: after\n\n"
	r := NewSSEReader(io.NopCloser(&dataEOFReader{[]byte(in)}), e, Stats{}, 50)
	out, err := io.ReadAll(r)
	if err != ErrEventTooLarge || string(out) != "data: ok\n\n" {
		t.Fatalf("out %q err %v", out, err)
	}
}

func TestJSONNumbersAndBlockedScalars(t *testing.T) {
	e := engine(t, config.Redaction{BlockedKeyPatterns: []string{`(?i)^ssn$`}})
	// Numbers are not value-scanned (a Luhn-valid timestamp would be
	// masked and change type); under a blocked key they are masked.
	in := `{"card":4111111111111111,"n":-1.5e3,"ssn":{"a":"","b":null,"c":true,"d":[1,"x"]}}`
	out, err := e.JSON([]byte(in), Stats{})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"card":4111111111111111,"n":-1.5e3,"ssn":{"a":"","b":null,"c":true,"d":["[REDACTED:KEY]","[REDACTED:KEY]"]}}`
	if string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}

// Regression tests for the Sep 30 review findings.

func TestJSONKeysAreRedacted(t *testing.T) {
	e := engine(t, config.Redaction{})
	out, err := e.JSON([]byte(`{"john.doe@example.com":3,"host":"a"}`), Stats{})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"[REDACTED:EMAIL]":3,"host":"a"}` {
		t.Fatalf("got %s", out)
	}
}

func TestNestedJSONInString(t *testing.T) {
	e := engine(t, config.Redaction{BlockedKeyPatterns: []string{`(?i).*password.*`}})
	in := `{"content":[{"type":"text","text":"{\"dob\": \"1980-01-02\", \"password\":\"hunter2\",\"mail\":\"a@b.io\"}"},` +
		`{"type":"text","text":"[not json] a@b.io"}]}`
	st := Stats{}
	out, err := e.JSON([]byte(in), st)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"content":[{"type":"text","text":"{\"dob\":\"[REDACTED:DATE_OF_BIRTH]\",\"password\":\"[REDACTED:KEY]\",\"mail\":\"[REDACTED:EMAIL]\"}"},` +
		`{"type":"text","text":"[not json] [REDACTED:EMAIL]"}]}`
	if string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
	if st["email"] != 2 || st["date_of_birth"] != 1 || st["blocked_key"] != 1 {
		t.Fatalf("stats %v", st)
	}
}

func TestCardNextToOtherDigits(t *testing.T) {
	e := engine(t, config.Redaction{})
	for in, want := range map[string]string{
		"card 4111111111111111 12 25":     "card [REDACTED:CREDIT_CARD] 12 25",
		"exp 12 4111 1111 1111 1111":      "exp 12 [REDACTED:CREDIT_CARD]",
		"id 34111111111111111 not a card": "id 34111111111111111 not a card", // never carved from a longer number
	} {
		if got := e.String(in, Stats{}); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOverlappingMatchesMerge(t *testing.T) {
	e := engine(t, config.Redaction{Custom: []config.CustomRule{{Name: "acct", Regex: `\b1234 5678\b`}}})
	st := Stats{}
	got := e.String("+1 212-555-1234 5678", st)
	if got != "[REDACTED:PHONE_US]" {
		t.Fatalf("got %q", got)
	}
	if st["phone_us"] != 1 || st["acct"] != 1 {
		t.Fatalf("stats %v", st)
	}
}

func TestEpochMillisNotCards(t *testing.T) {
	e := engine(t, config.Redaction{})
	// 1700000000008 passes Luhn; the issuer prefix keeps it out.
	for _, ts := range []string{"1700000000008", "1727700000123", "_time=1700000000008"} {
		if got := e.String(ts, Stats{}); got != ts {
			t.Errorf("timestamp %q masked: %q", ts, got)
		}
	}
	for _, card := range []string{"378282246310005", "6011111111111117", "5555555555554444", "36227206271667", "3530111333300000"} {
		if got := e.String(card, Stats{}); got != "[REDACTED:CREDIT_CARD]" {
			t.Errorf("test card %s not masked: %q", card, got)
		}
	}
}

func TestSSEIDAndEventLinesRedacted(t *testing.T) {
	e := engine(t, config.Redaction{})
	in := "event: alert for 219-09-9999\nid: user-jane@example.com-17\nretry: 3000\ndata: x\n\n"
	out, err := io.ReadAll(NewSSEReader(io.NopCloser(strings.NewReader(in)), e, Stats{}, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	want := "event: alert for [REDACTED:US_SSN]\nid: [REDACTED:EMAIL]-17\nretry: 3000\ndata: x\n\n"
	if string(out) != want {
		t.Fatalf("got %q", out)
	}
}
