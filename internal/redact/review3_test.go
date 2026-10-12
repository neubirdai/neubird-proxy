package redact

import (
	"io"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

// linear fails if f on four times the input takes more than about eight
// times as long (quadratic work takes sixteen). Ratios, not durations, so
// it holds under -race and on slow machines.
func linear(t *testing.T, what string, f func(n int)) {
	t.Helper()
	timeOf := func(n int) time.Duration {
		best := time.Duration(1 << 62)
		for range 3 {
			start := time.Now()
			f(n)
			best = min(best, time.Since(start))
		}
		return best
	}
	small, large := timeOf(128<<10), timeOf(512<<10)
	if large > 8*small+50*time.Millisecond {
		t.Fatalf("%s: 128 KiB %s, 512 KiB %s: not linear", what, small, large)
	}
}

// Many BEGIN lines without an END cost linear time, not one scan to the
// end of the text each.
func TestPrivateKeyHeadersLinear(t *testing.T) {
	e := engine(t, config.Redaction{})
	linear(t, "BEGIN lines", func(n int) {
		out := e.String(strings.Repeat("-----BEGIN PRIVATE KEY-----", n/27), Stats{})
		if strings.Contains(out, "BEGIN") {
			t.Fatal("headers not masked")
		}
	})
}

// findPrivateKeys matches exactly what the regexp it replaces matches.
func TestFindPrivateKeysMatchesRegexp(t *testing.T) {
	parts := []string{"-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----END PRIVATE KEY-----",
		"-----END RSA PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----", "-----END", "-----BEGIN", "MIIEvQ+/=", "\n", " ", "x", "-", "é"}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for j := rng.Intn(12); j >= 0; j-- {
			b.WriteString(parts[rng.Intn(len(parts))])
		}
		s := b.String()
		for _, n := range []int{-1, 1, 2} {
			want := privateKeyRe.FindAllStringSubmatchIndex(s, n)
			got := findPrivateKeys(s, n)
			if len(want) == 0 && len(got) == 0 {
				continue
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%q n=%d: got %v, want %v", s, n, got, want)
			}
		}
	}
}

func FuzzFindPrivateKeys(f *testing.F) {
	f.Add("-----BEGIN PRIVATE KEY-----abc\n-----END PRIVATE KEY----- -----BEGIN RSA PRIVATE KEY-----x")
	f.Fuzz(func(t *testing.T, s string) {
		want := privateKeyRe.FindAllStringSubmatchIndex(s, -1)
		got := findPrivateKeys(s, -1)
		if (len(want) != 0 || len(got) != 0) && !reflect.DeepEqual(got, want) {
			t.Fatalf("%q: got %v, want %v", s, got, want)
		}
	})
}

// Needle windows in text without whitespace are found in linear time.
func TestNeedleWindowsLinear(t *testing.T) {
	e := engine(t, config.Redaction{})
	for _, unit := range []string{"a@" + strings.Repeat("b", 98), "token=" + strings.Repeat("b", 94)} {
		linear(t, unit[:6], func(n int) { e.String(strings.Repeat(unit, n/100), Stats{}) })
	}
}

// needleWindows widens exactly as scanning each window to whitespace does.
func TestNeedleWindowsMatchesNaive(t *testing.T) {
	naive := func(s, lower string, needles []string, before, after int) [][2]int {
		var ws [][2]int
		for _, n := range needles {
			for from := 0; ; {
				k := strings.Index(lower[from:], n)
				if k < 0 {
					break
				}
				p := from + k
				a, z := p, p+len(n)
				for c := 0; a > 0 && c < before; a-- {
					if !isSpace(s[a-1]) {
						c++
					}
				}
				for c := 0; z < len(s) && c < after; z++ {
					if !isSpace(s[z]) {
						c++
					}
				}
				for a > 0 && !isSpace(s[a-1]) {
					a--
				}
				for z < len(s) && !isSpace(s[z]) {
					z++
				}
				ws = append(ws, [2]int{a, z})
				from = p + len(n)
			}
		}
		return ws
	}
	merge := func(ws [][2]int) [][2]int {
		if len(ws) <= 1 {
			return ws
		}
		// The same merge as needleWindows.
		for i := 1; i < len(ws); i++ {
			for j := i; j > 0 && ws[j][0] < ws[j-1][0]; j-- {
				ws[j], ws[j-1] = ws[j-1], ws[j]
			}
		}
		m := ws[:1]
		for _, w := range ws[1:] {
			if l := &m[len(m)-1]; w[0] <= l[1] {
				l[1] = max(l[1], w[1])
			} else {
				m = append(m, w)
			}
		}
		return m
	}
	rng := rand.New(rand.NewSource(2))
	alphabet := "ab tok=\n"
	for i := 0; i < 20000; i++ {
		b := make([]byte, rng.Intn(80))
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		s := string(b)
		before, after := rng.Intn(5), rng.Intn(5)
		needles := []string{"tok", "a"}
		got := needleWindows(s, s, needles, before, after)
		raw := naive(s, s, needles, before, after)
		if len(raw) > maxWindows(s) {
			continue // over the cap, the whole string
		}
		want := merge(raw)
		if len(got) != 0 || len(want) != 0 {
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%q b=%d a=%d: got %v, want %v", s, before, after, got, want)
			}
		}
	}
}

// A percent-encoded character in a password must not end the match early.
func TestEncodedSecretsMaskedWhole(t *testing.T) {
	e := engine(t, config.Redaction{})
	for _, c := range []struct{ in, leak string }{
		{"dsn=postgres://admin:p%40ssw0rdXYZ@db:5432/app", "ssw0rdXYZ"},
		{"dsn=postgres://admin:pa%2Fssw0rd@10.0.0.5:5432/app", "ssw0rd"},
		{"amqp://svc:Zk9%2FqP%3Fw%40Lm@rabbit/", "Lm"},
		{"GET /login?user=bob&password=abc%26defSECRET&x=1", "defSECRET"},
		{"GET /login?user=bob&password=abc%20defSECRET&x=1", "defSECRET"},
		{"GET /login?user=bob&password=abc%3BdefSECRET&x=1", "defSECRET"},
	} {
		if out := e.String(c.in, Stats{}); strings.Contains(out, c.leak) {
			t.Errorf("%s -> %s", c.in, out)
		}
	}
}

// A leading BOM doesn't keep JSON or SSE from their key rules.
func TestLeadingBOM(t *testing.T) {
	e := engine(t, config.Redaction{})
	doc := `{"mobile_phone":"2125550147","u_dob":"1980-01-02","tax_id":"219099999"}`
	leaks := []string{"2125550147", "1980-01-02", "219099999"}
	check := func(what, out string) {
		t.Helper()
		for _, l := range leaks {
			if strings.Contains(out, l) {
				t.Errorf("%s: %s", what, out)
			}
		}
	}
	out, err := e.JSONFields([]byte("\xef\xbb\xbf"+doc), Stats{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	check("buffered", string(out))

	s, _, _, err := NewJSONStream(io.NopCloser(strings.NewReader("\xef\xbb\xbf"+doc+"\n"+doc)), e, Stats{}, 1<<20, nil, -1)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(s)
	check("stream", string(b))

	// One byte at a time, so the BOM arrives in pieces.
	r := NewSSEReader(io.NopCloser(iotestOneByte(strings.NewReader("\xef\xbb\xbfdata: "+doc+"\n\n"))), e, Stats{}, 1<<20)
	b, err = io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	check("sse", string(b))
	if !strings.HasPrefix(string(b), "data: ") {
		t.Errorf("sse: %q", b)
	}
}

// Invisible characters and other scripts' digits don't hide PII.
func TestInvisiblesAndDigits(t *testing.T) {
	e := engine(t, config.Redaction{})
	for _, in := range []string{
		"ssn 219-09‎-9999", "ssn 219-09⁦-9999", "ssn 219-09͏-9999",
		"card 4111‏1111 1111 1111",
		"jane.doe‎@example.com", "jane.doe@exa‎mple.com",
		"ssn \U0001D7D0\U0001D7CF\U0001D7D7-\U0001D7CE\U0001D7D7-\U0001D7D7\U0001D7D7\U0001D7D7\U0001D7D7",
		"ssn ٢١٩-٠٩-٩٩٩٩",
	} {
		if out := e.String(in, Stats{}); out == in {
			t.Errorf("unchanged: %q", in)
		}
	}
}

// Key rules see the key normalized.
func TestNormalizedKeys(t *testing.T) {
	e := engine(t, config.Redaction{})
	for _, doc := range []string{`{"ｐａｓｓｗｏｒｄ":"Hunter2xyz"}`, "{\"pass­word\":\"Hunter2xyz\"}"} {
		out, err := e.JSONFields([]byte(doc), Stats{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "Hunter2xyz") {
			t.Errorf("%s -> %s", doc, out)
		}
	}
}

// Entities inside a secret don't end it.
func TestEntityEncodedSecretsMaskedWhole(t *testing.T) {
	e := engine(t, config.Redaction{})
	for _, in := range []string{
		`<user password="Tr0ub&amp;dor3XYZ"/>`,
		"password=abcd&#59;efghSECRET",
		"password=abcd&#34;efghSECRET",
		"password=abcd&lt;efghSECRET",
		"password=abcd&#32;efghSECRET",
	} {
		if out := e.String(in, Stats{}); strings.Contains(out, "efgh") || strings.Contains(out, "dor3XYZ") {
			t.Errorf("%s -> %s", in, out)
		}
	}
}

// '&' without ';' is linear, in text and in JSON keys.
func TestAmpersandsLinear(t *testing.T) {
	e := engine(t, config.Redaction{})
	linear(t, "text", func(n int) { e.String(strings.Repeat("&", n), Stats{}) })
	linear(t, "key", func(n int) {
		if _, err := e.JSONFields([]byte(`{"`+strings.Repeat("&", n)+`":1}`), Stats{}, nil); err != nil {
			t.Fatal(err)
		}
	})
}

// Normalization can glue a keyword to the character before it (a digit of
// another script, an entity for a letter, an invisible character between
// two letters), so the normalized pass misses it; the pass over the text
// as written must still run and keep its match.
func TestKeywordBoundaryAfterNormalization(t *testing.T) {
	e := engine(t, config.Redaction{})
	for _, in := range []string{
		"٣password=hunter2", "x‎password=hunter2", "x️password=hunter2",
		"_‎http://user:hunter2@host", "_٣http://user:hunter2@host",
		"&#97;password=hunter2", "&#95;http://user:hunter2@host",
		"password=abc&#00000059;defghij", "password=abc&#x000003b;defghij",
	} {
		if out := e.String(in, Stats{}); strings.Contains(out, "hunter2") || strings.Contains(out, "defghij") {
			t.Errorf("%q -> %q", in, out)
		}
	}
}

// Matches found a chunk at a time, through touching matches, are the
// matches of one search over the whole text.
func TestDenseTouchingMatchesChunked(t *testing.T) {
	e := engine(t, config.Redaction{})
	for _, unit := range []string{";pwd=%%%", ";pwd=aaa", "1 212-555-0147", "ab://u:p@"} {
		s := strings.Repeat(unit, 5000)
		for _, r := range e.rules {
			if r.find != nil {
				continue
			}
			want := r.re.FindAllStringSubmatchIndex(s, -1)
			var got [][]int
			forEachMatch(r, s, [][2]int{{0, len(s)}}, func(loc []int) { got = append(got, append([]int(nil), loc...)) })
			if len(want) == 0 && len(got) == 0 {
				continue
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s on %q: %d matches, want %d", r.name, unit, len(got), len(want))
			}
		}
	}
}
