// Package redact masks PII in response bodies before they leave MetLife.
//
// The rule model follows the OpenTelemetry redaction processor: ordered
// value rules, blocked key patterns that mask a whole value by its JSON key,
// allowed values that exempt known-safe matches, and label or HMAC masking.
// Audit output is counts per rule, never matched values.
package redact

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

type valueRule struct {
	name      string
	label     string
	needles   []string // prefilter; see pattern
	minDigits int
	scope     scope
	before    int
	after     int
	re        *regexp.Regexp
	find      func(s string, n int) [][]int // replaces re's FindAllStringSubmatchIndex when set
	raw       bool                          // also matched on the undecoded text
	rawRe     *regexp.Regexp                // re for the undecoded text, if not re
	group     int                           // submatch to mask; 0 is the whole match
	anchored  *regexp.Regexp                // re matching a whole string; for validated whole-match rules
	validate  func(string) bool
}

func newValueRule(name string, p pattern) valueRule {
	r := valueRule{name: name, label: strings.ToUpper(name), re: p.re, find: p.find, raw: p.raw, rawRe: p.rawRe, validate: p.validate, needles: p.needles, minDigits: p.minDigits, scope: p.scope, before: p.before, after: p.after}
	re, validate := p.re, p.validate
	if g := re.SubexpIndex("v"); g > 0 {
		r.group = g
	}
	if validate != nil && r.group == 0 {
		r.anchored = regexp.MustCompile(`^(?:` + re.String() + `)$`)
	}
	return r
}

type keyRule struct {
	name  string
	label string
	re    *regexp.Regexp
}

// Engine is immutable after New and safe for concurrent use.
type Engine struct {
	rules    []valueRule
	keyRules []keyRule
	allowed  []*regexp.Regexp
	hmacKey  []byte // nil means label masking
}

// Stats counts matches per rule name for one request.
type Stats map[string]int

func (s Stats) Total() int {
	n := 0
	for _, v := range s {
		n += v
	}
	return n
}

// New compiles a rule set. Any invalid regex or unknown builtin is an error,
// so the proxy refuses to boot rather than run with a partial rule set.
func New(cfg config.Redaction) (*Engine, error) {
	e := &Engine{}
	var errs []error

	names := builtinOrder
	if cfg.Builtins != nil {
		names = *cfg.Builtins
	}
	seen := map[string]bool{}
	for _, name := range names {
		b, ok := builtins[name]
		if !ok {
			known := append(append([]string{}, builtinOrder...), optionalBuiltins...)
			errs = append(errs, fmt.Errorf("redaction.builtins: unknown rule %q (known: %s)", name, strings.Join(known, ", ")))
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		for _, p := range b.values {
			e.rules = append(e.rules, newValueRule(name, p))
		}
		if b.key != nil {
			e.keyRules = append(e.keyRules, keyRule{name: name, label: strings.ToUpper(name), re: b.key})
		}
	}

	for i, p := range cfg.BlockedKeyPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("redaction.blocked_key_patterns[%d]: %w", i, err))
			continue
		}
		e.keyRules = append(e.keyRules, keyRule{name: "blocked_key", label: "KEY", re: re})
	}

	for i, c := range cfg.Custom {
		if seen[c.Name] {
			errs = append(errs, fmt.Errorf("redaction.custom[%d]: name %q collides with another rule", i, c.Name))
			continue
		}
		seen[c.Name] = true
		re, err := regexp.Compile(c.Regex)
		if err != nil {
			errs = append(errs, fmt.Errorf("redaction.custom[%d] (%s): %w", i, c.Name, err))
			continue
		}
		if re.MatchString("") {
			errs = append(errs, fmt.Errorf("redaction.custom[%d] (%s): regex matches the empty string", i, c.Name))
			continue
		}
		e.rules = append(e.rules, newValueRule(c.Name, pattern{re: re}))
	}

	for i, p := range cfg.AllowedValues {
		// An allowed value exempts a match only when it covers the whole match.
		re, err := regexp.Compile(`^(?:` + p + `)$`)
		if err != nil {
			errs = append(errs, fmt.Errorf("redaction.allowed_values[%d]: %w", i, err))
			continue
		}
		e.allowed = append(e.allowed, re)
	}

	if cfg.Mask == config.MaskHMAC {
		if len(cfg.HMACKey) == 0 {
			errs = append(errs, errors.New("redaction: hmac masking needs a key"))
		}
		e.hmacKey = cfg.HMACKey
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return e, nil
}

// RuleNames lists active rules in precedence order, for startup logging.
func (e *Engine) RuleNames() []string {
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, r := range e.rules {
		add(r.name)
	}
	for _, k := range e.keyRules {
		add("key:" + k.name)
	}
	return out
}

// span is one match. int32 fields: a body is far below 2 GiB, and text
// dense with matches holds one span per few bytes.
type span struct {
	start, end, rule int32
}

// String masks every rule match in s.
//
// Matching runs on a normalized view of s (see normalize), so
// jane.doe%40example.com and full-width digits are caught; masks replace the
// corresponding bytes of the original. Matches are found against the
// unmasked text, so a mask is never re-matched by a later rule. Overlapping
// matches merge into one mask, labeled by the earliest match (ties go to the
// higher-precedence rule), so no part of either match survives.
func (e *Engine) String(orig string, st Stats) string {
	if orig == "" || len(e.rules) == 0 {
		return orig
	}
	s, off := normalize(orig)
	nDigits := countDigits(s)
	var lower string
	var clusters [][2]int
	clustersDone := false
	var spans []span
	for i, r := range e.rules {
		if nDigits < r.minDigits {
			continue
		}
		// (?i) also folds the Kelvin sign to k and the long s to s, which
		// an ASCII needle search can't see: with either present, keyword
		// rules run over the whole string.
		folds := hasFoldRunes(s)
		if len(r.needles) > 0 && !folds {
			if lower == "" {
				lower = asciiLower(s)
			}
			if !containsAny(lower, r.needles) {
				continue
			}
		}
		var regions [][2]int
		switch r.scope {
		case scopeDigits:
			if !clustersDone {
				clusters, clustersDone = digitClusters(s), true
			}
			regions = clusters
		case scopeNeedles:
			if folds {
				regions = [][2]int{{0, len(s)}}
			} else {
				regions = needleWindows(s, lower, r.needles, r.before, r.after)
			}
		default:
			regions = [][2]int{{0, len(s)}}
		}
		forEachMatch(r, s, regions, func(loc []int) {
			a, z := loc[2*r.group], loc[2*r.group+1]
			if a < 0 || a == z {
				return
			}
			m := s[a:z]
			if r.validate != nil && !r.validate(m) {
				if r.anchored != nil {
					// The regex is greedy: "4111111111111111 12" fails Luhn
					// as a whole but contains a valid card. Retry shorter
					// candidates.
					spans = e.subMatches(s, a, z, i, spans)
				}
				return
			}
			if e.isAllowed(m) {
				return
			}
			spans = append(spans, span{int32(a), int32(z), int32(i)})
		})
	}
	if off != nil && encodesDelimiters(orig) {
		spans = e.rawMatches(orig, off, spans)
	}
	if len(spans) == 0 {
		return orig
	}
	sort.Slice(spans, func(a, b int) bool {
		if spans[a].start != spans[b].start {
			return spans[a].start < spans[b].start
		}
		return spans[a].rule < spans[b].rule
	})

	var b strings.Builder
	b.Grow(len(orig))
	pos := 0 // in orig
	for i := 0; i < len(spans); {
		first := spans[i]
		end := first.end
		st[e.rules[first.rule].name]++
		j := i + 1
		for ; j < len(spans) && spans[j].start < end; j++ {
			end = max(end, spans[j].end)
			if spans[j].rule != first.rule {
				st[e.rules[spans[j].rule].name]++
			}
		}
		oa, oz := int(first.start), int(end)
		if off != nil {
			oa, oz = int(off[first.start]), int(off[end])
		}
		b.WriteString(orig[pos:oa])
		// HMAC over the normalized value, so encoded and plain forms of the
		// same value get the same token.
		b.WriteString(e.mask(e.rules[first.rule].label, s[first.start:end]))
		pos = oz
		i = j
	}
	b.WriteString(orig[pos:])
	return b.String()
}

// rawMatches runs the raw rules over orig, the text as written, and adds
// their matches as spans of the normalized text that cover them.
func (e *Engine) rawMatches(orig string, off []int32, spans []span) []span {
	var lower string
	folds := hasFoldRunes(orig)
	for i, r := range e.rules {
		if !r.raw {
			continue
		}
		if r.rawRe != nil {
			r.re, r.group = r.rawRe, r.rawRe.SubexpIndex("v")
		}
		if len(r.needles) > 0 && !folds {
			if lower == "" {
				lower = asciiLower(orig)
			}
			if !containsAny(lower, r.needles) {
				continue
			}
		}
		regions := [][2]int{{0, len(orig)}}
		if r.scope == scopeNeedles && !folds {
			regions = needleWindows(orig, lower, r.needles, r.before, r.after)
		}
		forEachMatch(r, orig, regions, func(loc []int) {
			a, z := loc[2*r.group], loc[2*r.group+1]
			// A match with nothing decoded in it is the normalized pass's
			// match again.
			if a < 0 || a == z || !needsNormalize(orig[loc[0]:loc[1]]) {
				return
			}
			if m := orig[a:z]; (r.validate != nil && !r.validate(m)) || e.isAllowed(m) {
				return
			}
			// The normalized span starts with the first byte produced at
			// or before a and ends with the first produced at or after z.
			from := off[sort.Search(len(off), func(k int) bool { return int(off[k]) > a })-1]
			na := sort.Search(len(off), func(k int) bool { return off[k] >= from })
			nz := sort.Search(len(off), func(k int) bool { return int(off[k]) >= z })
			spans = append(spans, span{int32(na), int32(nz), int32(i)})
		})
	}
	return spans
}

// encodesDelimiters reports whether s holds an encoding that decodes to a
// character that can end a value: a percent-escape or entity candidate, or
// full-width punctuation (U+FF01 to U+FF5E are EF BC 81 to EF BD 9E).
func encodesDelimiters(s string) bool {
	if strings.ContainsAny(s, "%&") {
		return true
	}
	for i := strings.IndexByte(s, 0xEF); i >= 0 && i+1 < len(s); {
		if c := s[i+1]; c == 0xBC || c == 0xBD {
			return true
		}
		k := strings.IndexByte(s[i+1:], 0xEF)
		if k < 0 {
			break
		}
		i += 1 + k
	}
	return false
}

// subMatches retries a match that failed validation, over runs of its
// separator-delimited digit or word groups, longest first. Candidates start
// and end on group boundaries, so a card is never carved out of the middle
// of a longer number.
func (e *Engine) subMatches(s string, start, end, rule int, spans []span) []span {
	r := e.rules[rule]
	var groups [][2]int
	for i := start; i < end; {
		if !isWord(s[i]) {
			i++
			continue
		}
		j := i
		for j < end && isWord(s[j]) {
			j++
		}
		groups = append(groups, [2]int{i, j})
		i = j
	}
	for g := 0; g < len(groups); g++ {
		for h := len(groups) - 1; h >= g; h-- {
			if g == 0 && h == len(groups)-1 {
				continue // the whole match, already rejected
			}
			a, z := groups[g][0], groups[h][1]
			m := s[a:z]
			if r.anchored.MatchString(m) && r.validate(m) && !e.isAllowed(m) {
				spans = append(spans, span{int32(a), int32(z), int32(rule)})
				g = h
				break
			}
		}
	}
	return spans
}

func isWord(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

// IsText reports whether b is UTF-8 with no NUL bytes. Anything else
// (compressed, binary, or a legacy 8-bit encoding) cannot be redacted
// reliably and must be refused, not scanned.
func IsText(b []byte) bool {
	return utf8.Valid(b) && bytes.IndexByte(b, 0) < 0
}

// Text applies value rules to a whole non-JSON body.
func (e *Engine) Text(body []byte, st Stats) []byte {
	return []byte(e.String(string(body), st))
}

// blockedKey returns the key rule that masks the value under key, if any.
// The key is matched as written and normalized, so ｐａｓｓｗｏｒｄ or a soft
// hyphen inside "password" is still the password key.
func (e *Engine) blockedKey(key string) *keyRule {
	norm, _ := normalize(key)
	for i := range e.keyRules {
		if e.keyRules[i].re.MatchString(key) || (norm != key && e.keyRules[i].re.MatchString(norm)) {
			return &e.keyRules[i]
		}
	}
	return nil
}

func (e *Engine) isAllowed(m string) bool {
	for _, re := range e.allowed {
		if re.MatchString(m) {
			return true
		}
	}
	return false
}

// mask renders [REDACTED:LABEL], or with HMAC masking
// [REDACTED:LABEL:<16 hex>] so equal values correlate across events.
// BufferFactor is how many times its size redacting a buffered body or a
// stream document may take (measured peaks plus a margin), and SSEFactor
// the same for an SSE event. HMAC masks are longer than labels, so text
// dense with matches grows more with them.
func (e *Engine) BufferFactor() int64 {
	if e.hmacKey != nil {
		return 24
	}
	return 18
}

func (e *Engine) SSEFactor() int64 {
	if e.hmacKey != nil {
		return 27
	}
	return 20
}

func (e *Engine) mask(label, value string) string {
	if e.hmacKey == nil {
		return "[REDACTED:" + label + "]"
	}
	h := hmac.New(sha256.New, e.hmacKey)
	h.Write([]byte(value))
	return "[REDACTED:" + label + ":" + hex.EncodeToString(h.Sum(nil))[:16] + "]"
}

func countDigits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n++
		}
	}
	return n
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// findIn runs r over each region of s and returns submatch indexes in s's
// coordinates. Each region carries one byte of context on each side (when
// there is one), so \b and similar assertions at its edges see the real
// neighbors; matches are kept only if they start inside the region proper.
// matchChunk is how many matches are found per regexp call: all of them
// at once, for text dense with matches, would cost several times its size.
const matchChunk = 1024

// findAll returns up to n matches of r in s (all of them for n < 0), as
// regexp's FindAllStringSubmatchIndex does.
func (r valueRule) findAll(s string, n int) [][]int {
	if r.find != nil {
		return r.find(s, n)
	}
	return r.re.FindAllStringSubmatchIndex(s, n)
}

// forEachMatch calls f with every match of r within the regions of s, a
// chunk at a time. Each search starts one byte before where it may match,
// so \b sees the byte before; a match starting on that byte is skipped.
//
// A full chunk is cut at its last gap: the matches before the last match
// that doesn't touch its predecessor are reported, and the next search
// starts at that match. Nothing can start on the gap byte before it (the
// search would have found it), so restarting there loses no match; at a
// match's last byte it could (a phone's optional "1 " prefix starts on the
// previous number's last digit).
func forEachMatch(r valueRule, s string, regions [][2]int, f func(loc []int)) {
	for _, reg := range regions {
		start, z := reg[0], reg[1]
		cz := min(len(s), z+1)
		var expect []int // the match a resumed search must find first
		for start <= z {
			ca := max(0, start-1)
			n := matchChunk
			locs := r.findAll(s[ca:cz], n)
			for _, loc := range locs {
				for k := range loc {
					if loc[k] >= 0 {
						loc[k] += ca
					}
				}
			}
			if expect != nil && (len(locs) == 0 || locs[0][0] != expect[0] || locs[0][1] != expect[1]) {
				// Restarting mid-text changed what ^ or \b see (a custom
				// rule): finish the region from its start in one search,
				// reporting only what follows the resume point.
				ra := max(0, reg[0]-1)
				locs = r.findAll(s[ra:cz], -1)
				for _, loc := range locs {
					for k := range loc {
						if loc[k] >= 0 {
							loc[k] += ra
						}
					}
					if loc[0] >= start && loc[0] >= reg[0] && loc[1] <= z {
						f(loc)
					}
				}
				break
			}
			cut := len(locs)
			if len(locs) == n {
				cut = 0
				for k := len(locs) - 1; k > 0; k-- {
					if locs[k][0] > locs[k-1][1] {
						cut = k
						break
					}
				}
				if cut == 0 {
					// No gap: every match touches the next. Finish the
					// region in one search.
					locs = r.findAll(s[ca:cz], -1)
					for _, loc := range locs {
						for k := range loc {
							if loc[k] >= 0 {
								loc[k] += ca
							}
						}
					}
					cut = len(locs)
				}
			}
			for _, loc := range locs[:cut] {
				if loc[0] < start || loc[1] > z {
					continue
				}
				f(loc)
			}
			if cut == len(locs) {
				break
			}
			start = locs[cut][0]
			expect = []int{locs[cut][0], locs[cut][1]}
		}
	}
}

// hasFoldRunes reports whether s holds a rune that (?i) folds onto an ASCII
// letter: U+212A KELVIN SIGN (k) or U+017F LATIN SMALL LETTER LONG S (s).
func hasFoldRunes(s string) bool {
	return strings.Contains(s, "\u212a") || strings.Contains(s, "\u017f")
}

func isDigitShape(c byte) bool {
	return c >= '0' && c <= '9' || c == ' ' || c == '(' || c == ')' || c == '.' || c == '+' || c == '-'
}

// digitClusters returns maximal runs of digit-shape characters that hold
// at least 4 digits (the fewest any digit-shape rule needs).
func digitClusters(s string) [][2]int {
	var out [][2]int
	for i := 0; i < len(s); {
		if !isDigitShape(s[i]) {
			i++
			continue
		}
		j, d := i, 0
		for j < len(s) && isDigitShape(s[j]) {
			if s[j] >= '0' && s[j] <= '9' {
				d++
			}
			j++
		}
		if d >= 4 {
			out = append(out, [2]int{i, j})
			if len(out) > maxWindows(s) {
				return [][2]int{{0, len(s)}}
			}
		}
		i = j
	}
	return out
}

// maxWindows is how many windows a string may be split into before the
// rules just run over all of it: the list costs 16 bytes a window, and
// text dense with candidates ("@ @ @ ...") would make it many times the
// text's size.
func maxWindows(s string) int { return len(s)/64 + 16 }

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// needleWindows returns merged windows around every needle occurrence:
// before bytes ahead of it and after bytes past it, widened to whitespace
// (or the string's ends) so no token is cut.
func needleWindows(s, lower string, needles []string, before, after int) [][2]int {
	var ws [][2]int
	for _, n := range needles {
		// Occurrences come in order, so the unwidened bounds only grow.
		// Widening stops where the previous window's did once it reaches
		// the previous unwidened bound: text without whitespace would
		// otherwise be rescanned for every occurrence.
		prevA, prevZ, wa, wz := -1, -1, 0, 0
		for from := 0; ; {
			k := strings.Index(lower[from:], n)
			if k < 0 {
				break
			}
			p := from + k
			// before and after count non-space bytes: the patterns allow
			// any whitespace between a keyword and its value, as in
			// column-aligned dumps ("password        = x").
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
			ua, uz := a, z
			for a > 0 && !isSpace(s[a-1]) {
				if a <= prevA {
					a = wa
					break
				}
				a--
			}
			if z <= wz && prevZ >= 0 && z >= prevZ {
				z = wz
			}
			for z < len(s) && !isSpace(s[z]) {
				z++
			}
			prevA, prevZ, wa, wz = ua, uz, a, z
			ws = append(ws, [2]int{a, z})
			if len(ws) > maxWindows(s) {
				return [][2]int{{0, len(s)}}
			}
			// The next occurrence may sit inside this window, but its value
			// can run past the window's end: it gets a window of its own
			// (the cap above bounds how many).
			from = p + len(n)
		}
	}
	if len(ws) <= 1 {
		return ws
	}
	sort.Slice(ws, func(i, j int) bool { return ws[i][0] < ws[j][0] })
	merged := ws[:1]
	for _, w := range ws[1:] {
		last := &merged[len(merged)-1]
		if w[0] <= last[1] {
			last[1] = max(last[1], w[1])
		} else {
			merged = append(merged, w)
		}
	}
	return merged
}

// asciiLower lowercases ASCII letters only, so byte offsets stay aligned
// with s (strings.ToLower can change the length of non-ASCII text).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
