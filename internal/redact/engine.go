// Package redact masks PII in response bodies before they leave MetLife.
//
// The rule model follows the OpenTelemetry redaction processor: ordered
// value rules, blocked key patterns that mask a whole value by its JSON key,
// allowed values that exempt known-safe matches, and label or HMAC masking.
// Audit output is counts per rule, never matched values.
package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

type valueRule struct {
	name     string
	label    string
	re       *regexp.Regexp
	anchored *regexp.Regexp // re matching a whole string; set when validate is
	validate func(string) bool
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
			errs = append(errs, fmt.Errorf("redaction.builtins: unknown rule %q (known: %s)", name, strings.Join(builtinOrder, ", ")))
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		label := strings.ToUpper(name)
		if b.value != nil {
			vr := valueRule{name: name, label: label, re: b.value, validate: b.validate}
			if b.validate != nil {
				vr.anchored = regexp.MustCompile(`^(?:` + b.value.String() + `)$`)
			}
			e.rules = append(e.rules, vr)
		}
		if b.key != nil {
			e.keyRules = append(e.keyRules, keyRule{name: name, label: label, re: b.key})
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
		e.rules = append(e.rules, valueRule{name: c.Name, label: strings.ToUpper(c.Name), re: re})
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
	for _, r := range e.rules {
		out = append(out, r.name)
	}
	for _, k := range e.keyRules {
		out = append(out, "key:"+k.name)
	}
	return out
}

type span struct {
	start, end, rule int
}

// String masks every rule match in s. Matches are found against the
// original text, so a mask is never re-matched by a later rule. Overlapping
// matches merge into one mask, labeled by the earliest match (ties go to
// the higher-precedence rule), so no part of either match survives.
func (e *Engine) String(s string, st Stats) string {
	if s == "" || len(e.rules) == 0 {
		return s
	}
	var spans []span
	for i, r := range e.rules {
		for _, loc := range r.re.FindAllStringIndex(s, -1) {
			if loc[0] == loc[1] {
				continue
			}
			m := s[loc[0]:loc[1]]
			if r.validate != nil && !r.validate(m) {
				// The regex is greedy: "4111111111111111 12" fails Luhn as a
				// whole but contains a valid card. Retry shorter candidates.
				spans = e.subMatches(s, loc[0], loc[1], i, spans)
				continue
			}
			if e.isAllowed(m) {
				continue
			}
			spans = append(spans, span{loc[0], loc[1], i})
		}
	}
	if len(spans) == 0 {
		return s
	}
	sort.Slice(spans, func(a, b int) bool {
		if spans[a].start != spans[b].start {
			return spans[a].start < spans[b].start
		}
		return spans[a].rule < spans[b].rule
	})

	var b strings.Builder
	b.Grow(len(s))
	pos := 0
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
		b.WriteString(s[pos:first.start])
		b.WriteString(e.mask(e.rules[first.rule].label, s[first.start:end]))
		pos = end
		i = j
	}
	b.WriteString(s[pos:])
	return b.String()
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
				spans = append(spans, span{a, z, rule})
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

// Text applies value rules to a whole non-JSON body.
func (e *Engine) Text(body []byte, st Stats) []byte {
	return []byte(e.String(string(body), st))
}

// blockedKey returns the key rule that masks the value under key, if any.
func (e *Engine) blockedKey(key string) *keyRule {
	for i := range e.keyRules {
		if e.keyRules[i].re.MatchString(key) {
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
func (e *Engine) mask(label, value string) string {
	if e.hmacKey == nil {
		return "[REDACTED:" + label + "]"
	}
	h := hmac.New(sha256.New, e.hmacKey)
	h.Write([]byte(value))
	return "[REDACTED:" + label + ":" + hex.EncodeToString(h.Sum(nil))[:16] + "]"
}
