package redact

import (
	"fmt"
	"regexp"
	"strings"
)

// Fields is a JSON field allowlist. Each pattern is a dot path of object
// keys, where * matches any one key; array elements add no segment, so
// result.*.number covers every element of a result array. A pattern allows
// its path and everything beneath it.
//
// With an allowlist, every string or number leaf outside it is masked as
// [REDACTED:FIELD] whatever it contains. This is the control for free text
// (names, addresses, health conditions) that no pattern can recognize:
// only fields someone reviewed and approved leave in the clear, and
// allowed fields still get every rule.
type Fields struct {
	pats [][]string
}

func NewFields(patterns []string) (*Fields, error) {
	f := &Fields{}
	for i, p := range patterns {
		segs := strings.Split(p, ".")
		for _, s := range segs {
			if s == "" {
				return nil, fmt.Errorf("response_fields[%d]: empty segment in %q", i, p)
			}
		}
		f.pats = append(f.pats, segs)
	}
	if len(f.pats) == 0 {
		return nil, fmt.Errorf("response_fields: at least one pattern is required")
	}
	return f, nil
}

// fieldNameRe is a key that reads as a field name rather than data.
var fieldNameRe = regexp.MustCompile(`^[A-Za-z_@$][A-Za-z0-9_.$@-]{0,63}$`)

// allowsKey reports whether the last key of path may leave as it is: it's
// inside an allowed field, on the way to one (a literal segment of a
// pattern, or a * position), or shaped like a field name. Any other key is
// data the allowlist didn't approve: a query can put free text in keys
// (Splunk chart ... by name), and its value is masked anyway.
func (f *Fields) allowsKey(path []string) bool {
	if f.allows(path) || fieldNameRe.MatchString(path[len(path)-1]) {
		return true
	}
	for _, p := range f.pats {
		if len(p) < len(path) {
			continue
		}
		ok := true
		for i := range path {
			if p[i] != "*" && p[i] != path[i] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func (f *Fields) allows(path []string) bool {
	for _, p := range f.pats {
		if len(p) > len(path) {
			continue
		}
		ok := true
		for i, seg := range p {
			if seg != "*" && seg != path[i] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
