package redact

import (
	"fmt"
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

// allowsKey reports whether the last key of path may leave as it is: it's
// inside an allowed field, or on the way to one (a literal segment of a
// pattern, or a * position). Any other key is masked like a value: a query
// can put data in keys (Splunk chart ... by name).
func (f *Fields) allowsKey(path []string) bool {
	if f.allows(path) {
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
