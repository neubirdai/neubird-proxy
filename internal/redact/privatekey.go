package redact

import (
	"regexp"
	"strings"
)

// privateKeyRe is what findPrivateKeys matches: a PEM private key from its
// BEGIN line to the first END line after it, or, with no END line, through
// the base64 that follows. As a regexp, the lazy [\s\S]*? makes every BEGIN
// line without an END scan to the end of the text, so text with many of
// them takes quadratic time; findPrivateKeys looks for the next END line
// once.
var privateKeyRe = regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----|[A-Za-z0-9+/=\s]*)`)

// pemLine returns the end of a "-----<word>[A-Z ]*PRIVATE KEY-----" line
// starting at s[i:] (s[i:] starts with "-----"+word), or -1.
func pemLine(s string, i int, word string) int {
	j := i + 5 + len(word)
	k := j
	for k < len(s) && (s[k] >= 'A' && s[k] <= 'Z' || s[k] == ' ') {
		k++
	}
	if !strings.HasSuffix(s[j:k], "PRIVATE KEY") || !strings.HasPrefix(s[k:], "-----") {
		return -1
	}
	return k + 5
}

// findPrivateKeys returns up to n matches of privateKeyRe in s (all for
// n < 0), in linear time.
func findPrivateKeys(s string, n int) [][]int {
	var out [][]int
	// end is the first END line at or after endFrom (endAt, endZ), or none
	// (endAt < 0): searches only move forward, so it is found once.
	endFrom, endAt, endZ := -1, -1, -1
	nextEnd := func(from int) (int, int) {
		if endFrom >= 0 && from >= endFrom && (endAt < 0 || from <= endAt) {
			return endAt, endZ
		}
		endFrom, endAt, endZ = from, -1, -1
		for p := from; ; {
			k := strings.Index(s[p:], "-----END")
			if k < 0 {
				break
			}
			if z := pemLine(s, p+k, "END"); z >= 0 {
				endAt, endZ = p+k, z
				break
			}
			p += k + 1
		}
		return endAt, endZ
	}
	for pos := 0; n < 0 || len(out) < n; {
		k := strings.Index(s[pos:], "-----BEGIN")
		if k < 0 {
			break
		}
		a := pos + k
		h := pemLine(s, a, "BEGIN")
		if h < 0 {
			pos = a + 1
			continue
		}
		z := h
		if _, ez := nextEnd(h); ez >= 0 {
			z = ez
		} else {
			for z < len(s) && isKeyBody(s[z]) {
				z++
			}
		}
		out = append(out, []int{a, z})
		pos = z
	}
	return out
}

// isKeyBody is [A-Za-z0-9+/=\s] as RE2 reads it (\s is [\t\n\f\r ]).
func isKeyBody(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '=' || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' '
}
