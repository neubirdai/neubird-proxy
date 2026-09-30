package redact

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// normalize decodes the encodings PII hides behind in logs and markup, so
// rules see jane.doe@example.com where the data says jane.doe%40example.com
// or jane.doe&#64;example.com:
//
//   - percent-escapes (%40), once
//   - HTML numeric entities (&#64; &#x40;) and a few named ones (&amp; &commat;)
//   - full-width ASCII (２１９ → 219)
//   - invisible format characters (zero-width space, soft hyphen, BOM), removed
//
// off maps each byte of the result to the offset in s of the input that
// produced it, with off[len(result)] == len(s), so a match in the result
// can be masked in s. When s needs no normalization, it is returned as is
// with a nil off.
func normalize(s string) (string, []int) {
	if !needsNormalize(s) {
		return s, nil
	}
	b := make([]byte, 0, len(s))
	off := make([]int, 0, len(s)+1)
	emit := func(from int, p ...byte) {
		for range p {
			off = append(off, from)
		}
		b = append(b, p...)
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			emit(i, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 3
		case c == '&':
			if r, n := entity(s[i:]); n > 0 {
				emit(i, utf8.AppendRune(nil, r)...)
				i += n
				continue
			}
			emit(i, c)
			i++
		case c >= utf8.RuneSelf:
			r, n := utf8.DecodeRuneInString(s[i:])
			switch {
			case r >= 0xFF01 && r <= 0xFF5E: // full-width ! through ~
				emit(i, byte(r-0xFF01+'!'))
			case invisible(r):
			default:
				for k := 0; k < n; k++ {
					emit(i+k, s[i+k])
				}
			}
			i += n
		default:
			emit(i, c)
			i++
		}
	}
	off = append(off, len(s))
	return string(b), off
}

func needsNormalize(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '%' || c == '&' || c >= utf8.RuneSelf {
			return true
		}
	}
	return false
}

func invisible(r rune) bool {
	switch r {
	case 0x00AD, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF:
		return true
	}
	return false
}

var namedEntities = map[string]rune{
	"amp": '&', "lt": '<', "gt": '>', "quot": '"', "apos": '\'', "nbsp": ' ',
	"commat": '@', "period": '.', "hyphen": '-', "dash": '-', "num": '#', "colon": ':',
}

// entity decodes an HTML entity at the start of s, returning the rune and
// the number of bytes consumed, or 0 if s does not start with one.
func entity(s string) (rune, int) {
	end := strings.IndexByte(s, ';')
	if end < 2 || end > 10 {
		return 0, 0
	}
	name := s[1:end]
	if name[0] == '#' {
		var v uint64
		var err error
		if len(name) > 1 && (name[1] == 'x' || name[1] == 'X') {
			v, err = strconv.ParseUint(name[2:], 16, 32)
		} else {
			v, err = strconv.ParseUint(name[1:], 10, 32)
		}
		if err != nil || v == 0 || v > utf8.MaxRune {
			return 0, 0
		}
		return rune(v), end + 1
	}
	if r, ok := namedEntities[name]; ok {
		return r, end + 1
	}
	return 0, 0
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}
