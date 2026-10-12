package redact

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// normalize decodes the encodings PII hides behind in logs and markup, so
// rules see jane.doe@example.com where the data says jane.doe%40example.com
// or jane.doe&#64;example.com:
//
//   - percent-escapes (%40), once
//   - HTML numeric entities (&#64; &#x40;) and a few named ones (&amp; &commat;)
//   - full-width ASCII (２１９ → 219), and decimal digits of other scripts
//     (٢١٩, 𝟐𝟏𝟗 → 219)
//   - invisible characters (format characters such as zero-width space,
//     soft hyphen, BOM and bidi marks; variation selectors), removed
//
// off maps each byte of the result to the offset in s of the input that
// produced it, with off[len(result)] == len(s), so a match in the result
// can be masked in s. When s needs no normalization, it is returned as is
// with a nil off.
//
// Offsets are int32 (4 bytes per byte of text, not 8): bodies are capped
// far below 2 GiB.
func normalize(s string) (string, []int32) {
	if !needsNormalize(s) {
		return s, nil
	}
	b := make([]byte, 0, len(s))
	off := make([]int32, 0, len(s)+1)
	emit := func(from int, p ...byte) {
		for range p {
			off = append(off, int32(from))
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
			case unicode.Is(unicode.Nd, r):
				emit(i, digitValue(r))
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
	off = append(off, int32(len(s)))
	return string(b), off
}

// needsNormalize reports whether normalize would change s: a percent
// escape or entity candidate, or a rune it rewrites or removes. Other
// non-ASCII text (accented names, CJK) passes as is, without the offset
// table.
func needsNormalize(s string) bool {
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '%' || c == '&':
			return true
		case c >= utf8.RuneSelf:
			r, n := utf8.DecodeRuneInString(s[i:])
			if (r >= 0xFF01 && r <= 0xFF5E) || invisible(r) || unicode.Is(unicode.Nd, r) {
				return true
			}
			i += n
		default:
			i++
		}
	}
	return false
}

// invisible reports a rune that renders as nothing: a format character
// (Cf: soft hyphen, zero-width space and joiners, bidi marks and isolates,
// word joiner, BOM, tag characters), the combining grapheme joiner or a
// variation selector.
func invisible(r rune) bool {
	switch {
	case r == 0x034F, r >= 0x180B && r <= 0x180F, r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return true
	}
	return unicode.Is(unicode.Cf, r)
}

// digitValue returns the ASCII digit for a decimal digit (Nd) of any
// script. Unicode allocates each script's digits as a contiguous run from
// zero to nine, so a range in the Nd table is whole runs of ten.
func digitValue(r rune) byte {
	for _, rg := range unicode.Nd.R16 {
		if lo, hi := rune(rg.Lo), rune(rg.Hi); r >= lo && r <= hi {
			return byte('0' + (r-lo)%10)
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if lo, hi := rune(rg.Lo), rune(rg.Hi); r >= lo && r <= hi {
			return byte('0' + (r-lo)%10)
		}
	}
	return '0'
}

var namedEntities = map[string]rune{
	"amp": '&', "lt": '<', "gt": '>', "quot": '"', "apos": '\'', "nbsp": ' ',
	"commat": '@', "period": '.', "hyphen": '-', "dash": '-', "num": '#', "colon": ':',
}

// entity decodes an HTML entity at the start of s, returning the rune and
// the number of bytes consumed, or 0 if s does not start with one.
func entity(s string) (rune, int) {
	// An entity is at most 11 bytes: looking further for ';' would scan to
	// the end of the text for every '&'.
	end := strings.IndexByte(s[:min(len(s), 11)], ';')
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
