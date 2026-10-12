package redact

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func oldEntity(s string) (rune, int) {
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

func TestZZEnt(t *testing.T) {
	al := []string{"#", "x", "X", "0", "1", "9", "f", ";", "a", "amp", "commat", "period", "0000", "1114111", "10FFFF"}
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 2000000; i++ {
		var b strings.Builder
		b.WriteByte('&')
		for j := rng.Intn(8); j >= 0; j-- {
			b.WriteString(al[rng.Intn(len(al))])
		}
		s := b.String()
		r1, n1 := oldEntity(s)
		r2, n2 := entity(s)
		if r1 != r2 || n1 != n2 {
			t.Fatalf("%q old %d,%d new %d,%d", s, r1, n1, r2, n2)
		}
	}
}
