package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMemoryLimit(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	for name, tc := range map[string]struct {
		files []string
		want  int64
	}{
		"v2 limit":    {[]string{write("v2", "536870912\n")}, 512 << 20},
		"v2 no limit": {[]string{write("v2max", "max\n")}, 0},
		"v1 limit":    {[]string{filepath.Join(dir, "missing"), write("v1", "268435456\n")}, 256 << 20},
		"v1 no limit": {[]string{write("v1max", "9223372036854771712\n")}, 0},
		"no cgroup":   {[]string{filepath.Join(dir, "missing")}, 0},
	} {
		if got := memoryLimit(tc.files); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
}
