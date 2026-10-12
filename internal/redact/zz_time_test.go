package redact

import (
	"strings"
	"testing"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

func TestZZTime(t *testing.T) {
	e := engine(t, config.Redaction{})
	units := []string{
		";pwd=%41", ";pwd=&#65;", "&#", "&#1", "&#x", "&a", "&amp", "&ampx", "&#0000000", "pwd=&#1", "pwd=&#11111111",
		"password=&", "password=a&", "password=a&#", "password=&#59", "pwd=a&#59;", "pwd", "pwd:", "pwd=", "pwd ", "pwd=\"",
		"a://", "a://b", "a://b:", "a://b:c", "a://b:%41", "a://b:&", "ab://u:%2F", "%", "%4", "&;", "&&&&&&&&&&&;",
		"secret=", "x&#59;", "\uff10", "\uff1b", "\u0663", "\u200b", "token=\u200b", "key=%41%41%41 ", "key", "keykeykey=",
		"-----BEGIN PRIVATE KEY-----", "api_key=&amp;", "ab://u:&#59;@", "ab://u:&#59;", "pwd=x pwd=y&",
	}
	for _, u := range units {
		tm := func(n int) time.Duration {
			s := strings.Repeat(u, n/len(u))
			best := time.Hour
			for range 2 {
				st := time.Now()
				e.String(s, Stats{})
				best = min(best, time.Since(st))
			}
			return best
		}
		a, b := tm(256<<10), tm(1<<20)
		r := float64(b) / float64(a)
		flag := ""
		if r > 10 {
			flag = "  <<<<"
		}
		t.Logf("%-30q %9s %9s %.1f%s", u, a, b, r, flag)
	}
}
