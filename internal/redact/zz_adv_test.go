package redact

import (
	"strings"
	"testing"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

func TestZZLeaks(t *testing.T) {
	e := engine(t, config.Redaction{})
	for _, in := range []string{
		"password=abc&#59;defghijSECRET",
		"password=abc&#00000059;defghijSECRET",
		"password=abc&#x000003b;defghijSECRET",
		"&#97;password=hunter2SECRET",
		"&#95;http://user:hunter2SECRET@host",
		"٣password=hunter2SECRET",
		"x‎password=hunter2SECRET",
		"x️password=hunter2SECRET",
		"_‎http://user:hunter2SECRET@host",
		"_٣http://user:hunter2SECRET@host",
		"ｐａｓｓｗｏｒｄ=abc&#59;defSECRET",
		"password&#61;abc&#59;defSECRET",
		"pass%77ord=abc%22defSECRET",
		"http%3A%2F%2Fuser:pa%2FssSECRET@host",
	} {
		out := e.String(in, Stats{})
		t.Logf("leak=%v %q -> %q", strings.Contains(out, "SECRET"), in, out)
	}
}
