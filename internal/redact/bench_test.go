package redact

import (
	"fmt"
	"strings"
	"testing"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

// splunkExport builds a Splunk-export-shaped NDJSON body of about n bytes
// with some PII in every event.
func splunkExport(n int) []byte {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, `{"preview":false,"offset":%d,"result":{"_time":"2026-09-30T14:02:%02d.000+00:00","host":"app-prd-%d",`+
			`"_raw":"2026-09-30 14:02:11 INFO claim submitted member=MET104938271 email=j.rivera%d@example.com phone=(212) 555-0147 `+
			`client_ip=10.44.8.21 latency_ms=41 build=4.12.1 trace=6816f79cc0a8016401c5a33be04be441","sourcetype":"claims:api"}}`+"\n",
			i, i%60, i%40, i)
	}
	return []byte(b.String())
}

func benchCfg() config.Redaction {
	return config.Redaction{
		Mask:               config.MaskLabel,
		BlockedKeyPatterns: []string{`(?i).*ssn.*`, `(?i).*password.*`},
		Custom:             []config.CustomRule{{Name: "member_id", Regex: `\bMET[0-9]{9}\b`}},
	}
}

func benchEngine(b *testing.B) *Engine {
	e, err := New(benchCfg())
	if err != nil {
		b.Fatal(err)
	}
	return e
}

func BenchmarkJSONSplunkExport(b *testing.B) {
	for _, size := range []int{1 << 20, 20 << 20} {
		body := splunkExport(size)
		b.Run(fmt.Sprintf("%dMB", size>>20), func(b *testing.B) {
			e := benchEngine(b)
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := e.JSON(body, Stats{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTextSplunkRaw(b *testing.B) {
	body := splunkExport(1 << 20)
	e := benchEngine(b)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.Text(body, Stats{})
	}
}

// quietExport is Splunk-export-shaped NDJSON with no PII, the common case
// for operational logs.
func quietExport(n int) []byte {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, `{"preview":false,"offset":%d,"result":{"_time":"2026-09-30T14:02:%02d.000+00:00","host":"app-prd-%d",`+
			`"_raw":"2026-09-30 14:02:11 INFO request completed route=/api/v2/claims/status status=200 latency_ms=41 build=4.12.1 `+
			`pool=claims-worker-7 queue_depth=3 trace=6816f79cc0a8016401c5a33be04be441","sourcetype":"claims:api"}}`+"\n",
			i, i%60, i%40)
	}
	return []byte(b.String())
}

func BenchmarkJSONQuietExport(b *testing.B) {
	body := quietExport(20 << 20)
	e := benchEngine(b)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := e.JSON(body, Stats{}); err != nil {
			b.Fatal(err)
		}
	}
}
