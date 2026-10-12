package redact

import (
	"encoding/json"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

func zzPeak(f func()) uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				close(done)
				return
			default:
			}
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak.Load() {
				peak.Store(m.HeapAlloc)
			}
			time.Sleep(5 * time.Microsecond)
		}
	}()
	f()
	close(stop)
	<-done
	runtime.ReadMemStats(&ms)
	if ms.HeapAlloc > peak.Load() {
		peak.Store(ms.HeapAlloc)
	}
	return peak.Load() - base
}

var zzInputs = map[string]string{
	"pwd_pct3":      ";pwd=%%%",
	"rawdense_pct":  ";pwd=%41",
	"normdense_pct": ";pwd=aaa%",
	"url_pct1":      "ab://u:%@",
	"url_pct":       "ab://u:%41@",
	"mix":           ";pwd=%%%ab://u:%@",
	"longval_amp":   "",
}

func TestZZMem(t *testing.T) {
	debug.SetGCPercent(2)
	defer debug.SetGCPercent(100)
	const N = 2 << 20
	for _, hm := range []bool{false, true} {
		r := config.Redaction{}
		if hm {
			r.HMACKey = []byte("0123456789abcdef0123456789abcdef"); r.Mask = config.MaskHMAC
		}
		e := engine(t, r)
		for name, unit := range zzInputs {
			var in string
			if name == "longval_amp" {
				in = "password=" + strings.Repeat("a&amp;", N/6)
			} else {
				in = strings.Repeat(unit, N/len(unit))
			}
			n := len(in)
			p := zzPeak(func() { _ = e.String(in, Stats{}) })
			js, _ := json.Marshal(map[string]string{"k": in})
			arr := make([]string, 0)
			for i := 0; i+256 <= len(in); i += 256 {
				arr = append(arr, in[i:i+256])
			}
			ja, _ := json.Marshal(arr)
			in = ""
			pj := zzPeak(func() { _, _ = e.JSONFields(js, Stats{}, nil) })
			pa := zzPeak(func() { _, _ = e.JSONFields(ja, Stats{}, nil) })
			t.Logf("hmac=%v %-15s String %.1fx  JSON1 %.1fx  JSONarr %.1fx", hm, name, float64(p)/float64(n), float64(pj)/float64(len(js)), float64(pa)/float64(len(ja)))
		}
	}
}
