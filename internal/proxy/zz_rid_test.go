package proxy

import (
	"io"
	"net/http"
	"testing"
)

func TestZZRID(t *testing.T) {
	f := newFixture(t, lockedConfig, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Request-Id", "upstream")
		w.Header().Add("X-Request-Id", "upstream2")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	})
	for _, c := range []struct {
		path string
		h    map[string]string
	}{
		{"/splunk/services/search/jobs", map[string]string{"Authorization": "Bearer " + token, "X-Request-Id": "abc"}},
		{"/splunk/services/search/jobs", map[string]string{"Authorization": "Bearer bad", "X-Request-Id": "abc"}},
		{"/splunk/services/search/jobs", map[string]string{"X-Request-Id": "abc"}},
		{"/nope/x", map[string]string{"X-Request-Id": "abc"}},
		{"/nope/x", map[string]string{"Authorization": "Bearer " + token, "X-Request-Id": "abc"}},
		{"/splunk/notallowed", map[string]string{"Authorization": "Bearer " + token, "X-Request-Id": "abc"}},
	} {
		resp, _ := f.do(t, "GET", c.path, c.h)
		t.Logf("%s auth=%q -> %d %q", c.path, c.h["Authorization"], resp.StatusCode, resp.Header.Values("X-Request-Id"))
	}
}
