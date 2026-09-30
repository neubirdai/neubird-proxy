package proxy

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Splunk export: each result reaches the client, redacted, before the
// upstream sends the next one.
func TestNDJSONStreamsThroughProxy(t *testing.T) {
	next := make(chan struct{})
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"offset":0,"result":{"_raw":"user jane@example.com"}}`+"\n")
		w.(http.Flusher).Flush()
		<-next
		io.WriteString(w, `{"offset":1,"result":{"_raw":"MET123456789"}}`+"\n")
	})
	req, _ := http.NewRequest("GET", f.proxy.URL+"/splunk/services/search/jobs/export", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ContentLength != -1 || resp.Header.Get("Content-Length") != "" {
		t.Fatalf("streamed response has a Content-Length: %d", resp.ContentLength)
	}
	br := bufio.NewReader(resp.Body)
	line := make(chan string, 1)
	go func() { l, _ := br.ReadString('\n'); line <- l }()
	select {
	case got := <-line:
		if got != `{"offset":0,"result":{"_raw":"user [REDACTED:EMAIL]"}}`+"\n" {
			t.Fatalf("first line %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first result not streamed; proxy is buffering the export")
	}
	close(next)
	if rest, _ := io.ReadAll(br); string(rest) != `{"offset":1,"result":{"_raw":"[REDACTED:MEMBER_ID]"}}`+"\n" {
		t.Fatalf("rest %q", rest)
	}
	if logs := f.waitForAudit(t); !strings.Contains(logs, `"redactions":2`) {
		t.Fatalf("audit %s", logs)
	}
}

func TestSingleJSONKeepsContentLength(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{"result":[{"email":"jane@example.com"}]}`))
	resp, body := f.do(t, "GET", "/splunk/x", bearer)
	if want := `{"result":[{"email":"[REDACTED:EMAIL]"}]}`; body != want || resp.ContentLength != int64(len(want)) {
		t.Fatalf("body %q content-length %d", body, resp.ContentLength)
	}
}

func TestNDJSONStreamCutMidway(t *testing.T) {
	for name, c := range map[string]struct{ second, reason string }{
		"document over cap": {`{"x":"` + strings.Repeat("secret-bob@example.com ", 400) + `"}`, "json_doc_too_large"},
		"invalid document":  {`{"x": bob@example.com}`, "json_stream_invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, baseConfig, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"ok":"jane@example.com"}`+"\n"+c.second+"\n")
			})
			req, _ := http.NewRequest("GET", f.proxy.URL+"/splunk/export", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := f.proxy.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, rerr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if rerr == nil {
				t.Fatal("stream ended cleanly; client cannot tell it was cut")
			}
			if string(body) != `{"ok":"[REDACTED:EMAIL]"}`+"\n" || strings.Contains(string(body), "bob") {
				t.Fatalf("body %q", body)
			}
			if logs := f.waitForAudit(t); !strings.Contains(logs, `"blocked":"`+c.reason+`"`) {
				t.Fatalf("audit %s", logs)
			}
			if f.srv.Metrics.Blocked.Value("splunk", c.reason) != 1 {
				t.Fatal("blocked metric")
			}
		})
	}
}

func TestStreamedTrailersDropped(t *testing.T) {
	for _, ct := range []string{"application/json", "text/event-stream"} {
		f := newFixture(t, baseConfig, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Trailer", "X-Owner")
			w.Header().Set("Content-Type", ct)
			if ct == "application/json" {
				io.WriteString(w, `{"a":1}`+"\n")
				w.(http.Flusher).Flush()
				io.WriteString(w, `{"b":2}`+"\n")
			} else {
				io.WriteString(w, "data: x\n\n")
			}
			w.Header().Set("X-Owner", "jane@example.com")
		})
		req, _ := http.NewRequest("GET", f.proxy.URL+"/splunk/x", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := f.proxy.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if v := resp.Trailer.Get("X-Owner"); v != "" {
			t.Errorf("%s: trailer reached NeuBird: %q", ct, v)
		}
	}
}
