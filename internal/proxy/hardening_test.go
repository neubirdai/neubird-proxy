package proxy

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Keys that differ only in case, or repeat, are read differently by
// different JSON parsers; the tool check refuses them.
func TestMCPToolCheckRefusesAmbiguousKeys(t *testing.T) {
	tools := map[string]bool{"get_job_status": true}
	for _, body := range []string{
		`{"method":"tools/call","params":{"name":"delete_job","Name":"get_job_status"}}`,
		`{"method":"tools/call","Method":"x","params":{"name":"delete_job"}}`,
		`{"Method":"tools/call","params":{"name":"delete_job"}}`,
		`{"method":"tools/call","params":{"name":"get_job_status","name":"delete_job"}}`,
		`{"method":"tools/call","params":{"NAME":"delete_job"}}`,
		`{"method":"tools/call","params":"x"}`,
		`[{"method":"tools/list"},{"method":"tools/call","params":{"name":"get_job_status","Name":"x"}}]`,
		"{\"method\":\"tools/call\",\"params\":{\"name\":\"get_job_status\"},\"param\u017f\":{\"name\":\"delete_job\"}}",
		`{"method":"tools/call","params":{"name":"get_job_status"}}{"method":"tools/call","params":{"name":"delete_job"}}`,
		"{\"method\":\"tools/call\",\"params\":{\"\u212aame\":1}}",
		`{"method":"tools/call","params":{"name":"get_job_status","arguments":` + strings.Repeat("[", 2000) + `]}}`,
	} {
		if checkMCPTools([]byte(body), tools) == "" {
			t.Errorf("allowed: %s", body)
		}
	}
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_job_status","arguments":{"Name":"x","name":"y"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}`,
	} {
		if r := checkMCPTools([]byte(body), tools); r != "" {
			t.Errorf("refused %s: %s", body, r)
		}
	}
}

// One malformed escape must not hide the rest of the request from the deny
// patterns, nor must JSON string escapes.
func TestRequestDenyPatternsLenientDecoding(t *testing.T) {
	f := newFixture(t, lockedConfig, jsonHandler(`{}`))
	post := func(body, ct string) int {
		req, _ := http.NewRequest("POST", f.proxy.URL+"/splunk/services/search/jobs", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", ct)
		resp, err := f.proxy.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, c := range []struct{ body, ct string }{
		{"search=search%20*%20%7C%20delete&x=%zz", "application/x-www-form-urlencoded"},
		{`{"search":"search * | delete"}`, "application/json"},
	} {
		if code := post(c.body, c.ct); code != 403 {
			t.Errorf("%q: %d, want 403", c.body, code)
		}
	}
}

// A buffered text body is read to its end inside modifyResponse, which is
// when the transport fills in trailers; they must still not reach NeuBird.
func TestTrailersDroppedOnBufferedText(t *testing.T) {
	f := newFixture(t, lockedConfig, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-Owner")
		w.Header().Set("Content-Type", "text/plain")
		w.(http.Flusher).Flush() // chunked, so the trailer is sent
		io.WriteString(w, "ok")
		w.Header().Set("X-Owner", "jane@example.com")
	})
	resp, _ := f.do(t, "GET", "/servicenow/api/now/table/incident", map[string]string{"Authorization": basic("x", scopedToken)})
	if resp.Header.Get("Trailer") != "" || len(resp.Trailer) != 0 {
		t.Fatalf("trailer reached NeuBird: header %v, trailer %v", resp.Header, resp.Trailer)
	}
}

func TestSemicolonDotSegmentsRefused(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	for _, p := range []string{"/splunk/a/..;/b", "/splunk/a/%2e%2e;x/b", "/splunk/.;/b"} {
		if resp, _ := f.do(t, "GET", p, bearer); resp.StatusCode != 400 {
			t.Errorf("%s: %d, want 400", p, resp.StatusCode)
		}
	}
}

// Without a token, an unknown connection name is indistinguishable from a
// known one.
func TestUnknownConnectionNeedsToken(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	if resp, _ := f.do(t, "GET", "/nosuch/x", nil); resp.StatusCode != 401 {
		t.Errorf("no token: %d, want 401", resp.StatusCode)
	}
	if resp, _ := f.do(t, "GET", "/nosuch/x", bearer); resp.StatusCode != 404 {
		t.Errorf("token: %d, want 404", resp.StatusCode)
	}
}

func TestDialGuardRefusesMetadataAndSelf(t *testing.T) {
	for _, a := range []string{"168.63.129.16:80", "100.100.100.200:80", "[fd00:ec2::254]:80", "169.254.169.254:80", "127.0.0.1:9090", "[::ffff:127.0.0.1]:9090"} {
		if refuseInternalAddresses("tcp", a, nil) == nil {
			t.Errorf("%s allowed", a)
		}
	}
	for _, ip := range ownAddrs() {
		if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			if refuseInternalAddresses("tcp", "["+ip.String()+"]:9090", nil) == nil {
				t.Errorf("own address %s allowed", ip)
			}
		}
	}
	if err := refuseInternalAddresses("tcp", "10.20.30.40:443", nil); err != nil {
		t.Errorf("private address refused: %v", err)
	}
}

// A stalled streamed JSON body neither holds a buffer slot nor waits
// forever.
func TestStreamedJSONDoesNotHoldSlot(t *testing.T) {
	old := bodyWorkTimeout
	bodyWorkTimeout = 2 * time.Second
	t.Cleanup(func() { bodyWorkTimeout = old })
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	cfg := strings.Replace(baseConfig, "max_body_bytes: 4096", "max_body_bytes: 4096\nmax_concurrent_buffered: 1", 1)
	f := newFixture(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/stall") {
			// The first document, then a second one trickled slowly.
			io.WriteString(w, "{\"a\":1}\n{\"b\":\"")
			w.(http.Flusher).Flush()
			for i := 0; i < 50; i++ {
				select {
				case <-hang:
					return
				case <-r.Context().Done():
					return
				case <-time.After(200 * time.Millisecond):
				}
				io.WriteString(w, "x")
				w.(http.Flusher).Flush()
			}
			select {
			case <-hang:
			case <-r.Context().Done():
			}
			return
		}
		io.WriteString(w, `{"ok":true}`)
	})
	done := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", f.proxy.URL+"/splunk/stall", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := f.proxy.Client().Do(req)
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if resp, body := f.do(t, "GET", "/splunk/other", bearer); resp.StatusCode != 200 || body != `{"ok":true}` {
		t.Fatalf("second request: %d %s", resp.StatusCode, body)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("second request waited %v for the stalled stream's slot", d)
	}
	select {
	case <-done: // cut by the work deadline
	case <-time.After(5 * time.Second):
		t.Fatal("stalled stream was not cut")
	}
}

func TestJSONStringsMultiDocument(t *testing.T) {
	var seen []string
	collect := func(v string) string { seen = append(seen, v); return "" }
	if _, err := jsonStrings([]byte("{\"index\":\"a\"}\n{\"q\":\"\\u0064elete\"}\n"), collect); err != nil || !strings.Contains(strings.Join(seen, "|"), "delete") {
		t.Fatalf("got %q %v", seen, err)
	}
	if _, err := jsonStrings([]byte(strings.Repeat("[", 5000)+`"\u0041"`), collect); err != errTooDeep {
		t.Fatalf("deep body: %v", err)
	}
}

func TestDotSegmentSecondPassLenient(t *testing.T) {
	for _, p := range []string{"/splunk/%2e%2e/%zz", "/x/%2e%2e/y%"} {
		if !hasDotSegment(p) {
			t.Errorf("%s: not caught", p)
		}
	}
	if hasDotSegment("/a+b/%zz/c") {
		t.Error("false positive")
	}
}

// A checked request body stays reserved until the response is done, and
// is released then.
func TestRequestBodyReservedUntilDone(t *testing.T) {
	inUpstream := make(chan struct{})
	finish := make(chan struct{})
	f := newFixture(t, lockedConfig, func(w http.ResponseWriter, r *http.Request) {
		close(inUpstream)
		<-finish
		jsonHandler(`{}`)(w, r)
	})
	f.srv.SetMemoryLimit(64 << 20)
	body := strings.Repeat("a", 1000)
	go func() {
		req, _ := http.NewRequest("POST", f.proxy.URL+"/splunk/services/search/jobs", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		if resp, err := f.proxy.Client().Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	<-inUpstream
	if held := f.srv.reqMem.inUse(); held != int64(len(body)) {
		t.Errorf("held %d while the request is upstream, want %d", held, len(body))
	}
	close(finish)
	deadline := time.Now().Add(3 * time.Second)
	for f.srv.reqMem.inUse() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := f.srv.reqMem.inUse(); n != 0 {
		t.Errorf("not released: %d still held", n)
	}
}

func (b *memBudget) inUse() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total - b.free
}

// Deeply nested JSON is not recursed into: the proxy keeps running and the
// response is handled as text (or refused under a field allowlist).
func TestDeepJSONResponse(t *testing.T) {
	deep := strings.Repeat("[", 200000) + `"jane@example.com"`
	f := newFixture(t, strings.Replace(baseConfig, "max_body_bytes: 4096", "max_body_bytes: 1048576", 1), jsonHandler(deep))
	resp, body := f.do(t, "GET", "/splunk/x", bearer)
	if resp.StatusCode == 200 && strings.Contains(body, "jane@") {
		t.Fatalf("unredacted: %d", resp.StatusCode)
	}
}

// A busy event stream whose reads never end on an event boundary isn't
// cut: the deadline covers one event at a time.
func TestBusySSEStreamNotCut(t *testing.T) {
	old := bodyWorkTimeout
	bodyWorkTimeout = 300 * time.Millisecond
	t.Cleanup(func() { bodyWorkTimeout = old })
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: x")
		for i := 0; i < 60; i++ {
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
			io.WriteString(w, "\n\ndata: x")
		}
		io.WriteString(w, "\n\n")
	})
	_, body := f.do(t, "GET", "/splunk/stream", bearer)
	if n := strings.Count(body, "data: x"); n != 61 {
		t.Fatalf("%d events, want 61 (stream cut?)", n)
	}
}

// A caller that stops reading doesn't keep its response in memory for
// longer than the write deadline.
func TestStalledReaderIsCut(t *testing.T) {
	old := bodyWorkTimeout
	bodyWorkTimeout = 300 * time.Millisecond
	t.Cleanup(func() { bodyWorkTimeout = old })
	f := newFixture(t, strings.Replace(baseConfig, "max_body_bytes: 4096", "max_body_bytes: 33554432", 1), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, strings.Repeat("a", 8<<20)) // well past socket buffers
	})
	conn, err := net.Dial("tcp", strings.TrimPrefix(f.proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /splunk/big HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "+token+"\r\n\r\n")
	// Never read. The handler must finish (its audit line is written) soon
	// after the deadline, not wait for the reader.
	deadline := time.Now().Add(20 * time.Second) // redacting under -race is slow
	for !strings.Contains(f.logs.String(), `"path":"/big"`) {
		if time.Now().After(deadline) {
			t.Fatalf("handler still blocked on a reader that stopped; logs: %.600s", f.logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Over HTTP/2 (as on the tunnel), an event stream idling between events
// longer than the write deadline isn't reset.
func TestIdleSSEOverHTTP2(t *testing.T) {
	old := bodyWorkTimeout
	bodyWorkTimeout = 300 * time.Millisecond
	t.Cleanup(func() { bodyWorkTimeout = old })
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(time.Second)
		io.WriteString(w, "data: two\n\n")
	})
	h2 := httptest.NewUnstartedServer(f.srv)
	h2.EnableHTTP2 = true
	h2.StartTLS()
	defer h2.Close()
	req, _ := http.NewRequest("GET", h2.URL+"/splunk/stream", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h2.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto %s", resp.Proto)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil || !strings.Contains(string(b), "data: two") {
		t.Fatalf("stream cut: %v %q", err, b)
	}
}

// A passthrough upgrade hijacks the connection; the deferred flush must not
// touch the writer afterwards (it would panic in net/http).
func TestUpgradeThenNoFlush(t *testing.T) {
	cfg := strings.Replace(baseConfig, "    passthrough: true", "    passthrough: true\n    request_headers: [Upgrade, Connection]", 1)
	f := newFixture(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		c, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Request-Id: upstream\r\n\r\nhello")
		rw.Flush()
	})
	errLog := &syncBuffer{}
	srv := httptest.NewUnstartedServer(f.srv)
	srv.Config.ErrorLog = log.New(errLog, "", 0)
	srv.Start()
	defer srv.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "GET /elastic/ws HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "+token+"\r\nX-Request-Id: abc-123\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ := io.ReadAll(conn)
	conn.Close()
	if !strings.Contains(string(b), "101") || !strings.Contains(string(b), "hello") {
		t.Fatalf("upgrade: %q", b)
	}
	// The proxy's request id, once, on the 101 too.
	if !strings.Contains(string(b), "X-Request-Id: abc-123\r\n") || strings.Contains(string(b), "upstream") {
		t.Fatalf("upgrade request id: %q", b)
	}
	// The handler returns once the upgraded connection ends.
	f.waitForAudit(t)
	time.Sleep(100 * time.Millisecond)
	if strings.Contains(errLog.String(), "panic") {
		t.Fatalf("panic: %s", errLog.String())
	}
}

func TestJSONUnescapeLexical(t *testing.T) {
	for in, want := range map[string]string{
		`{"n":NaN,"s":"x | delete"}`: `{"n":NaN,"s":"x | delete"}`,
		`😀 \"q\" \\ \/ \n`:           "\U0001F600 \"q\" \\ / \n",
		`\u12 \x \`:                  `\u12 \x \`,
	} {
		if got := jsonUnescapeLexical([]byte(in)); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}

// Without a token, a 401 says nothing about whether the name exists.
func TestUnauthorizedLooksTheSame(t *testing.T) {
	f := newFixture(t, baseConfig, jsonHandler(`{}`))
	for _, p := range []string{"/splunk/x", "/servicenow/x", "/nosuch/x"} {
		resp, body := f.do(t, "GET", p, nil)
		if resp.StatusCode != 401 || resp.Header.Get("X-Request-Id") != "" || resp.Header.Get("WWW-Authenticate") != "" {
			t.Errorf("%s: %d %v %s", p, resp.StatusCode, resp.Header, body)
		}
	}
}

func TestDenyPatternsSurviveNonStandardJSON(t *testing.T) {
	f := newFixture(t, lockedConfig, jsonHandler(`{}`))
	req, _ := http.NewRequest("POST", f.proxy.URL+"/splunk/services/search/jobs", strings.NewReader(`{"n":NaN,"search":"x \u007c delete"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("%d, want 403", resp.StatusCode)
	}
}

func TestMCPCheckUTF8AndLongNames(t *testing.T) {
	tools := map[string]bool{"ok": true}
	if r := checkMCPTools([]byte("{\"method\":\"tools/call\",\"params\":{\"name\":\"\x80\x80\"}}"), tools); !strings.Contains(r, "not UTF-8") {
		t.Fatalf("invalid UTF-8: %q", r)
	}
	r := checkMCPTools([]byte(`{"method":"tools/call","params":{"name":"`+strings.Repeat("x", 10000)+`"}}`), tools)
	if len(r) > 200 {
		t.Fatalf("reason %d bytes", len(r))
	}
}

// An SSE event near the size cap is delivered: the cap leaves room for the
// event's reservation at the SSE factor.
func TestLargeSSEEventFitsBudget(t *testing.T) {
	old := bodyWorkTimeout
	// Stuck means waiting out this deadline; the check below allows for a
	// slow runner redacting 3 MiB under -race.
	bodyWorkTimeout = 20 * time.Second
	t.Cleanup(func() { bodyWorkTimeout = old })
	ev := "data: " + strings.Repeat("a", 3<<20) + "\n\n"
	f := newFixture(t, strings.Replace(baseConfig, "max_body_bytes: 4096", "max_body_bytes: 8388608", 1), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, ev)
	})
	// A budget whose buffered cap (total/BufferFactor) would admit the
	// event, but whose SSE reservation (len x SSEFactor) wouldn't fit.
	limit := int64(len(ev)) * (f.srv.engine.BufferFactor() + f.srv.engine.SSEFactor()) / 2 * 4 / 3
	f.srv.SetMemoryLimit(limit)
	start := time.Now()
	resp, body := f.do(t, "GET", "/splunk/stream", bearer)
	if time.Since(start) > 15*time.Second {
		t.Fatalf("event waited %v for memory it can't get", time.Since(start))
	}
	// Delivered, or refused at once as too large: never stuck.
	if resp.StatusCode == 200 && !strings.Contains(body, "data: aaa") && len(body) > 0 {
		t.Fatalf("%d: %.100q", resp.StatusCode, body)
	}
}

// Request trailers are headers too: with deny patterns set the body is read
// whole, which fills them in, and none may reach the upstream.
func TestRequestTrailersNotForwarded(t *testing.T) {
	got := make(chan http.Header, 1)
	f := newFixture(t, lockedConfig, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		got <- r.Trailer
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	})
	req, _ := http.NewRequest("POST", f.proxy.URL+"/splunk/services/search/jobs", io.MultiReader(strings.NewReader("search=index%3Dmain")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Trailer = http.Header{"Cookie": {"session=evil"}, "Authorization": {"Bearer smuggled"}}
	resp, err := f.proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if tr := <-got; len(tr) != 0 {
		t.Fatalf("trailers forwarded: %v", tr)
	}
}

// ReverseProxy clears the response header after relaying a 1xx; the
// request id must still be on the final response.
func TestRequestIDAfterEarlyHints(t *testing.T) {
	f := newFixture(t, lockedConfig, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "</a.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		w.Header().Set("X-Request-Id", "upstream")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	})
	resp, _ := f.do(t, "GET", "/splunk/services/search/jobs", map[string]string{"Authorization": "Bearer " + token, "X-Request-Id": "abc-123"})
	if v := resp.Header.Values("X-Request-Id"); len(v) != 1 || v[0] != "abc-123" {
		t.Fatalf("X-Request-Id = %q", v)
	}
	if resp.Header.Get("Link") != "" {
		t.Fatal("1xx header leaked")
	}
}
