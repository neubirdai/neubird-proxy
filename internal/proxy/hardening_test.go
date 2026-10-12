package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
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
