package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

const fieldsConfig = `
client_token_env: NEUBIRD_PROXY_TOKEN
allow_http_upstreams: true
connections:
  - name: servicenow
    upstream: UPSTREAM/servicenow
    response_fields: [result.number, result.priority, result.state, result.assignment_group.display_value]
  - name: maestro
    upstream: UPSTREAM/maestro
    methods: [GET, POST]
    mcp_tools: [get_job_status, list_failed_jobs]
    response_fields: [jsonrpc, id, result.content.type, result.isError, error.code]
`

func TestResponseFieldAllowlist(t *testing.T) {
	f := newFixture(t, fieldsConfig, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("kind") {
		case "text":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "Dana Whitfield")
		case "badjson":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"result": Dana`)
		default:
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"result":[{"number":"INC0010042","priority":"2","description":"Caller Dana Whitfield, 42 Elm St, type 2 diabetes",`+
				`"assignment_group":{"display_value":"Digital Identity L2","link":"https://x/api/now/table/sys_user_group/abc"}}]}`)
		}
	})
	_, body := f.do(t, "GET", "/servicenow/api/now/table/incident", bearer)
	want := `{"result":[{"number":"INC0010042","priority":"2","description":"[REDACTED:FIELD]",` +
		`"assignment_group":{"display_value":"Digital Identity L2","link":"[REDACTED:FIELD]"}}]}`
	if body != want {
		t.Fatalf("got  %s\nwant %s", body, want)
	}
	for _, kind := range []string{"text", "badjson"} {
		resp, body := f.do(t, "GET", "/servicenow/x?kind="+kind, bearer)
		if resp.StatusCode != 502 || !strings.Contains(body, "not_json") || strings.Contains(body, "Dana") {
			t.Errorf("%s: status %d body %s", kind, resp.StatusCode, body)
		}
	}
}

func TestMCPToolAllowlist(t *testing.T) {
	f := newFixture(t, fieldsConfig, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"owner Maria Gonzalez\"}],\"isError\":false}}\n\n")
	})
	post := func(body string) (int, string) {
		req, _ := http.NewRequest("POST", f.proxy.URL+"/maestro/mcp", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := f.proxy.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	code, body := post(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_job_status","arguments":{"job":"X"}}}`)
	if code != 200 || strings.Contains(body, "Maria") || !strings.Contains(body, `"text":"[REDACTED:FIELD]"`) {
		t.Fatalf("allowed tool: %d %s", code, body)
	}
	for _, bad := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"rerun_job"}}`,
		`[{"jsonrpc":"2.0","id":3,"method":"tools/list"},{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_job"}}]`,
		`not json`,
	} {
		if code, body := post(bad); code != 403 {
			t.Errorf("%s: %d %s", bad, code, body)
		}
	}
	if code, _ := post(`{"jsonrpc":"2.0","id":5,"method":"tools/list"}`); code != 200 {
		t.Errorf("tools/list: %d", code)
	}
}

func TestInformationalResponsesDropped(t *testing.T) {
	f := newFixture(t, baseConfig, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "</u/jane@example.com>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, "{}")
	})
	var hints []string
	req, _ := http.NewRequest("GET", f.proxy.URL+"/splunk/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = req.WithContext(withGot1xx(req.Context(), func(code int, h map[string][]string) {
		hints = append(hints, strings.Join(h["Link"], ","))
	}))
	resp, err := f.proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(hints) != 0 {
		t.Fatalf("1xx relayed to client: %v", hints)
	}
}

func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := newCA(t)
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", ca.Raw)
	srvCert, srvKey := newLeaf(t, ca, caKey, "proxy", true)
	writePEM(t, filepath.Join(dir, "tls.crt"), "CERTIFICATE", srvCert.Raw)
	writeKey(t, filepath.Join(dir, "tls.key"), srvKey)

	tcfg, err := ServerTLSConfig(&config.TLS{
		CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key"), ClientCAFile: filepath.Join(dir, "ca.crt"),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	srv.TLS = tcfg
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	client := func(certs ...tls.Certificate) error {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: certs, ServerName: "proxy"}}}
		resp, err := c.Get(srv.URL)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := client(); err == nil {
		t.Fatal("connection without a client certificate succeeded")
	}
	cliCert, cliKey := newLeaf(t, ca, caKey, "neubird", false)
	if err := client(tls.Certificate{Certificate: [][]byte{cliCert.Raw}, PrivateKey: cliKey}); err != nil {
		t.Fatalf("valid client certificate refused: %v", err)
	}
	otherCA, otherKey := newCA(t)
	rogue, rogueKey := newLeaf(t, otherCA, otherKey, "rogue", false)
	if err := client(tls.Certificate{Certificate: [][]byte{rogue.Raw}, PrivateKey: rogueKey}); err == nil {
		t.Fatal("certificate from another CA accepted")
	}
}

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func newLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, server bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{cn}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "EC PRIVATE KEY", der)
}
