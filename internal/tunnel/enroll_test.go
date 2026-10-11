package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

const testJoinToken = "nbjt_Eqsj3YL4mQ0Su35QzRZS4KjcVHYOfWDnFMrVo_NgHZQ"

// enrollRelay is a fake relay that also speaks the enrollment protocol: it
// records the tokens presented and answers with answer; tunnels go to
// tunnels as with fakeRelay. alpns are the protocols it offers.
type enrollRelay struct {
	fakeRelay
	mu     sync.Mutex
	tokens []string
	answer string
}

func newEnrollRelay(t *testing.T, p *pki, answer string, alpns ...string) *enrollRelay {
	t.Helper()
	cert, _, _ := p.leaf(t, "relay", leafOpts{server: true})
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: alpns, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &enrollRelay{fakeRelay: fakeRelay{ln: ln, tunnels: make(chan tunnelConn, 16)}, answer: answer}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.handle(c.(*tls.Conn))
		}
	}()
	return r
}

func (r *enrollRelay) handle(tc *tls.Conn) {
	if tc.Handshake() != nil {
		tc.Close()
		return
	}
	cs := tc.ConnectionState()
	if cs.NegotiatedProtocol == EnrollALPN {
		defer tc.Close()
		line, _ := bufio.NewReader(tc).ReadString('\n')
		r.mu.Lock()
		r.tokens = append(r.tokens, strings.TrimSpace(line))
		r.mu.Unlock()
		io.WriteString(tc, r.answer+"\n")
		return
	}
	tenant, proxy, _ := ParseID(cs.PeerCertificates[0].URIs[0].String())
	cc, err := (&http2.Transport{}).NewClientConn(tc)
	if err != nil {
		return
	}
	r.tunnels <- tunnelConn{cc: cc, tenant: tenant, proxy: proxy}
}

func (r *enrollRelay) presented() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.tokens...)
}

func TestJoinTokenEnrollsBeforeTunnel(t *testing.T) {
	p := newPKI(t)
	relay := newEnrollRelay(t, p, "ok enrolled", ALPN, EnrollALPN)
	cfg := p.proxyConfig(t, relay.ln.Addr().String())
	cfg.JoinToken = testJoinToken
	c, reg := newClient(t, cfg, http.NotFoundHandler())
	c.Start(context.Background())
	first := relay.next(t)
	if resp, _ := get(t, first, "/x"); resp.StatusCode != 404 {
		t.Fatalf("tunnel after enrolling: status %d", resp.StatusCode)
	}
	if got := relay.presented(); len(got) != 1 || got[0] != testJoinToken {
		t.Fatalf("tokens presented: %q", got)
	}
	// Reconnects don't enroll again.
	first.cc.Close()
	relay.next(t)
	if n := len(relay.presented()); n != 1 {
		t.Fatalf("enrolled %d times", n)
	}
	if metricHas(reg, `result="enroll_error"`) {
		t.Fatal("enroll_error recorded")
	}
}

func TestJoinTokenRefused(t *testing.T) {
	p := newPKI(t)
	relay := newEnrollRelay(t, p, "error join token expired at 2026-10-01T00:00:00Z", ALPN, EnrollALPN)
	cfg := p.proxyConfig(t, relay.ln.Addr().String())
	cfg.JoinToken = testJoinToken
	c, reg := newClient(t, cfg, http.NotFoundHandler())
	_, err := c.connect(context.Background(), relay.ln.Addr().String())
	if err == nil || !strings.Contains(err.Error(), "relay refused: join token expired") {
		t.Fatalf("err = %v", err)
	}
	if !metricHas(reg, `result="enroll_error"`) {
		t.Fatal("no enroll_error metric")
	}
	select {
	case <-relay.tunnels:
		t.Fatal("a tunnel opened after the enrollment was refused")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestJoinTokenRelayWithoutEnrollment(t *testing.T) {
	p := newPKI(t)
	relay := newEnrollRelay(t, p, "", ALPN) // an older relay
	cfg := p.proxyConfig(t, relay.ln.Addr().String())
	cfg.JoinToken = testJoinToken
	c, _ := newClient(t, cfg, http.NotFoundHandler())
	_, err := c.connect(context.Background(), relay.ln.Addr().String())
	if err == nil || !strings.Contains(err.Error(), "doesn't accept join tokens") {
		t.Fatalf("err = %v", err)
	}
}

func TestNoJoinTokenNoEnrollment(t *testing.T) {
	p := newPKI(t)
	relay := newEnrollRelay(t, p, "ok enrolled", ALPN, EnrollALPN)
	c, _ := newClient(t, p.proxyConfig(t, relay.ln.Addr().String()), http.NotFoundHandler())
	c.Start(context.Background())
	relay.next(t)
	if n := len(relay.presented()); n != 0 {
		t.Fatalf("enrolled without a join token: %d", n)
	}
}
