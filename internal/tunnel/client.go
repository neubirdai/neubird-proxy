package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/http2"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/metrics"
)

const (
	pingAfter   = 5 * time.Second // PING after this long without traffic
	pingTimeout = 5 * time.Second // drop the tunnel if a PING goes unanswered
	backoffMin  = time.Second
	// Short enough that a tunnel is back within ~15 s of the network
	// returning, even after a long outage.
	backoffMax = 15 * time.Second
	// A tunnel up this long resets the backoff, so a relay restart (GOAWAY)
	// is followed by a reconnect within a second, while a relay that
	// accepts and drops at once still gets backed off.
	stableAfter = 10 * time.Second
	dialTimeout = 15 * time.Second
	// maxHeaderBytes caps one request's header list over a tunnel.
	maxHeaderBytes = 64 << 10
	// With TLS 1.3 the client's handshake completes before the relay has
	// checked the client certificate; a refusal arrives as an alert on the
	// first read. The relay starts HTTP/2 at once, so a tunnel only counts
	// as connected once its first bytes arrive.
	acceptTimeout = 10 * time.Second
	// How often the certificate files are re-read and the expiry metric
	// refreshed, besides on every connect.
	identityRefresh = time.Hour
)

// Client keeps tunnels open to every relay and serves handler over them.
type Client struct {
	cfg     *config.Tunnel
	handler http.Handler
	log     *slog.Logger

	// The identity is re-read from its files on every connect and every
	// identityRefresh, so a renewed Secret takes effect on the next
	// reconnect without a restart. nil until the files first load.
	idMu    sync.Mutex
	id      *Identity
	idError string // last load error, logged once per change
	live    atomic.Int64

	hs *http.Server // carries the graceful-shutdown hook for every tunnel
	h2 *http2.Server

	up       *metrics.Counter
	connects *metrics.Counter
	expiry   *metrics.Counter

	// dial is the TCP dialer; tests replace it.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// proxyFor returns the outbound HTTP proxy for a relay, or nil.
	proxyFor func(*url.URL) (*url.URL, error)

	// enrolled is, per relay, the fingerprint of the key this process has
	// enrolled there (or found known), when a join token is configured. A
	// key reloaded from a new file is enrolled again.
	enrolled map[string]*atomic.Pointer[string]

	wg      sync.WaitGroup
	closing chan struct{} // closed by Shutdown: stop reconnecting
	once    sync.Once
}

// New prepares a client. handler is the proxy itself; requests from a
// tunnel go through it exactly like inbound ones. id may be nil when the
// certificate files don't load yet; the client keeps trying.
func New(cfg *config.Tunnel, id *Identity, handler http.Handler, log *slog.Logger, reg *metrics.Registry) *Client {
	c := &Client{
		cfg: cfg, id: id, handler: handler, log: log,
		// The relay is authenticated, but a header list per stream is
		// still capped well below the 1 MiB default.
		hs: &http.Server{MaxHeaderBytes: maxHeaderBytes},
		h2: &http2.Server{
			ReadIdleTimeout:      pingAfter,
			PingTimeout:          pingTimeout,
			MaxConcurrentStreams: 250,
		},
		up:       reg.Gauge("neubird_proxy_tunnels", "Tunnels currently connected, by relay.", "relay"),
		connects: reg.Counter("neubird_proxy_tunnel_connects_total", "Tunnel connection attempts by relay and result.", "relay", "result"),
		expiry:   reg.Gauge("neubird_proxy_tunnel_cert_expiry_days", "Days until the tunnel certificate expires."),
		dial:     (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		proxyFor: httpproxy.FromEnvironment().ProxyFunc(),
		closing:  make(chan struct{}),
		enrolled: map[string]*atomic.Pointer[string]{},
	}
	for _, r := range cfg.Relays {
		c.enrolled[r] = &atomic.Pointer[string]{}
	}
	// Registers the http2 server with hs, so hs.Shutdown sends GOAWAY on
	// every tunnel and lets in-flight requests finish.
	if err := http2.ConfigureServer(c.hs, c.h2); err != nil {
		panic(err) // only fails on a misconfigured TLSConfig, which hs has none of
	}
	for _, r := range cfg.Relays {
		c.up.Set(0, r)
	}
	return c
}

// Start opens connections_per_relay tunnels to each relay and keeps them
// open until Shutdown (or until ctx ends, which also cancels in-flight
// requests, so pass a context that outlives the shutdown signal).
func (c *Client) Start(ctx context.Context) {
	if id, err := c.identity(); err == nil {
		c.log.Info("tunnel starting", "identity", id.Name(), "relays", c.cfg.Relays,
			"connections_per_relay", c.cfg.ConnectionsPerRelay, "key", id.Fingerprint, "cert_expires", id.Leaf.NotAfter.Format(time.RFC3339),
			"join_token", c.cfg.JoinToken != "")
	}
	c.wg.Add(1)
	go c.refresh(ctx)
	for _, relay := range c.cfg.Relays {
		for i := 0; i < c.cfg.ConnectionsPerRelay; i++ {
			c.wg.Add(1)
			go c.keep(ctx, relay)
		}
	}
}

// Shutdown stops reconnecting, sends GOAWAY on every tunnel so relays send
// no new requests, and waits for in-flight requests until ctx expires.
func (c *Client) Shutdown(ctx context.Context) error {
	c.once.Do(func() { close(c.closing) })
	_ = c.hs.Shutdown(ctx)
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// keep holds one tunnel slot open: connect, serve until the connection
// ends, back off, repeat.
func (c *Client) keep(ctx context.Context, relay string) {
	defer c.wg.Done()
	backoff := backoffMin
	for ctx.Err() == nil && !c.isClosing() {
		start := time.Now()
		conn, err := c.connect(ctx, relay, true)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.log.Warn("tunnel connect failed", "relay", relay, "error", err.Error(), "retry_in", backoff.String())
		} else if c.isClosing() {
			// Connected while shutting down: hs.Shutdown has already sent
			// GOAWAY to the others and wouldn't reach this one.
			conn.Close()
			return
		} else {
			c.up.Add(1, relay)
			c.live.Add(1)
			c.log.Info("tunnel connected", "relay", relay)
			err := c.serve(ctx, conn)
			c.live.Add(-1)
			c.up.Add(-1, relay)
			lived := time.Since(start)
			c.log.Info("tunnel closed", "relay", relay, "lived", lived.Round(time.Second).String(), "reason", closeReason(err))
			if lived > stableAfter {
				backoff = backoffMin
			}
		}
		if c.isClosing() {
			return
		}
		// Equal jitter (half fixed, half random), so a relay restart doesn't
		// get every proxy back at once.
		wait := backoff/2 + rand.N(backoff/2+1)
		select {
		case <-ctx.Done():
			return
		case <-c.closing:
			return
		case <-time.After(wait):
		}
		backoff = min(backoff*2, backoffMax)
	}
}

func (c *Client) isClosing() bool {
	select {
	case <-c.closing:
		return true
	default:
		return false
	}
}

// Connected is the number of tunnels currently up, across relays.
func (c *Client) Connected() int { return int(c.live.Load()) }

// serve runs HTTP/2 with the relay as the client (docs/tunnel-protocol.md)
// and returns the connection's read error, if any, as the close reason.
func (c *Client) serve(ctx context.Context, conn *acceptedConn) error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only plain HTTP crosses the tunnel, whatever a connection's
		// settings. HTTP/2 already keeps upgrades out: the server answers
		// Upgrade and Connection headers itself and resets extended
		// CONNECT. CONNECT and TRACE are refused here.
		if r.Method == http.MethodConnect || r.Method == http.MethodTrace {
			c.log.Warn("tunnel request refused", "method", r.Method, "path", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintln(w, `{"error":"method_not_allowed","reason":"only plain HTTP requests cross the tunnel"}`)
			return
		}
		c.handler.ServeHTTP(w, r.WithContext(WithVia(r.Context())))
	})
	c.h2.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, BaseConfig: c.hs, Handler: handler})
	return conn.readErr()
}

func closeReason(err error) string {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return "closed"
	}
	return err.Error()
}

// identity returns the tunnel identity, re-reading the files first. A file
// that stops loading (mid-rotation, or a bad Secret) keeps the last good
// identity in use; the error is logged once per change.
func (c *Client) identity() (*Identity, error) {
	id, err := Load(c.cfg)
	c.idMu.Lock()
	defer c.idMu.Unlock()
	if err != nil {
		if msg := err.Error(); msg != c.idError {
			c.idError = msg
			if c.id != nil {
				c.log.Warn("tunnel certificate files don't load; keeping the previous certificate", "error", msg)
			} else {
				c.log.Error("tunnel certificate files don't load; no tunnel until they do", "error", msg)
			}
		}
		if c.id == nil {
			return nil, err
		}
		return c.id, nil
	}
	c.idError = ""
	// Identities are replaced, never modified: connects in progress keep
	// the one they started with.
	// A minted certificate is new on every load; only a new key, file
	// certificate or relay CA is worth a log line.
	if c.id != nil && (c.id.Fingerprint != id.Fingerprint || (!id.Minted && !c.id.Leaf.Equal(id.Leaf)) || !c.id.RelayCAs.Equal(id.RelayCAs)) {
		c.log.Info("tunnel key, certificate or relay CA reloaded", "key", id.Fingerprint, "cert_expires", id.Leaf.NotAfter.Format(time.RFC3339))
	}
	c.id = id
	c.expiry.Set(c.id.DaysLeft())
	if c.id.DaysLeft() < 30 {
		c.log.Warn("tunnel certificate expires soon", "days", int(c.id.DaysLeft()))
	}
	return c.id, nil
}

// refresh re-reads the identity periodically, so the expiry metric stays
// current and a renewed certificate is noticed without a reconnect.
func (c *Client) refresh(ctx context.Context) {
	defer c.wg.Done()
	t := time.NewTicker(identityRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closing:
			return
		case <-t.C:
			c.identity()
		}
	}
}

// acceptedConn is a tunnel connection whose first bytes from the relay have
// been read (to learn whether the relay accepted the client certificate);
// Read returns them first.
type acceptedConn struct {
	*tls.Conn
	br *bufio.Reader

	mu  sync.Mutex
	err error
}

func (a *acceptedConn) Read(p []byte) (int, error) {
	n, err := a.br.Read(p)
	if err != nil {
		a.mu.Lock()
		if a.err == nil {
			a.err = err
		}
		a.mu.Unlock()
	}
	return n, err
}

func (a *acceptedConn) readErr() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

// connect dials the relay (through the outbound proxy if one is set), runs
// mutual TLS, checks the negotiated protocol and waits for the relay to
// accept the client certificate. With enroll, a configured join token
// enrolls the key first.
func (c *Client) connect(ctx context.Context, relay string, enroll bool) (*acceptedConn, error) {
	id, err := c.identity()
	if err != nil {
		c.connects.Inc(relay, "identity_error")
		return nil, fmt.Errorf("tunnel certificate: %w", err)
	}
	if done := c.enrolled[relay].Load(); enroll && c.cfg.JoinToken != "" && (done == nil || *done != id.Fingerprint) {
		outcome, err := c.enroll(ctx, relay, id)
		if err != nil {
			c.connects.Inc(relay, "enroll_error")
			return nil, fmt.Errorf("enrollment: %w", err)
		}
		fp := id.Fingerprint
		if c.enrolled[relay].CompareAndSwap(done, &fp) {
			msg := "enrolled with the join token"
			if outcome == "known" {
				msg = "key already enrolled"
			}
			c.log.Info(msg, "relay", relay, "key", id.Fingerprint)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	host, _, _ := net.SplitHostPort(relay)

	raw, err := c.dialRelay(ctx, relay)
	if err != nil {
		c.connects.Inc(relay, "dial_error")
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{
		Certificates: []tls.Certificate{id.Certificate},
		RootCAs:      id.RelayCAs,
		ServerName:   host,
		NextProtos:   []string{ALPN},
		MinVersion:   tls.VersionTLS13,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		c.connects.Inc(relay, "tls_error")
		return nil, fmt.Errorf("tls: %w", err)
	}
	if p := conn.ConnectionState().NegotiatedProtocol; p != ALPN {
		conn.Close()
		c.connects.Inc(relay, "protocol_mismatch")
		return nil, fmt.Errorf("relay negotiated protocol %q, want %q", p, ALPN)
	}
	conn.SetReadDeadline(time.Now().Add(acceptTimeout))
	br := bufio.NewReader(conn)
	if _, err := br.Peek(1); err != nil {
		conn.Close()
		c.connects.Inc(relay, "rejected")
		return nil, fmt.Errorf("relay refused the tunnel (certificate revoked, unrecorded, expired or for another tenant?): %w", err)
	}
	conn.SetReadDeadline(time.Time{})
	c.connects.Inc(relay, "ok")
	return &acceptedConn{Conn: conn, br: br}, nil
}

// enroll presents the join token to one relay over EnrollALPN, with the
// same pinned-CA TLS and certificate as a tunnel. The relay records the
// certificate's key ("enrolled"), or already has it ("known").
func (c *Client) enroll(ctx context.Context, relay string, id *Identity) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	host, _, _ := net.SplitHostPort(relay)
	raw, err := c.dialRelay(ctx, relay)
	if err != nil {
		return "", err
	}
	conn := tls.Client(raw, &tls.Config{
		Certificates: []tls.Certificate{id.Certificate},
		RootCAs:      id.RelayCAs,
		ServerName:   host,
		NextProtos:   []string{EnrollALPN},
		MinVersion:   tls.VersionTLS13,
	})
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		if strings.Contains(err.Error(), "no application protocol") {
			return "", errors.New("the relay doesn't accept join tokens; send NeuBird the key's fingerprint instead")
		}
		return "", fmt.Errorf("tls: %w", err)
	}
	if p := conn.ConnectionState().NegotiatedProtocol; p != EnrollALPN {
		return "", errors.New("the relay doesn't accept join tokens; send NeuBird the key's fingerprint instead")
	}
	conn.SetDeadline(time.Now().Add(acceptTimeout))
	if _, err := io.WriteString(conn, c.cfg.JoinToken+"\n"); err != nil {
		return "", fmt.Errorf("send join token: %w", err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 512)).ReadString('\n')
	line = strings.TrimSpace(line)
	switch {
	case line == "ok enrolled":
		return "enrolled", nil
	case line == "ok known":
		return "known", nil
	case strings.HasPrefix(line, "error "):
		return "", fmt.Errorf("relay refused: %s", strings.TrimPrefix(line, "error "))
	case err != nil:
		who := "this proxy's join token"
		if id.Tenant != "" {
			who = id.Tenant + "/" + id.Proxy
		}
		return "", fmt.Errorf("relay refused the enrollment (is %s in NeuBird's records?): %w", who, err)
	default:
		return "", fmt.Errorf("unexpected answer from the relay: %q", line)
	}
}

// Check connects to one relay, completes the mutual-TLS handshake and
// waits for the relay to accept the certificate, then closes the
// connection. For `neubird-proxy test`. It never spends the join token: a
// diagnostic run with another copy of the key would enroll that copy.
func (c *Client) Check(ctx context.Context, relay string) (tls.ConnectionState, error) {
	conn, err := c.connect(ctx, relay, false)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	return conn.ConnectionState(), nil
}

// dialRelay opens TCP to the relay, through HTTPS_PROXY with CONNECT when
// the environment configures one (NO_PROXY respected).
func (c *Client) dialRelay(ctx context.Context, relay string) (net.Conn, error) {
	px, err := c.proxyFor(&url.URL{Scheme: "https", Host: relay})
	if err != nil {
		return nil, fmt.Errorf("outbound proxy: %w", err)
	}
	if px == nil {
		return c.dial(ctx, "tcp", relay)
	}
	if px.Scheme != "http" {
		return nil, fmt.Errorf("outbound proxy %s: only http:// proxies are supported", px.Redacted())
	}
	addr := px.Host
	if px.Port() == "" {
		addr = net.JoinHostPort(px.Hostname(), "80")
	}
	conn, err := c.dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("outbound proxy %s: %w", px.Redacted(), err)
	}
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
		defer conn.SetDeadline(time.Time{})
	}
	req := "CONNECT " + relay + " HTTP/1.1\r\nHost: " + relay + "\r\n"
	if u := px.User; u != nil {
		pw, _ := u.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)) + "\r\n"
	}
	if _, err := conn.Write([]byte(req + "\r\n")); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("outbound proxy %s: %w", px.Redacted(), err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("outbound proxy %s refused CONNECT: %s", px.Redacted(), resp.Status)
	}
	if br.Buffered() > 0 {
		conn.Close()
		return nil, errors.New("outbound proxy sent data before the TLS handshake")
	}
	return conn, nil
}

type viaKey struct{}

// WithVia marks a request as having arrived through a tunnel, for the
// audit line.
func WithVia(ctx context.Context) context.Context { return context.WithValue(ctx, viaKey{}, "tunnel") }

// Via reports how a request arrived: "tunnel", or "" for inbound.
func Via(ctx context.Context) string {
	v, _ := ctx.Value(viaKey{}).(string)
	return v
}
