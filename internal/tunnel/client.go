package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/http2"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/metrics"
)

const (
	pingAfter   = 15 * time.Second // PING after this long without traffic
	pingTimeout = 10 * time.Second // drop the tunnel if a PING goes unanswered
	backoffMin  = time.Second
	backoffMax  = 60 * time.Second
	stableAfter = 60 * time.Second // a tunnel up this long resets the backoff
	dialTimeout = 15 * time.Second
)

// Client keeps tunnels open to every relay and serves handler over them.
type Client struct {
	cfg     *config.Tunnel
	id      *Identity
	handler http.Handler
	log     *slog.Logger

	hs *http.Server // carries the graceful-shutdown hook for every tunnel
	h2 *http2.Server

	up       *metrics.Counter
	connects *metrics.Counter
	expiry   *metrics.Counter

	// dial is the TCP dialer; tests replace it.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// proxyFor returns the outbound HTTP proxy for a relay, or nil.
	proxyFor func(*url.URL) (*url.URL, error)

	wg      sync.WaitGroup
	closing chan struct{} // closed by Shutdown: stop reconnecting
	once    sync.Once
}

// New prepares a client. handler is the proxy itself; requests from a
// tunnel go through it exactly like inbound ones.
func New(cfg *config.Tunnel, id *Identity, handler http.Handler, log *slog.Logger, reg *metrics.Registry) *Client {
	c := &Client{
		cfg: cfg, id: id, handler: handler, log: log,
		hs: &http.Server{},
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
	c.expiry.Set(c.id.DaysLeft())
	c.log.Info("tunnel starting", "tenant", c.id.Tenant, "proxy", c.id.Proxy, "relays", c.cfg.Relays,
		"connections_per_relay", c.cfg.ConnectionsPerRelay, "cert_expires", c.id.Leaf.NotAfter.Format(time.RFC3339))
	if c.id.DaysLeft() < 30 {
		c.log.Warn("tunnel certificate expires soon", "days", int(c.id.DaysLeft()))
	}
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
		conn, err := c.connect(ctx, relay)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.log.Warn("tunnel connect failed", "relay", relay, "error", err.Error(), "retry_in", backoff.String())
		} else {
			c.up.Add(1, relay)
			c.log.Info("tunnel connected", "relay", relay)
			c.serve(ctx, conn)
			c.up.Add(-1, relay)
			lived := time.Since(start)
			c.log.Info("tunnel closed", "relay", relay, "lived", lived.Round(time.Second).String())
			if lived > stableAfter {
				backoff = backoffMin
			}
		}
		if c.isClosing() {
			return
		}
		// Full jitter, so a relay restart doesn't get every proxy back at once.
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

// serve runs HTTP/2 with the relay as the client (docs/tunnel-protocol.md).
func (c *Client) serve(ctx context.Context, conn *tls.Conn) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.handler.ServeHTTP(w, r.WithContext(WithVia(r.Context())))
	})
	c.h2.ServeConn(conn, &http2.ServeConnOpts{Context: ctx, BaseConfig: c.hs, Handler: handler})
}

// connect dials the relay (through the outbound proxy if one is set), runs
// mutual TLS and checks the negotiated protocol.
func (c *Client) connect(ctx context.Context, relay string) (*tls.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	host, _, _ := net.SplitHostPort(relay)

	raw, err := c.dialRelay(ctx, relay)
	if err != nil {
		c.connects.Inc(relay, "dial_error")
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{
		Certificates: []tls.Certificate{c.id.Certificate},
		RootCAs:      c.id.RelayCAs,
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
	c.connects.Inc(relay, "ok")
	return conn, nil
}

// Check connects to one relay and completes the mutual-TLS handshake, then
// closes the connection. For `neubird-proxy test`.
func (c *Client) Check(ctx context.Context, relay string) (tls.ConnectionState, error) {
	conn, err := c.connect(ctx, relay)
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
