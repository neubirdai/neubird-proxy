package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/metrics"
)

// serverTLSRefresh is how often the listener's certificate, key and client
// CA files are re-read. A mounted Secret is updated in place within about a
// minute of a change, so a renewal or an emergency rotation takes effect
// without a restart.
const serverTLSRefresh = time.Minute

// ServerTLS is the inbound listener's TLS: TLS 1.2 or later, and with
// tls.client_ca_file, a required client certificate from that CA. The files
// are re-read every serverTLSRefresh; each handshake uses the latest set that
// loaded, and a set that stops loading (mid-rotation, or a bad Secret) keeps
// the previous one in use.
type ServerTLS struct {
	cfg    *config.TLS
	log    *slog.Logger
	expiry *metrics.Counter

	mu       sync.Mutex
	cur      *serverTLSFiles
	errMsg   string // last load error logged, so each is logged once
	warnedAt int    // days left when expiry was last warned about
}

// serverTLSFiles is one loaded set of files. Sets are replaced, never
// modified: a handshake in progress keeps the one it started with.
type serverTLSFiles struct {
	raw       [][]byte // cert, key, client CA: compared to skip unchanged files
	cert      *tls.Certificate
	clientCAs *x509.CertPool
}

// NewServerTLS loads the files once; an error here fails startup. reg may
// be nil (tests).
func NewServerTLS(t *config.TLS, log *slog.Logger, reg *metrics.Registry) (*ServerTLS, error) {
	s := &ServerTLS{cfg: t, log: log, warnedAt: -1}
	if reg != nil {
		s.expiry = reg.Gauge("neubird_proxy_tls_cert_expiry_days", "Days until the inbound listener's certificate expires.")
	}
	f, err := s.load(nil)
	if err != nil {
		return nil, err
	}
	s.set(f)
	return s, nil
}

// Config is the listener's tls.Config. Each handshake gets the current
// certificate and client CAs through GetConfigForClient.
func (s *ServerTLS) Config() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return s.handshakeConfig(), nil },
	}
}

func (s *ServerTLS) handshakeConfig() *tls.Config {
	s.mu.Lock()
	f := s.cur
	s.mu.Unlock()
	c := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*f.cert},
		// A config from GetConfigForClient doesn't inherit the server's
		// ALPN protocols: without these, clients would never get HTTP/2.
		NextProtos: []string{"h2", "http/1.1"},
	}
	if f.clientCAs != nil {
		c.ClientCAs = f.clientCAs
		c.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return c
}

// Run re-reads the files every serverTLSRefresh until ctx is done.
func (s *ServerTLS) Run(ctx context.Context) {
	t := time.NewTicker(serverTLSRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Refresh()
		}
	}
}

// Refresh re-reads the files once. A set that doesn't load is logged (once
// per distinct error) and the previous set stays in use.
func (s *ServerTLS) Refresh() {
	s.mu.Lock()
	prev := s.cur
	s.mu.Unlock()
	f, err := s.load(prev)
	if err != nil {
		s.mu.Lock()
		if msg := err.Error(); msg != s.errMsg {
			s.errMsg = msg
			s.log.Warn("tls certificate files don't load; keeping the previous certificate", "error", msg)
		}
		s.mu.Unlock()
		return
	}
	s.mu.Lock()
	s.errMsg = ""
	s.mu.Unlock()
	if f != prev {
		s.log.Info("tls certificate, key or client CA reloaded", "cert_expires", f.cert.Leaf.NotAfter.Format(time.RFC3339))
	}
	s.set(f)
}

// load reads the files, returning prev itself when none of them changed.
func (s *ServerTLS) load(prev *serverTLSFiles) (*serverTLSFiles, error) {
	certPEM, err := os.ReadFile(s.cfg.CertFile)
	if err != nil {
		return nil, fmt.Errorf("tls.cert_file: %w", err)
	}
	keyPEM, err := os.ReadFile(s.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls.key_file: %w", err)
	}
	var caPEM []byte
	if s.cfg.ClientCAFile != "" {
		if caPEM, err = os.ReadFile(s.cfg.ClientCAFile); err != nil {
			return nil, fmt.Errorf("tls.client_ca_file: %w", err)
		}
	}
	raw := [][]byte{certPEM, keyPEM, caPEM}
	if prev != nil && bytes.Equal(prev.raw[0], raw[0]) && bytes.Equal(prev.raw[1], raw[1]) && bytes.Equal(prev.raw[2], raw[2]) {
		return prev, nil
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	f := &serverTLSFiles{raw: raw, cert: &cert}
	if s.cfg.ClientCAFile != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("tls.client_ca_file: no certificates found in %s", s.cfg.ClientCAFile)
		}
		f.clientCAs = pool
	}
	return f, nil
}

func (s *ServerTLS) set(f *serverTLSFiles) {
	days := time.Until(f.cert.Leaf.NotAfter).Hours() / 24
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur = f
	if s.expiry != nil {
		s.expiry.Set(days)
	}
	// Once a day while under 30 days, not on every refresh.
	if days < 30 && int(days) != s.warnedAt {
		s.warnedAt = int(days)
		s.log.Warn("tls certificate expires soon", "days", int(days))
	}
}
