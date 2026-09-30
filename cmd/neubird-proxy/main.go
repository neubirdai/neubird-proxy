// Command neubird-proxy is the redaction reverse proxy MetLife runs in
// front of its APIM endpoints for NeuBird.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/neubirdai/neubird-proxy/internal/config"
	"github.com/neubirdai/neubird-proxy/internal/proxy"
	"github.com/neubirdai/neubird-proxy/internal/redact"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/neubird-proxy/config.yaml", "path to the YAML config")
	check := flag.Bool("check", false, "validate the config and exit")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(*configPath, *check, log); err != nil {
		log.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func run(configPath string, check bool, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	engine, err := redact.New(cfg.Redaction)
	if err != nil {
		return err
	}
	if check {
		fmt.Printf("config ok: %d connections, rules: %s\n", len(cfg.Connections), strings.Join(engine.RuleNames(), ", "))
		return nil
	}

	srv, err := proxy.New(cfg, engine, log, nil)
	if err != nil {
		return err
	}

	var conns []string
	for _, c := range cfg.Connections {
		mode := "redact"
		if c.Passthrough {
			mode = "passthrough"
		}
		conns = append(conns, c.Name+"("+mode+")")
	}
	log.Info("starting", "version", version, "listen", cfg.Listen, "admin_listen", cfg.AdminListen,
		"tls", cfg.TLS != nil, "connections", conns, "rules", engine.RuleNames(),
		"mask", cfg.Redaction.Mask, "max_body_bytes", cfg.MaxBodyBytes)

	var ready atomic.Bool
	admin := http.NewServeMux()
	admin.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	admin.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	admin.Handle("GET /metrics", srv.Metrics.Registry.Handler())

	proxySrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: MCP SSE streams and Splunk exports are long-lived.
	}
	adminSrv := &http.Server{Addr: cfg.AdminListen, Handler: admin, ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 2)
	go func() {
		var err error
		if cfg.TLS != nil {
			err = proxySrv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			err = proxySrv.ListenAndServe()
		}
		errc <- fmt.Errorf("proxy listener: %w", err)
	}()
	go func() { errc <- fmt.Errorf("admin listener: %w", adminSrv.ListenAndServe()) }()
	ready.Store(true)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	ready.Store(false)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = proxySrv.Shutdown(shutdownCtx)
	_ = adminSrv.Shutdown(shutdownCtx)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}
