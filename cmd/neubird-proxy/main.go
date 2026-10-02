// Command neubird-proxy is the redaction reverse proxy MetLife runs in
// front of its APIM endpoints for NeuBird.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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

// Subcommands run instead of the proxy. The same binary is in the image,
// so `kubectl exec <pod> -- /neubird-proxy test` runs inside the pod, with
// its secrets and network.
var commands = map[string]struct {
	run   func(args []string, stdout, stderr io.Writer) int
	usage string
}{
	"validate": {cmdValidate, "check a config file, offline or with secrets"},
	"test":     {cmdTest, "diagnose each connection: DNS, TCP, TLS, a request through the proxy"},
	"preview":  {cmdPreview, "show a response next to what NeuBird would receive (terminal or HTML)"},
	"token":    {cmdToken, "generate a random proxy token"},
	"metrics":  {cmdMetrics, "summarize /metrics output from one or more pods"},
	"netpol":   {cmdNetpol, "generate egress network rules allowing only the configured upstreams"},
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "usage: neubird-proxy [-config path]            run the proxy\n")
	fmt.Fprintf(w, "       neubird-proxy <command> [flags] [args]   run a tool\n\ncommands:\n")
	for _, name := range []string{"validate", "test", "preview", "token", "metrics", "netpol"} {
		fmt.Fprintf(w, "  %-9s %s\n", name, commands[name].usage)
	}
	fmt.Fprintf(w, "\nrun 'neubird-proxy <command> -h' for its flags\n")
}

func main() {
	if len(os.Args) > 1 {
		if c, ok := commands[os.Args[1]]; ok {
			os.Exit(c.run(os.Args[2:], os.Stdout, os.Stderr))
		}
		if a := os.Args[1]; a == "help" || a == "-h" || a == "--help" {
			usage(os.Stdout)
			return
		}
	}
	flag.Usage = func() { usage(os.Stderr); fmt.Fprintln(os.Stderr, "\nflags:"); flag.PrintDefaults() }
	configPath := flag.String("config", "/etc/neubird-proxy/config.yaml", "path to the YAML config")
	check := flag.Bool("check", false, "validate the config and exit (see also: neubird-proxy validate)")
	redactFile := flag.String("redact", "", "redact this file (- for stdin) with the config's rules, print it, and exit; per-rule counts go to stderr")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if *redactFile != "" {
		if err := redactOffline(*configPath, *redactFile, os.Stdout, os.Stderr); err != nil {
			log.Error("fatal", "error", err.Error())
			os.Exit(1)
		}
		return
	}
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
		for _, w := range warnings(cfg) {
			fmt.Printf("warning: %s\n", w)
		}
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
	log.Info("starting", "version", version, "config_sha256", configHash(configPath),
		"listen", cfg.Listen, "admin_listen", cfg.AdminListen,
		"tls", cfg.TLS != nil, "connections", conns, "rules", engine.RuleNames(),
		"mask", cfg.Redaction.Mask, "max_body_bytes", cfg.MaxBodyBytes)
	for _, w := range warnings(cfg) {
		log.Warn("risky configuration", "detail", w)
	}

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

	var serverTLS *tls.Config
	if cfg.TLS != nil {
		if serverTLS, err = proxy.ServerTLSConfig(cfg.TLS); err != nil {
			return err
		}
	}
	proxySrv := &http.Server{
		TLSConfig:         serverTLS,
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
			err = proxySrv.ListenAndServeTLS("", "")
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

// configHash identifies the exact config a pod runs, so a ConfigMap change
// shows up in the logs even if nobody announced it.
func configHash(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// warnings lists settings that weaken the proxy's guarantees. They are
// allowed, but every pod start says so.
func warnings(cfg *config.Config) []string {
	var out []string
	if cfg.TLS == nil {
		out = append(out, "tls is not set: the proxy listener is plain HTTP and relies on the load balancer for TLS")
	} else if cfg.TLS.ClientCAFile == "" {
		out = append(out, "tls.client_ca_file is not set: clients are authenticated by token only, not mTLS")
	}
	if cfg.AllowHTTPUpstreams {
		out = append(out, "allow_http_upstreams is set: upstream traffic may be unencrypted")
	}
	if cfg.ClientTokenPreviousEnv != "" {
		out = append(out, "client_token_previous_env is set: two tokens are accepted until rotation is finished")
	}
	for _, c := range cfg.Connections {
		if c.Passthrough {
			out = append(out, fmt.Sprintf("connection %s: passthrough, responses are NOT redacted", c.Name))
		}
		if len(c.PathRes) == 0 {
			out = append(out, fmt.Sprintf("connection %s: no paths allowlist, every upstream path is reachable", c.Name))
		}
		var writes []string
		for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			if c.MethodSet[m] {
				writes = append(writes, m)
			}
		}
		if len(writes) > 0 && len(c.RequestDenyRes) == 0 && len(c.MCPTools) == 0 {
			out = append(out, fmt.Sprintf("connection %s: allows %s with no request_deny_patterns or mcp_tools", c.Name, strings.Join(writes, ", ")))
		}
	}
	return out
}

// redactOffline runs the redaction rules over a local file, so MetLife can
// measure what the rules catch on their own data without it leaving their
// network. JSON (including NDJSON) is redacted as JSON, anything else as
// text; non-text input is refused, as the proxy would.
func redactOffline(configPath, input string, stdout, stderr io.Writer) error {
	rc, err := config.LoadRedaction(configPath, os.LookupEnv)
	if err != nil {
		return err
	}
	engine, err := redact.New(*rc)
	if err != nil {
		return err
	}
	var body []byte
	if input == "-" {
		body, err = io.ReadAll(os.Stdin)
	} else {
		body, err = os.ReadFile(input)
	}
	if err != nil {
		return err
	}
	if !redact.IsText(body) {
		return fmt.Errorf("%s is not UTF-8 text; the proxy would refuse it (not_text)", input)
	}
	st := redact.Stats{}
	out, err := engine.JSON(body, st)
	if err != nil {
		out = engine.Text(body, st)
	}
	if _, err := stdout.Write(out); err != nil {
		return err
	}
	fmt.Fprintln(stdout)
	counts, _ := json.Marshal(st)
	fmt.Fprintf(stderr, "redactions: %d %s\n", st.Total(), counts)
	return nil
}
