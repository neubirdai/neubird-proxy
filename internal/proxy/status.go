package proxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/neubirdai/neubird-proxy/internal/config"
)

// statusPath is answered by the proxy itself. Connection names start with
// [a-z0-9], so it can never shadow one.
const statusPath = "/_neubird/status"

// Status is what GET /_neubird/status returns: how NeuBird must send an
// open-mode request (neubird_destinations) for the token it presented.
// Nothing about upstreams, host patterns, connections, secrets or traffic.
type Status struct {
	Destinations *DestinationsStatus `json:"destinations,omitempty"`
}

// DestinationsStatus is how open mode wants requests: where the proxy token
// goes, and which upstream headers NeuBird may set.
type DestinationsStatus struct {
	ClientAuth        string   `json:"client_auth"`
	ClientAuthHeader  string   `json:"client_auth_header,omitempty"`
	CredentialHeaders []string `json:"credential_headers"`
}

// serveStatus answers GET /_neubird/status for a bearer token that opens open
// mode, or for anyone when open mode takes client_auth: none (a tunnel-only
// proxy). Any other token gets a 401, the same as a wrong token on a
// connection.
func (s *Server) serveStatus(w *recorder, r *http.Request) {
	defer func() {
		s.Metrics.Requests.Inc("_status", strconv.Itoa(w.status))
		s.log.Info("status", "remote_addr", r.RemoteAddr, "method", r.Method, "status", w.status)
	}()
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "status is GET only")
		return
	}
	if s.dest == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid proxy token")
		return
	}
	if s.dest.Conn.ClientAuth != config.AuthNone {
		scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		tok = strings.TrimSpace(tok)
		if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid proxy token")
			return
		}
		sum := sha256.Sum256([]byte(tok))
		match := 0
		for _, t := range s.tokens[s.dest.Conn.Name] {
			match |= subtle.ConstantTimeCompare(sum[:], t[:])
		}
		if match != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid proxy token")
			return
		}
	}
	c := s.dest.Conn
	d := &DestinationsStatus{ClientAuth: c.ClientAuth, ClientAuthHeader: c.ClientAuthHeader}
	for h := range c.CredentialHeaderSet {
		d.CredentialHeaders = append(d.CredentialHeaders, h)
	}
	if c.CredentialHeaderAny {
		// "*", plus Authorization for NeuBird agents that predate "*": they
		// move only the headers listed, so they still send that one.
		d.CredentialHeaders = append(d.CredentialHeaders, "*", "Authorization")
	}
	sort.Strings(d.CredentialHeaders)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(Status{Destinations: d})
}
