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

// Status is what GET /_neubird/status returns: enough for NeuBird to offer
// the proxy's connections in its UI and send requests the proxy will
// accept. Nothing from config values (upstreams, paths, patterns, secrets)
// and nothing from traffic.
type Status struct {
	Version      string             `json:"version,omitempty"`
	ConfigSHA256 string             `json:"config_sha256,omitempty"`
	Connections  []ConnectionStatus `json:"connections"`
	// Destinations is open mode (neubird_destinations), when the token opens
	// it: NeuBird may name any destination matching Hosts.
	Destinations *DestinationsStatus `json:"destinations,omitempty"`
}

// DestinationsStatus describes open mode. The host patterns are the
// customer's envelope for NeuBird, not a secret; upstream credentials and
// patterns of the named connections are still never reported.
type DestinationsStatus struct {
	Hosts             []string `json:"hosts"`
	ClientAuth        string   `json:"client_auth"`
	ClientAuthHeader  string   `json:"client_auth_header,omitempty"`
	CredentialHeaders []string `json:"credential_headers"`
	Methods           []string `json:"methods"`
}

type ConnectionStatus struct {
	Name             string `json:"name"`
	ClientAuth       string `json:"client_auth"`
	ClientAuthHeader string `json:"client_auth_header,omitempty"`
	// Credentials is customer (the proxy injects the backend credential) or
	// neubird (NeuBird sends it in X-Neubird-Upstream-<header>).
	Credentials       string   `json:"credentials"`
	CredentialHeaders []string `json:"credential_headers,omitempty"`
	Methods           []string `json:"methods"`
	MCPTools          []string `json:"mcp_tools,omitempty"`
	// PathsRestricted and FieldsRestricted say whether paths and
	// response_fields are set, without saying what they are.
	PathsRestricted  bool `json:"paths_restricted"`
	FieldsRestricted bool `json:"fields_restricted"`
	Redaction        bool `json:"redaction"`
}

// serveStatus answers GET /_neubird/status for a bearer token, listing only
// the connections that token opens. A token that opens none gets a 401, the
// same as a wrong token on a connection.
func (s *Server) serveStatus(w *recorder, r *http.Request) {
	var listed int
	defer func() {
		s.Metrics.Requests.Inc("_status", strconv.Itoa(w.status))
		s.log.Info("status", "remote_addr", r.RemoteAddr, "method", r.Method, "status", w.status, "connections", listed)
	}()
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "status is GET only")
		return
	}
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	tok = strings.TrimSpace(tok)
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid proxy token")
		return
	}
	sum := sha256.Sum256([]byte(tok))

	st := Status{Version: s.Version, ConfigSHA256: s.ConfigSHA256, Connections: []ConnectionStatus{}}
	// Every connection's tokens are compared, matched or not, so timing
	// doesn't reveal which connections a token opens.
	for i := range s.cfg.Connections {
		c := &s.cfg.Connections[i]
		match := 0
		for _, t := range s.tokens[c.Name] {
			match |= subtle.ConstantTimeCompare(sum[:], t[:])
		}
		if match == 1 {
			st.Connections = append(st.Connections, connectionStatus(c))
		}
	}
	if d := s.dest; d != nil {
		match := 0
		for _, t := range s.tokens[d.Conn.Name] {
			match |= subtle.ConstantTimeCompare(sum[:], t[:])
		}
		if match == 1 {
			cs := connectionStatus(d.Conn)
			st.Destinations = &DestinationsStatus{
				Hosts:             append([]string(nil), d.Hosts...),
				ClientAuth:        cs.ClientAuth,
				ClientAuthHeader:  cs.ClientAuthHeader,
				CredentialHeaders: cs.CredentialHeaders,
				Methods:           cs.Methods,
			}
		}
	}
	if len(st.Connections) == 0 && st.Destinations == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid proxy token")
		return
	}
	listed = len(st.Connections)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(st)
}

func connectionStatus(c *config.Connection) ConnectionStatus {
	cs := ConnectionStatus{
		Name:             c.Name,
		ClientAuth:       c.ClientAuth,
		ClientAuthHeader: c.ClientAuthHeader,
		Credentials:      c.Credentials,
		Methods:          strings.Split(allowHeader(c), ", "),
		MCPTools:         c.MCPTools,
		PathsRestricted:  len(c.PathRes) > 0,
		FieldsRestricted: len(c.ResponseFields) > 0,
		Redaction:        !c.Passthrough,
	}
	for h := range c.CredentialHeaderSet {
		cs.CredentialHeaders = append(cs.CredentialHeaders, h)
	}
	sort.Strings(cs.CredentialHeaders)
	return cs
}
