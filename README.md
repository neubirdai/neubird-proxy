# neubird-proxy

A redacting reverse proxy that MetLife runs in their AKS cluster between
NeuBird and MetLife's internal APIM endpoints. It masks PII in every response
before the data leaves MetLife. Design: *MetLife Redaction Proxy: Engineering
Proposal* (Sep 30, 2026).

```
NeuBird ──(one proxy token)──▶ neubird-proxy ──(APIM subscription key)──▶ APIM (internal) ──(Key Vault creds)──▶ Splunk / Maestro / ServiceNow
                                  │ redacts every response body
```

- **Routing.** The first path segment names the connection:
  `/splunk/services/search/jobs?x=1` goes to `<splunk upstream>/services/search/jobs?x=1`.
  A connection can also claim a hostname (`host:`) for connectors that cannot
  take a base URL with a path.
- **Credentials.** NeuBird sends one proxy token, as a Bearer token, a Basic
  password, or a named header (set per connection, so connectors need no code
  change). The proxy checks the token, removes it, and sends
  `Ocp-Apim-Subscription-Key` instead. For a backend that APIM does not front,
  `upstream_basic_auth` or `headers` inject its credential from the Secret.
- **Redaction.** Responses only. JSON is walked token by token, so keys, key
  order and number precision survive. Text, XML and CSV get whole-body regex.
  `text/event-stream` (MCP) is redacted one event at a time and flushed
  immediately. Gzip is decoded.
- **Fail closed.** Anything the proxy cannot redact is refused with
  `502 {"error":"redaction_blocked","reason":...}`: a body over
  `max_body_bytes`, a binary or unparseable content type, an unknown content
  encoding, or a protocol upgrade (WebSocket). An SSE event over the cap cuts
  the stream. `passthrough: true` turns all of this off for a connection
  MetLife has cleared, such as Elastic.

## Rules

| Rule | Matches |
|---|---|
| `email` | RFC-ish addresses |
| `us_ssn` | `123-45-6789`, `123 45 6789`; rejects area 000/666/9xx, group 00, serial 0000 |
| `credit_card` | 13–19 digits, optionally space or dash separated, Luhn-checked |
| `phone_us` | `(212) 555-0147`, `212-555-0147`, `+1 212.555.0147`; a separator is required, so epoch timestamps don't match |
| `ipv4` | dotted quads |
| `date_of_birth` | key rule: whole value under `dob`, `date_of_birth`, `birth_date`, `birthday`, `u_dob` |

Omit `builtins` to enable all of them; `builtins: []` disables them. Custom
rules (`custom`) run after the builtins. `blocked_key_patterns` mask every
scalar value under a matching JSON key. An `allowed_values` pattern exempts a
match only if it covers the entire match. Where matches overlap, the earliest
match wins, and on a tie the higher-precedence rule wins. Rules match against
the original text, so a mask is never re-matched by a later rule.

Masks are `[REDACTED:EMAIL]`, or with `mask: hmac`
`[REDACTED:EMAIL:3f1c9a0b7d2e4f61]`. The HMAC form is an HMAC-SHA256 truncated
to 64 bits and keyed by `REDACTION_HMAC_KEY`, so the agent can still tell
when two events contain the same value.

Every regex is RE2 (linear time, no lookarounds or backreferences). An invalid
rule, an unknown builtin, or a pattern that matches the empty string stops the
proxy from starting.

**Limitation:** regex catches formatted identifiers. It does not catch
free-text names or street addresses (see
`internal/proxy/testdata/golden/servicenow_table.json.golden`, where "Dana
Whitfield" survives). NER detection (Presidio) is a phase 2 option.

## Config

See [`deploy/config.example.yaml`](deploy/config.example.yaml). Secrets never
appear in the file. Every `*_env` field and every `${VAR}` in a header value
must resolve to a non-empty environment variable, or the proxy refuses to
start. Unknown YAML fields are errors.

Validate before rolling out a ConfigMap change (v1 has no hot reload; restart
the pods):

```bash
make check-config CONFIG=path/to/config.yaml
# or, with the real env: neubird-proxy -check -config config.yaml
```

## Operations

- `:8443`: the proxy. This is the only port behind the load balancer. Optional
  in-pod TLS via `tls:`.
- `:9090`: `/healthz`, `/readyz`, `/metrics`, cluster-internal only.
- Audit: one JSON line per request with the connection, method, path (itself
  redacted), status, bytes, duration, per-rule match counts, and the block
  reason. Query strings and matched values are never logged.
- Metrics: `neubird_proxy_requests_total{connection,code}`,
  `neubird_proxy_redactions_total{connection,rule}`,
  `neubird_proxy_blocked_total{connection,reason}`,
  `neubird_proxy_response_bytes_total{connection}`.
- Stateless, no disk. Runs as two replicas with a read-only root filesystem, as non-root, with no capabilities.

## Deploy

```bash
kubectl -n neubird create secret generic neubird-proxy \
  --from-literal=NEUBIRD_PROXY_TOKEN=... \
  --from-literal=APIM_SUBSCRIPTION_KEY=...
kubectl -n neubird create configmap neubird-proxy --from-file=config.yaml
kubectl apply -f deploy/kubernetes.yaml   # edit the CHANGE ME lines first
```

## Develop

```bash
make test    # go test -race ./...
make lint
make image   # distroless static, non-root
make sbom    # SPDX JSON via syft
go test ./internal/proxy -run Golden -update   # regenerate golden files, then review the diff
```

Dependencies: the Go standard library and `gopkg.in/yaml.v3`.

## Not in v1

- Rewriting absolute upstream URLs inside response bodies (pagination links,
  Splunk job URIs). `Location` headers are rewritten. Whether bodies need it
  depends on the open connector question below.
- Request redaction, hot reload, and NER detection.

## Open questions (from the proposal)

For NeuBird engineering: do our Splunk, ServiceNow and MCP connectors accept a
base URL with a path prefix? Do they follow absolute URLs from responses? Where
does the proxy token go in each connector's UI? What is the largest expected
response body (this sets `max_body_bytes`)?

For MetLife: will ServiceNow be fronted by APIM? One subscription key or one per
API? What are the real member ID and PHI formats? Is regex-only detection
acceptable? What is the status of Cribl for Splunk?
