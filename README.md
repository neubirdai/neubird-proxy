# neubird-proxy

A redacting reverse proxy that MetLife runs in their AKS cluster between
NeuBird and MetLife's internal APIM endpoints. It limits what NeuBird can ask
for, and masks PII and secrets in every response before the data leaves
MetLife. Design: *MetLife Redaction Proxy: Engineering Proposal* (Sep 30,
2026). Open security work: [docs/security-plan.md](docs/security-plan.md).

```
NeuBird ──(proxy token)──▶ neubird-proxy ──(APIM subscription key)──▶ APIM (internal) ──(Key Vault creds)──▶ Splunk / Maestro / ServiceNow
                             │ allowlists requests, redacts responses
```

## What a request goes through

In order; the first check that fails ends the request.

1. **Capacity.** Beyond `max_concurrent_requests` in flight, the proxy returns 503.
2. **Path hygiene.** Paths with `.` or `..` segments (including
   percent-encoded, double-encoded and backslash forms) get a 400, so a
   request can't enter through one connection and be normalized upstream
   into another.
3. **Routing.** The first path segment names the connection:
   `/splunk/services/search/jobs?x=1` goes to
   `<splunk upstream>/services/search/jobs?x=1`. A connection can also claim a
   hostname (`host:`) for connectors that cannot take a base URL with a path.
4. **Token.** The token must be one this connection accepts: its own
   `client_token_env`, or the top-level current or previous token. It must be
   sent in the form the connection expects (a Bearer token, a Basic password,
   or a named header), so connectors need no code change. Tokens shorter than
   32 characters are refused at startup.
5. **Method allowlist.** GET and HEAD only, unless the connection lists
   `methods`. Anything else gets a 405.
6. **Path allowlist.** If `paths` is set, the path after the prefix must fully
   match one of the patterns, or the request gets a 403.
7. **Rate limit.** Per connection and per pod, when `rate_limit` is set;
   over the limit gets a 429.
8. **Request checks.** The query string and body are checked raw and
   URL-decoded against `request_deny_patterns`, for example Splunk commands
   that write or send data. On an MCP connection with `mcp_tools`, a
   `tools/call` (alone or in a batch) naming any other tool is refused, and so
   is a POST body that isn't JSON-RPC. Either gets a 403.
9. **Header allowlist.** Only allowlisted client headers go upstream. This
   drops the NeuBird token, cookies, `Ocp-Apim-Trace`, a client-supplied
   subscription key, and `Accept-Encoding`/`Range` (bodies must arrive whole
   and uncompressed). The proxy adds the APIM subscription key and an
   `X-Request-Id`.
10. **Response.**
    - Stripped: `Set-Cookie`, all `Ocp-Apim-*` headers, and trailers.
    - Dropped: 1xx informational responses such as 103 Early Hints, whose
      headers would otherwise reach the client before redaction runs.
    - Redacted: every remaining header value, then the body.
    - Refused if it can't be redacted (see Fail closed).

With `tls.client_ca_file`, the TLS handshake also requires a client
certificate from that CA before any of this runs (mutual TLS).

`passthrough: true` skips step 10's redaction and fail-closed checks for a
connection MetLife has cleared, such as Elastic. Every pod start logs a
warning for it.

## Redaction

- **JSON** is walked token by token, so key order and number precision
  survive.
  - Object keys get the value rules too, so a map keyed by email is masked.
    If two keys mask to the same label they collide, and parsers keep only
    one; `mask: hmac` avoids this.
  - A string that holds JSON (MCP tool `text`, Splunk `_raw`) is walked as
    JSON, so key rules apply inside it.
  - Numbers are masked only under a blocked key: a Luhn-valid timestamp must
    not change type.
- **Text, XML and CSV** get whole-body rules.
- **`text/event-stream`** (MCP) is redacted one event at a time, including
  `event:` and `id:` lines, and each event is flushed immediately.
- **Gzip** is decoded.
- **Field allowlist.** With `response_fields`, only the listed JSON fields
  leave unmasked. Every other string or number becomes `[REDACTED:FIELD]`,
  whatever it contains, and allowed fields still get every rule. A response
  that isn't JSON is refused (`not_json`), because the allowlist can't be
  checked. For SSE, a data payload that isn't JSON is masked whole. Patterns
  are dot paths of keys, where `*` matches any one key. Array elements add
  no segment, so `result.number` covers every element of a `result` array.
  A pattern allows everything beneath it.
- **Before matching**, text is normalized: percent-escapes (`%40`), HTML
  entities (`&#64;`, `&commat;`), full-width characters (`２１９`), and
  invisible characters (zero-width space, soft hyphen) are decoded or
  removed. The mask replaces the original bytes.

### Fail closed

The proxy refuses a response with
`502 {"error":"redaction_blocked","reason":...}` when it can't redact it:
- a body over `max_body_bytes`
- a body that isn't UTF-8 text (compressed or binary data behind a
  `text/plain` label or no `Content-Type`)
- an unsupported content type or encoding
- a 206 partial response
- a protocol upgrade

For SSE, the status line has already been sent. So an event over the cap, or
one that isn't text, cuts the stream instead; the client sees a truncated
read, and the audit line records the reason.

## Rules

PII:

| Rule | Matches |
|---|---|
| `email` | Addresses, including encoded forms |
| `us_ssn` | `219-09-9999`, `219 09 9999`, and after a keyword (`ssn=219099999`, `Social Security Number 219099999`); rejects area 000/666/9xx, group 00, serial 0000. Key rule: `ssn`, `social_security_number`, `tax_id`, `tin` |
| `credit_card` | 13–19 digits with an issuer prefix, separated by spaces, dots or dashes, Luhn-checked; still found next to other digit groups |
| `phone_us` | `(212) 555-0147`, `212-555-0147`, `+1 212.555.0147`, and unformatted after a keyword (`phone=2125550147`). Key rule: `phone`, `mobile_phone`, `home_phone`, ... |
| `ipv4` | Dotted quads |
| `date_of_birth` | A date after `DOB`, `D.O.B.`, `date of birth`, `born on`; key rule: `dob`, `date_of_birth`, `birth_date`, `birthday`, `u_dob` |

Secrets:

| Rule | Matches |
|---|---|
| `private_key` | PEM private key blocks |
| `jwt` | `eyJ...` tokens |
| `aws_access_key` | `AKIA...`, `ASIA...` and other AWS key IDs |
| `azure_key` | `AccountKey=` and `SharedAccessKey=` values, SAS `sig=` |
| `vendor_token` | GitHub, Slack, OpenAI, Google API and GitLab tokens |
| `url_credentials` | The password in `scheme://user:password@host` |
| `bearer_token` | The value after `Bearer`/`Basic`/`Token`, when it contains a digit |
| `secret_assignment` | The value in `password=`, `secret:`, `api_key=`, `client_secret=`, `db_password: "..."`; key rule on the same words |

Opt-in: `windows_account` masks the user in `DOMAIN\user`.

Omit `builtins` to enable the default set (everything but `windows_account`);
`builtins: []` disables them all.
- **Custom rules** (`custom`) run after the builtins. A custom regex with a
  named group `v`, such as `member:\s*(?P<v>\d+)`, masks only that group.
- **`blocked_key_patterns`** mask every scalar value under a matching JSON key.
- **`allowed_values`** exempt a match only if a pattern matches all of it.
- **Overlapping matches** merge into one mask, so no part of either survives.

Masks look like `[REDACTED:EMAIL]`. With `mask: hmac` they look like
`[REDACTED:EMAIL:3f1c9a0b7d2e4f61]`: an HMAC-SHA256 truncated to 64 bits,
computed over the normalized value, so the agent can tell when two events
contain the same value. This is pseudonymization, not anonymization: whoever
holds `REDACTION_HMAC_KEY` can recover low-entropy values like SSNs by brute
force.

Every regex is RE2 (linear time, no lookarounds or backreferences). An invalid
rule, an unknown builtin, or a pattern that matches the empty string stops the
proxy from starting.

### What it does not catch

Regex finds identifiers with a recognizable shape or keyword. It does not find:
- **Free-text names, street addresses or health conditions.** In the
  ServiceNow golden file, "Dana Whitfield" survives.
- **Hostnames and file paths**, unless MetLife adds a custom rule; the
  example config has one for `*.corp.metlife.com`.
- **Unformatted numbers without a keyword**, such as a bare 9-digit SSN.

For free text, use `response_fields`: fields nobody approved never leave in
the clear. The fields that must pass as free text, like Splunk `_raw` and
MCP tool output, still depend on the rules, and NER is the remaining gap
there; see the plan.

To measure the rules on your own data without sending it anywhere:

```bash
neubird-proxy -config config.yaml -redact sample.json > redacted.json   # counts per rule on stderr
```

`-redact` reads only the `redaction` section, so it needs no connection
secrets.

## Config

See [`deploy/config.example.yaml`](deploy/config.example.yaml), which is a
locked-down example. Secrets never appear in the file. Every `*_env` field and
every `${VAR}` in a header value must resolve to a non-empty environment
variable, or the proxy refuses to start. Unknown YAML fields are errors.

| Field | Default | Meaning |
|---|---|---|
| `listen` | `:8443` | NeuBird-facing listener |
| `admin_listen` | `:9090` | Health and metrics listener |
| `tls.cert_file`, `tls.key_file` | none | Terminate TLS in the pod; both are required if `tls` is set |
| `tls.client_ca_file` | none | Require client certificates from this PEM CA bundle (mutual TLS) |
| `upstream_ca_file` | system roots | Extra PEM CA bundle to trust for upstreams |
| `allow_http_upstreams` | `false` | Allow `http://` upstreams; otherwise only `https://` is accepted |
| `client_token_env` | none | Env var with the default token, 32+ characters; required unless every connection sets its own |
| `client_token_previous_env` | none | Also accepted during a rotation; remove it afterwards |
| `max_body_bytes` | 20 MiB | Cap for request bodies, buffered response bodies and each SSE event |
| `max_concurrent_requests` | 256 | In-flight requests before the proxy returns 503 |
| `max_concurrent_buffered` | 4 | Response bodies buffered for redaction at once; others wait |
| `upstream_defaults.headers` | none | Headers set on every upstream request; values may use `${VAR}` |
| `connections[].name` | required | Path prefix; `[a-z0-9][a-z0-9_-]*`, not `healthz`, `readyz` or `metrics` |
| `connections[].upstream` | required | Absolute https base URL; no query string |
| `connections[].host` | none | Also route requests for this `Host` to the connection, with no path prefix |
| `connections[].client_token_env` | top-level | A token for this connection only; the top-level tokens then do not open it |
| `connections[].client_auth` | `bearer` | `bearer`, `basic` (token as the password) or `header` |
| `connections[].client_auth_header` | none | Header name when `client_auth: header` |
| `connections[].methods` | `[GET, HEAD]` | Allowed methods |
| `connections[].paths` | any | RE2 patterns, each matched against the whole path after the prefix |
| `connections[].request_deny_patterns` | none | RE2 patterns; a match anywhere in the query or body, raw or URL-decoded, is refused |
| `connections[].request_headers` | none | Client headers to forward in addition to the defaults (Accept, Content-Type, User-Agent, conditional and MCP headers). Credentials, cookies and APIM trace headers are refused |
| `connections[].rate_limit` | none | `{requests_per_second, burst}` per pod |
| `connections[].response_fields` | none | JSON field allowlist; see Redaction |
| `connections[].mcp_tools` | none | Tools a `tools/call` may name; needs `POST` in `methods` |
| `connections[].headers` | none | Per-connection upstream headers, overriding the defaults |
| `connections[].upstream_basic_auth` | none | `{username_env, password_env}` injected as upstream Basic auth |
| `connections[].passthrough` | `false` | Skip redaction and fail-closed checks for this connection |
| `redaction.builtins` | default set | Built-in rules, in precedence order |
| `redaction.blocked_key_patterns` | none | RE2 patterns matched against JSON keys; every value under a matching key is masked |
| `redaction.custom[]` | none | `{name, regex}` value rules, applied after the builtins |
| `redaction.allowed_values` | none | RE2 patterns; a match is left unmasked when a pattern matches all of it |
| `redaction.mask` | `label` | `label` or `hmac` |
| `redaction.hmac_key_env` | `REDACTION_HMAC_KEY` | Env var holding the HMAC key when `mask: hmac` |

Validate before rolling out a ConfigMap change (v1 has no hot reload; restart
the pods). The check also prints the same warnings the pod logs at startup:

```bash
make check-config CONFIG=path/to/config.yaml
# or, with the real env: neubird-proxy -check -config config.yaml
```

## Responses the proxy generates

Connectors see these in addition to upstream responses. Upstream error
responses such as 4xx and 5xx pass through, and their bodies are redacted
too. Every response carries `X-Request-Id`.

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_path` | Path has a `.` or `..` segment, in any encoding |
| 400 | `upgrade_not_supported` | WebSocket or another protocol upgrade on a redacting connection |
| 401 | `unauthorized` | Missing or wrong token, a token scoped to another connection, or the token sent in the wrong form |
| 403 | `path_not_allowed` | Path not matched by `paths` |
| 403 | `request_denied` | Query or body matched `request_deny_patterns[i]` (the index is in `reason`), or a `tools/call` named a tool not in `mcp_tools` |
| 404 | `unknown_connection` | No connection matches the host or first path segment |
| 405 | `method_not_allowed` | Method not in `methods`; `Allow` lists the ones that are |
| 413 | `request_too_large` | Request body over `max_body_bytes` |
| 429 | `rate_limited` | Connection rate limit exceeded; `Retry-After: 1` |
| 502 | `redaction_blocked` | Fail closed; `reason` is one of `body_too_large`, `not_text`, `unsupported_content_type`, `unsupported_content_encoding`, `bad_gzip`, `partial_content`, `upgrade_not_supported`, `not_json` (with `response_fields`) |
| 502 | `upstream_unavailable` | Upstream unreachable or the request to it failed; the cause is logged, not returned |
| 503 | `overloaded` | `max_concurrent_requests` reached; `Retry-After: 1` |

## Operations

- **`:8443`** is the proxy, and the only port behind the load balancer.
  Optional in-pod TLS via `tls:`.
- **`:9090`** serves `/healthz`, `/readyz` and `/metrics`, cluster-internal
  only.
- **Startup** logs the config's SHA-256, so every ConfigMap change is visible
  in the logs. It also logs a warning for each passthrough connection, each
  connection without a paths allowlist, each connection allowing writes
  without deny patterns or `mcp_tools`, a plain-HTTP listener or one without
  mTLS, `allow_http_upstreams`, and a pending token rotation.
- **Audit:** one JSON line per request with `request_id`, connection,
  `remote_addr`, `forwarded_for` (as sent by the load balancer), method,
  path (itself redacted), `query_keys` (parameter names, never values),
  status, bytes, duration, per-rule match counts, and the block reason.
  Matched values and query values are never logged. Upstream errors log
  their cause, never the URL.
- **Metrics:** `neubird_proxy_requests_total{connection,code}`,
  `neubird_proxy_redactions_total{connection,rule}`,
  `neubird_proxy_blocked_total{connection,reason}`, and
  `neubird_proxy_response_bytes_total{connection}`.
- **Runtime:** stateless, no disk. Runs as two replicas with a read-only root
  filesystem, as non-root, with no capabilities.

### Capacity

These numbers come from `make bench` on one core (Apple M4 Max), using
Splunk-export-shaped data:

| Body | Throughput | 20 MiB body |
|---|---|---|
| Operational logs, no PII | 16 MB/s | ~1.3 s |
| PII in every event | 11 MB/s | ~1.9 s |

Peak heap is about 4.5× the body size, so 4 buffered 20 MiB bodies need about
360 MiB. That's why `max_concurrent_buffered` defaults to 4 against the
512 MiB memory limit. Raise both together. Redaction is single-threaded per
response; see the plan for the throughput work.

## Deploy

```bash
kubectl -n neubird create secret generic neubird-proxy \
  --from-literal=NEUBIRD_PROXY_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=NEUBIRD_PROXY_TOKEN_SERVICENOW="$(openssl rand -hex 32)" \
  --from-literal=APIM_SUBSCRIPTION_KEY=...
kubectl -n neubird create configmap neubird-proxy --from-file=config.yaml
kubectl apply -f deploy/kubernetes.yaml   # edit the CHANGE ME lines first
```

To rotate a token:
1. Add the new value as `NEUBIRD_PROXY_TOKEN` and move the old one to
   `NEUBIRD_PROXY_TOKEN_PREVIOUS`, with `client_token_previous_env` set, then
   restart.
2. Update NeuBird.
3. Remove the previous token and restart again.

## Supply chain

- Base images are pinned by digest in the `Dockerfile`, and the Go toolchain
  is pinned in `go.mod` (`toolchain go1.26.8`). `make vuln` runs
  `govulncheck` and must pass.
- CI (`.github/workflows/ci.yml`) runs lint, race tests, `govulncheck`, a
  fuzz pass, the example-config check, the image build, and the SBOM. Its
  actions are pinned by commit SHA.
- Dependencies are the Go standard library and `gopkg.in/yaml.v3`.
- Image signing and a MetLife-side build are in the plan.

## Develop

```bash
make test    # go test -race ./...
make lint
make vuln    # govulncheck
make fuzz    # FUZZTIME=5m for a longer run
make bench
make image   # distroless static, non-root
make sbom    # SPDX JSON via syft
go test ./internal/proxy -run Golden -update   # regenerate golden files, then review the diff
```

## Open questions (from the proposal)

For NeuBird engineering: do our Splunk, ServiceNow and MCP connectors accept a
base URL with a path prefix? Do they follow absolute URLs from responses? Where
does the proxy token go in each connector's UI? What is the largest expected
response body (this sets `max_body_bytes`)? Which exact endpoints and methods
does each connector call (this sets `paths` and `methods`)?

For MetLife: will ServiceNow be fronted by APIM? One subscription key or one per
API? What are the real member ID and PHI formats? Is regex-only detection
acceptable? What is the status of Cribl for Splunk?
