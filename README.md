# neubird-proxy

A redacting reverse proxy that MetLife runs in their AKS cluster between
NeuBird and MetLife's internal APIM endpoints. It limits what NeuBird can ask
for, and masks PII and secrets in every response before the data leaves
MetLife. Design: *MetLife Redaction Proxy: Engineering Proposal* (Sep 30,
2026). Open security work: [docs/security-plan.md](docs/security-plan.md).

**New here? Start with [docs/getting-started.md](docs/getting-started.md)**:
config, deploy, test and check the masking, in about an hour.

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

## Outbound tunnel (optional)

With a `tunnel:` section, the proxy connects *out* to NeuBird's relay, and
NeuBird's requests arrive over that connection. With `listen: "off"`,
nothing is exposed inbound at all.

What the customer needs on their network:
- **Outbound HTTPS** to `tunnel.neubird.ai:443`, nothing else. If they
  allowlist by IP rather than hostname, NeuBird publishes the relay's fixed
  IP addresses.
- **No TLS inspection** of that traffic. A corporate proxy that re-signs
  outbound HTTPS breaks mutual TLS. A plain HTTP proxy is fine: the tunnel
  uses `HTTPS_PROXY` with `CONNECT`.

Requests that arrive through the tunnel take exactly the same path as
inbound ones: token check, allowlists, redaction, and the audit line
(marked `via: tunnel`). The customer never uses NeuBird's per-tenant relay
hostnames (`<tenant>.relay.neubird.ai`); those are how NeuBird's own
connectors reach them, on NeuBird's side.
Protocol: [docs/tunnel-protocol.md](docs/tunnel-protocol.md). Design:
[docs/outbound-tunnel-design.md](docs/outbound-tunnel-design.md).

```yaml
listen: "off"                 # tunnel only: no inbound listener
tunnel:
  relays: [tunnel.neubird.ai:443]
  cert_file: /etc/neubird-proxy-tunnel/tls.crt      # signed by NeuBird
  key_file: /etc/neubird-proxy-tunnel/tls.key       # generated here, never sent
  ca_file: /etc/neubird-proxy-tunnel/relay-ca.crt   # pins NeuBird's relay CA
  connections_per_relay: 2    # two tunnels per pod, for faster failover
```

**Identity.** The certificate carries a SPIFFE ID, for example
`spiffe://neubird.ai/tenant/acme/proxy/aks-prod`. SPIFFE is an open
standard (CNCF) for naming workloads in certificates, the way a website
certificate names a domain. It tells the relay which customer (`acme`) and
which of their proxy deployments (`aks-prod`) is connecting.

**Getting the certificate.** The key is created here and never leaves:
1. Run `neubird-proxy csr -tenant <tenant> -proxy <name>`, with the tenant
   name NeuBird gives you. It writes `tunnel.key`, which stays with you, and
   `tunnel.csr`.
2. Send NeuBird the CSR. NeuBird signs it and returns the certificate and
   its relay CA certificate.
3. Put the key, certificate and relay CA in a Secret mounted at the paths
   above.
4. Generate the proxy token with `neubird-proxy token`, and give it to
   NeuBird through your usual secure channel.

Certificates last 90 days; the proxy warns from 30 days before expiry, and
renewal repeats these steps.

`validate` checks the files and shows the tunnel identity and certificate
expiry. `test` checks DNS, TCP and the mutual-TLS handshake to each relay.
`netpol` includes the relays in the egress rules.

**Behavior:**
- Each pod keeps `connections_per_relay` tunnels to every relay address.
- A dropped tunnel reconnects with exponential backoff (1 s to 60 s, with
  jitter).
- An outbound HTTP proxy from `HTTPS_PROXY` or `NO_PROXY` is used with
  `CONNECT`.
- Shutdown stops new requests and lets in-flight ones finish.
- Metrics: `neubird_proxy_tunnels{relay}` (connected now),
  `neubird_proxy_tunnel_connects_total{relay,result}`, and
  `neubird_proxy_tunnel_cert_expiry_days`.

## What NeuBird can reach

A request through the proxy can only reach URLs under a configured
connection's base URL, and with `paths` set, only the paths listed. Three
layers enforce this:

1. **The destination never comes from the request.** Each connection's
   upstream is a fixed base URL in the config. A request only picks a
   connection by name: the first path segment, or a configured `host:`. An
   unknown name gets `404 unknown_connection` and nothing is sent anywhere.
   A full URL in the request line, the `Host` header, or `X-Forwarded-Host`
   (stripped) never changes the host, port or scheme. So the proxy can't be
   used to reach other internal systems.
2. **A request can't leave its connection's base path.** The rest of the
   path is appended to the base URL. `.` and `..` segments are refused with
   `400 invalid_path`, including percent-encoded, double-encoded and
   backslash forms. Without that, `/splunk/../servicenow/` could be resolved
   by APIM into a different API. Upstream redirects (`Location`) are
   rewritten to point back through the proxy.
3. **`paths`, `methods` and `mcp_tools` restrict what's allowed within the
   connection.**
   - `paths` patterns must match the whole path after the prefix (they're
     anchored), or the request gets `403 path_not_allowed`.
   - `methods` defaults to GET and HEAD.
   - `mcp_tools` limits which tools a `tools/call` may name.

**Without `paths`, every URL under the base URL is reachable**, with the
allowed methods. Take a Splunk connection with base
`https://apim/splunk` and no `paths`: it can read any Splunk REST endpoint
behind that APIM route, not just search results. The pod logs a warning for
this at every start, and `neubird-proxy validate` shows it. Production
configs should list `paths` from an inventory of what each connector calls
(see the security plan, item 1).

**The network should enforce this too.** The proxy decides which paths,
methods and tools are allowed. Which hosts the pod can reach at all should
also be enforced below it, so a fault in one layer is still contained by
the other. See Kubernetes hardening.

## Redaction

- **JSON** is walked token by token, so key order and number precision
  survive. A body of several concatenated documents (Splunk export) streams
  one document at a time; see Latency and capacity.
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

For SSE and streamed JSON, the status line has already been sent. So an
event or document over the cap, or one that can't be redacted, cuts the
stream instead; the client sees a truncated read, and the audit line records
the reason (`sse_event_too_large`, `sse_not_text`, `json_doc_too_large`,
`json_stream_invalid`). Trailers are dropped from streamed responses too.

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
| `listen` | `:8443` | NeuBird-facing listener; `off` for tunnel only |
| `admin_listen` | `:9090` | Health and metrics listener |
| `tls.cert_file`, `tls.key_file` | none | Terminate TLS in the pod; both are required if `tls` is set |
| `tls.client_ca_file` | none | Require client certificates from this PEM CA bundle (mutual TLS) |
| `upstream_ca_file` | system roots | Extra PEM CA bundle to trust for upstreams |
| `allow_http_upstreams` | `false` | Allow `http://` upstreams; otherwise only `https://` is accepted |
| `client_token_env` | none | Env var with the default token, 32+ characters; required unless every connection sets its own |
| `client_token_previous_env` | none | Also accepted during a rotation; remove it afterwards |
| `max_body_bytes` | 20 MiB | Cap for request bodies, buffered response bodies, each SSE event and each streamed JSON document |
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
| `tunnel.relays` | none | Relay `host:port` addresses; setting `tunnel` enables the outbound tunnel |
| `tunnel.cert_file`, `tunnel.key_file` | required with `tunnel` | Tunnel client certificate (signed by NeuBird) and its key (from `neubird-proxy csr`) |
| `tunnel.ca_file` | required with `tunnel` | CA that signs the relays' certificates, pinned |
| `tunnel.connections_per_relay` | 1 | Tunnels each pod keeps to each relay (1 to 8) |
| `redaction.builtins` | default set | Built-in rules, in precedence order |
| `redaction.blocked_key_patterns` | none | RE2 patterns matched against JSON keys; every value under a matching key is masked |
| `redaction.custom[]` | none | `{name, regex}` value rules, applied after the builtins |
| `redaction.allowed_values` | none | RE2 patterns; a match is left unmasked when a pattern matches all of it |
| `redaction.mask` | `label` | `label` or `hmac` |
| `redaction.hmac_key_env` | `REDACTION_HMAC_KEY` | Env var holding the HMAC key when `mask: hmac` |

Validate before rolling out a ConfigMap change (v1 has no hot reload, so
restart the pods); see Tools.

## Tools

The proxy binary has subcommands for setting up and checking a deployment.
They're in the image too, so inside a pod they run with that pod's secrets
and network, and no credential has to be copied anywhere:

```bash
kubectl exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml
```

None of them prints a secret. Outside a pod, they read secrets from the
environment or from `-env-file secrets.env` (`KEY=VALUE` lines).

**`validate`: is this config right?** Runs every check the proxy runs at
startup and reports all problems in one go, with the field each is in. It
then summarizes each connection and prints the startup warnings. With
`-offline` it needs no secrets: missing variables get placeholders and are
listed.

```
$ neubird-proxy validate -offline -config config.yaml
VALID config.yaml

CONNECTION  UPSTREAM                                 AUTH    METHODS   PATHS  MCP TOOLS  FIELDS      MODE
splunk      https://int.apis.metlife.com/splunk      bearer  GET,POST  3      -          all         redact
servicenow  https://int.apis.metlife.com/servicenow  basic   GET,HEAD  2      -          14 allowed  redact
...
warnings:
  - tls is not set: the proxy listener is plain HTTP and relies on the load balancer for TLS
not checked (offline, placeholders used): APIM_SUBSCRIPTION_KEY, NEUBIRD_PROXY_TOKEN
```

**`test`: does each connection work?** (Output below is from the test
deployment, run in its pod.) Checks the network layer by layer
(DNS, TCP, TLS with the certificate and its expiry), so a failure names
where it broke. Then it sends a real request through the proxy's own
handler, as NeuBird would.
- **For MCP connections** it runs `initialize` and `tools/list`, and
  compares the server's tools with `mcp_tools`: which are allowed, which are
  blocked, and which are listed but not offered (a typo or a renamed tool).
- **For other connections** it sends a GET to the first plain path in
  `paths`, or `/`. Pick the probe with `-method`, `-path` and `-data`, and
  see the redacted body with `-show`.
- **Results** distinguish a refusal by the proxy's own policy from an
  upstream that rejects its credentials. The exit status is non-zero if any
  connection fails.

```
splunk -> https://splunk-e2e.tools.neubird.ai
  ok    dns        splunk-e2e.tools.neubird.ai -> 20.120.243.98
  ok    tcp        splunk-e2e.tools.neubird.ai:443 connected in 18ms
  ok    tls        TLS 1.3, certificate "*.tools.neubird.ai" from "Amazon RSA 2048 M01", expires in 106 days
  ok    initialize HTTP 200, application/json, 154 bytes, 172ms; redactions: none
  info  server     Splunk_MCP_Server 1.2.1, protocol 2025-06-18
  ok    tools/list HTTP 200, application/json, 7228 bytes, 325ms; redactions: none
  ok    tools      9 of 10 server tools allowed: splunk_get_index_info, splunk_get_indexes, ...
  info  tools      blocked by mcp_tools: splunk_run_saved_search

all 1 connections OK
```

**`preview`: what will NeuBird see?** Shows a response next to what NeuBird
would receive for it, line by line, with the rules that matched. The sample
goes through the proxy's real handler, so the output is exactly what
NeuBird gets, including a refusal (a binary body, say).
- **The sample** is a file, or with `-live` a response captured through the
  connection (`-path`, `-method`, `-data`).
- **`-html report.html`** writes a side-by-side report for a security
  review. `-html -` writes only the report to stdout, for
  `kubectl exec … > report.html`.
- **Both show the original data**, so treat the output as sensitive.

```
$ neubird-proxy preview -config config.yaml -connection servicenow sample.json
redactions: field_not_allowed 7, member_id 1
            (field_not_allowed: a field not in response_fields, masked whole as [REDACTED:FIELD] before any other rule)
legend:     - returned by the system   + received by NeuBird
    6 -       "short_description": "Member portal login fails for MET220019384",
      +       "short_description": "Member portal login fails for [REDACTED:MEMBER_ID]",
    7 -       "description": "Caller Dana Whitfield (dana.whitfield@example.org, 646-555-0192) ...",
      +       "description": "[REDACTED:FIELD]",
```

**`csr`** generates the tunnel's private key and a certificate signing
request for NeuBird to sign (see Outbound tunnel).

**`token`** prints a new random 64-character token:
`--from-literal=NEUBIRD_PROXY_TOKEN="$(neubird-proxy token)"`.

**`netpol`** generates egress rules that allow only the configured
upstreams: a CiliumNetworkPolicy, a NetworkPolicy, or a host list for a
firewall. See Kubernetes hardening.

**`metrics`** sums `/metrics` from one or more pods (URLs, files, or `-`)
into per-connection tables of requests by status, redactions by rule,
blocks by reason, and bytes:

```bash
for p in $(kubectl -n NS get pods -l app=neubird-proxy -o name); do
  kubectl get --raw /api/v1/namespaces/NS/${p/pod\//pods/}:9090/proxy/metrics
done | neubird-proxy metrics -
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

### Latency and capacity

**Single-document JSON** (ServiceNow and most APIs), and any body with a
declared `Content-Length` that holds one document, is redacted whole before
the first byte is sent. It keeps an exact `Content-Length`, and a failure is
a clean 502.

**Multi-document JSON with no declared length** (Splunk export) streams.
- Each document is redacted and sent as soon as it arrives, batched with any
  others already received, and each is followed by a newline.
- The first byte leaves as soon as the first result is redacted, and memory
  is bounded by the largest document, not the body.
- `max_body_bytes` caps each document, not the whole stream.
- If a later document is over the cap or isn't valid JSON, the stream is
  cut, because a 502 can no longer be sent. The audit line records
  `json_doc_too_large` or `json_stream_invalid`.

Measured end to end through the proxy on one core (Apple M4 Max), for a
Splunk export of 50,000 results (about 18 MB). Medians of 3–7 runs:

| Upstream | Proxy mode | First byte | Total | Added by proxy |
|---|---|---|---|---|
| Sends all at once | buffered (before streaming) | ~1.05–1.55 s | ~1.05–1.55 s | ~1.05–1.55 s |
| Sends all at once | streaming | 0.2 ms | ~1.2–1.7 s | ~1.2–1.7 s |
| Paced over ~2.4 s, like a running search | buffered (before streaming) | 3.4–4.1 s | 3.4–4.1 s | 1.1–1.6 s |
| Paced over ~2.4 s, like a running search | streaming | ~1 ms | ~2.1 s | within noise |

Ranges run from operational logs with no PII to PII in every event.
- **Redaction speed:** 11–16 MB/s (`make bench`), about 20–35 ms per 1,000
  Splunk results.
- **When Splunk is slower than that** (the usual case, because the search is
  still running), streaming hides the redaction entirely.
- **When a whole export is already sitting in Splunk,** streaming costs
  about 10–15% more total time than buffering did, in exchange for an
  immediate first byte.

Peak heap for a buffered body is about 4.5× its size, so 4 buffered 20 MiB
bodies need about 360 MiB. That's why `max_concurrent_buffered` defaults to 4
against the 512 MiB memory limit. Raise both together. Streamed responses
hold one document at a time and count against the cap only while their first
document is decoded. Redaction is single-threaded per response; see the plan
for the throughput work.

## Kubernetes hardening

`deploy/kubernetes.yaml` enforces these at the cluster level, independently
of the proxy's own checks:

| Control | What it enforces |
|---|---|
| Own namespace, Pod Security `restricted` | The cluster rejects any pod there that runs as root, escalates privileges, keeps Linux capabilities, mounts host paths or skips seccomp |
| Pod security context | Non-root user 65532, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp |
| Service account | A dedicated one with no Role bindings, and its token isn't mounted: the proxy can't talk to the Kubernetes API |
| `default-deny` NetworkPolicy | Nothing in the namespace sends or receives traffic unless another policy allows it |
| `neubird-proxy` NetworkPolicy | In: the proxy port from the load balancer's range only, the admin port (health, metrics) from monitoring only. Out: the APIM range on 443, plus DNS |
| Resources | A 512 MiB memory limit, matched to `max_concurrent_buffered` (see Latency and capacity) |

**Restricting egress by hostname.** A standard NetworkPolicy matches IP
ranges and ports, not hostnames. The policy above allows the APIM CIDR,
which may be wider than the hosts the proxy needs. To allow exactly the
configured upstream hosts, generate the rules from the config:

```bash
neubird-proxy netpol -config config.yaml -namespace neubird                    # CiliumNetworkPolicy (default)
neubird-proxy netpol -config config.yaml -namespace neubird -format kubernetes # NetworkPolicy with the hosts' current IPs
neubird-proxy netpol -config config.yaml -format list                          # host:port lines for a firewall
```

- **Cilium**, including Azure CNI powered by Cilium: the generated policy
  allows only the upstream hostnames and ports. It also lets the pod
  *resolve* only those names, so a lookup of anything else fails.
- **No FQDN-aware CNI:** `-format kubernetes` resolves the hosts now and
  allows their current addresses. That suits a private APIM endpoint with
  stable IPs. Regenerate it when they change; for anything behind a CDN,
  use hostname rules instead.
- **Azure Firewall application rules, AWS Network Firewall, or Route 53
  Resolver DNS Firewall:** `-format list` prints what to allow.

Regenerate the policy whenever connections change, so the network and the
proxy agree on what's reachable.

**Paths stay with the proxy.** The upstreams are HTTPS, so the network
can't see request paths without breaking TLS to inspect it. So the network
enforces which hosts the pod can reach, and the proxy enforces which paths,
methods and MCP tools are allowed on them (see What NeuBird can reach).
Either layer still contains the other if one is misconfigured.

**Image admission.** Deploy by digest, not tag. Enforce signed images, or
images from MetLife's own registry, with their admission policy (for
example Kyverno, Gatekeeper, or Azure Policy for AKS); see the security
plan, item 5.

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
- Dependencies are the Go standard library, `gopkg.in/yaml.v3`, and
  `golang.org/x/net` (from the Go team; HTTP/2 and outbound proxy settings
  for the tunnel).
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
