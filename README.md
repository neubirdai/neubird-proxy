# neubird-proxy

A redacting reverse proxy that MetLife runs in their AKS cluster between
NeuBird and MetLife's internal systems. It limits which systems NeuBird can
reach and what it can send them, and masks PII and secrets in every
response before the data leaves MetLife. Design: *MetLife Redaction Proxy:
Engineering Proposal* (Sep 30, 2026). Open security work:
[docs/security-plan.md](docs/security-plan.md).

**New here? Start with [the getting started guide](deploy/helm/neubird-proxy/docs/getting-started.md)**:
config, check the masking, install with Helm, connect, in about an hour.
Customers get everything they need inside the Helm chart
([`deploy/helm/neubird-proxy`](deploy/helm/neubird-proxy)): its README, the
guide, and the [configuration reference](deploy/helm/neubird-proxy/docs/configuration.md).

```
NeuBird ──▶ relay ⇄ tunnel (opened by the proxy, :443) ⇄ neubird-proxy ──▶ Splunk / Maestro / ServiceNow / APIM
             (the system's credentials)                    │ checks the host, request rules; redacts responses
```

MetLife sets once which hosts NeuBird may reach (`neubird_destinations`).
Systems are then added, changed and removed in NeuBird, each as a
connection with its own URL and credentials, with no change to the proxy.

## What a request goes through

NeuBird sends each request to `/_neubird/dest/<path>`, naming the system
in `X-Neubird-Destination: https://host[:port]` (the endpoint URL of its
connection). In order; the first check that fails ends the request.

1. **Capacity.** Beyond `max_concurrent_requests` in flight, the proxy returns 503.
2. **Path hygiene.** Paths with `.` or `..` segments (including
   percent-encoded, double-encoded, backslash and `..;` forms) get a 400,
   so a path can't be normalized upstream into a different API.
3. **Token.** A tunnel-only proxy (`listen: "off"`, the chart's mode
   `tunnel`) uses `client_auth: none`, the chart's default there: every
   request arrives over the mutually authenticated tunnel the proxy opened
   to its relay, and no token is checked; NeuBird sends none. A proxy with
   an inbound listener always needs a token, in the form `client_auth` sets
   (a Bearer token, a Basic password, or a named header); tokens shorter
   than 32 characters are refused at startup.
4. **Destination.** The host must match `neubird_destinations.hosts`, or the
   request gets `403 destination_not_allowed`. This is checked after the
   token, so a caller without it learns nothing about the hosts.
5. **Method allowlist.** GET and HEAD only, unless `methods` lists more
   (`"*"`: GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS; never CONNECT or TRACE).
   Anything else gets a 405.
6. **Rate limit.** Per pod, shared by every host, when `rate_limit` is set;
   over the limit gets a 429.
7. **Request checks.** The query string and body are checked raw,
   URL-decoded (leniently, so one malformed escape doesn't hide the rest),
   and with JSON string escapes decoded, against `request_deny_patterns`,
   for example Splunk commands that write or send data. A match gets a 403.
   The patterns are a blocklist: they catch what they name, in the
   encodings above.
8. **Headers.** Only allowlisted client headers go upstream. This drops the
   proxy token, cookies, `Ocp-Apim-Trace`, and `Accept-Encoding`/`Range`
   (bodies must arrive whole and uncompressed). The system's credentials
   arrive as `X-Neubird-Upstream-<Header>` and are forwarded as `<Header>`
   (any header by default; only those listed if `credential_headers` lists
   some). The proxy adds an
   `X-Request-Id`.
9. **Connect.** Connections to loopback, link-local (including
   `169.254.169.254`), unspecified and multicast addresses, other cloud
   metadata addresses (`168.63.129.16`, `100.100.100.200`,
   `fd00:ec2::254`) and the pod's own addresses are refused, whatever the
   name resolved to.
10. **Response.**
    - Stripped: `Set-Cookie`, all `Ocp-Apim-*` headers, and trailers.
    - Dropped: 1xx informational responses such as 103 Early Hints, whose
      headers would otherwise reach the client before redaction runs.
    - Redirects to the same host: rewritten to point back through the
      proxy. The proxy never follows a redirect itself.
    - Redacted: every remaining header value, then the body.
    - Refused if it can't be redacted (see Fail closed).

## Outbound tunnel

The proxy connects *out* to NeuBird's relay, and NeuBird's requests arrive
over that connection; with `listen: "off"`, nothing is exposed inbound at
all. The Helm chart always deploys it this way: it adds the `tunnel`
section and `listen: "off"` itself.

What the customer needs on their network:
- **Outbound HTTPS** to their own relay, `<tenant>.tunnel.neubird.ai:443`.
  Each customer has a dedicated relay; if they allowlist by IP rather than
  hostname, NeuBird gives them its fixed IP addresses.
- **No TLS inspection** of that traffic. A corporate proxy that re-signs
  outbound HTTPS breaks mutual TLS. A plain HTTP proxy is fine: the tunnel
  uses `HTTPS_PROXY` with `CONNECT`.

Requests that arrive through the tunnel get every check above and the
audit line (marked `via: tunnel`). On NeuBird's side, the relay runs in the
NeuBird tenant's own namespace and only that tenant's ace can call it.
Protocol: [docs/tunnel-protocol.md](docs/tunnel-protocol.md). Design:
[docs/outbound-tunnel-design.md](docs/outbound-tunnel-design.md).

```yaml
listen: "off"                 # tunnel only: no inbound listener
tunnel:
  relays: [acme.tunnel.neubird.ai:443]   # the customer's dedicated relay
  tenant: acme                  # names NeuBird gives you
  proxy: aks-prod
  key_file: /etc/neubird-proxy-tunnel/tunnel.key    # made here (keygen), never sent
  ca_file: /etc/neubird-proxy-tunnel/relay-ca.crt   # pins NeuBird's relay CA
  connections_per_relay: 2    # two tunnels per pod, for faster failover
  join_token_env: NEUBIRD_JOIN_TOKEN   # optional: enroll the key with a join token
```

**Identity.** The proxy has its own key and NeuBird records the key's
fingerprint; nothing is signed. On every connect the proxy mints a
short-lived self-signed certificate from the key. The relay accepts the
connection only if the key is recorded, and takes the customer (`acme`) and
proxy (`aks-prod`) from that record, so the proxy needs no name of its own;
on its first connect the join token's record names it. A proxy may still
name itself with a SPIFFE ID (`tunnel.tenant`, `tunnel.proxy`), for example
`spiffe://neubird.ai/tenant/acme/proxy/aks-prod`; the records must then
agree. SPIFFE is an open standard (CNCF) for naming workloads in
certificates, the way a website certificate names a domain.

**Setting it up.** The key is created here and never leaves. There are two
ways for NeuBird to learn it.

With a join token (what the Helm chart does by default):
1. NeuBird sends you your relay's hostname, its relay CA certificate, and
   a join token for your tenant and proxy name (`nbjt_…`, single use, with
   an expiry).
2. Put the token in the environment variable named by
   `tunnel.join_token_env`. The chart generates the key in a Secret.
3. On its first connect, the proxy presents the token and the relay records
   the key (`enrolled with the join token` in the log). Restarts and other
   replicas with the same key get `key already enrolled`. Once enrolled, the
   token can be removed.

With the fingerprint:
1. Run `neubird-proxy keygen -tenant <tenant> -proxy <name>`, with the
   tenant name NeuBird gives you. It writes `tunnel.key`, which stays with
   you, and prints its fingerprint (`sha256:…`).
2. Send NeuBird the fingerprint; it isn't secret. NeuBird records it and
   returns its relay CA certificate and your relay's hostname.
3. Put the key and relay CA in a Secret mounted at the paths above.

A tunnel-only proxy needs no proxy token (`client_auth: none`). A proxy
with an inbound listener needs one: generate it with `neubird-proxy token`
and give it to whatever calls the proxy (your gateway).

Nothing expires: the proxy re-mints its certificate on every connect.
To rotate the key, run `keygen` again, send NeuBird the new fingerprint,
and update the Secret: no restart (the proxy's log says
`tunnel key, certificate or relay CA reloaded`), and NeuBird then retires
the old key, moving the tunnels over without failing any request.
`neubird-proxy fingerprint <file>` prints a key's or certificate's
fingerprint. A proxy set up with a NeuBird-signed certificate can keep it
(`tunnel.cert_file`): NeuBird records its key's fingerprint the same way.

`validate` checks the files and shows the tunnel identity, certificate
expiry, and whether a join token is set. `test` checks DNS, TCP and the
mutual-TLS handshake to each relay. `netpol` includes the relays in the
egress rules.

**Behavior:**
- Each pod keeps `connections_per_relay` tunnels to every relay address.
- A dropped tunnel reconnects with exponential backoff (1 s to 15 s, with
  jitter).
- An outbound HTTP proxy from `HTTPS_PROXY` or `NO_PROXY` is used with
  `CONNECT`.
- Shutdown stops new requests and lets in-flight ones finish.
- Metrics: `neubird_proxy_tunnels{relay}` (connected now),
  `neubird_proxy_tunnel_connects_total{relay,result}`, and
  `neubird_proxy_tunnel_cert_expiry_days`.

## What NeuBird can reach

NeuBird names the host of every request, so the host patterns are the
boundary:

```yaml
neubird_destinations:
  hosts: ["*.apis.metlife.com", "maestro.corp.metlife.com"]   # optional; omitted means "*"
  methods: [GET, HEAD, POST]       # for every host (default GET, HEAD)
  request_deny_patterns: [...]     # optional
  rate_limit: {requests_per_second: 10, burst: 30}   # optional, shared
```

- **Patterns.** `*.example.com` matches any name under that domain (it
  needs two or more labels), `host` matches exactly, and either may end in
  `:port`. `*` matches any host name. An IP address is reached only when
  listed exactly: wildcards never match IP literals.
- **`hosts` is optional.** Without it, NeuBird may reach any host name the
  pod can, and the other guard rails still apply. Every pod start warns
  about the hosts NeuBird may reach, and loudly when `*` is listed.
- **Never the pod or the cloud's metadata.** Connections to loopback,
  link-local (including `169.254.169.254`), unspecified and multicast
  addresses, `168.63.129.16`, `100.100.100.200`, `fd00:ec2::254` and the
  pod's own addresses are refused, whatever the name resolved to. Other
  private addresses are allowed: the systems usually live there, so with
  `*` (or no `hosts`) NeuBird can reach any internal system the pod can,
  including through a DNS name it controls. Keep `hosts` to your domains,
  and restrict egress at the network.
- **Behind an outbound proxy** (`HTTPS_PROXY`), the outbound proxy
  resolves and dials the hosts, so the address check above only sees the
  outbound proxy; the proxy warns at startup. Put the systems in
  `NO_PROXY`, or rely on `hosts` and the network.
- **The destination is `scheme://host[:port]` only**, with no user info,
  path or query; `https` unless `allow_http_upstreams` is set.
- **A request stays on its host.** `.` and `..` segments are refused, and
  the proxy never follows a redirect: a same-host redirect is rewritten to
  come back through the proxy, where it's checked again.
- **Methods and request rules apply to every host.** Paths aren't
  restricted per host: within an allowed host and method, any path is
  reachable.

**The network should enforce the hosts too.** The proxy decides which hosts
it will forward to; which hosts the pod can reach at all should also be
enforced below it, so a fault in one layer is still contained by the other.
See Kubernetes hardening.

## Credentials

Who holds what, and what NeuBird sees:

| Credential | Held by | NeuBird sees it |
|---|---|---|
| The systems' credentials (API tokens, OAuth tokens, APIM subscription keys) | NeuBird, in each of its connections | Yes: it sends them with each request |
| Proxy token (`client_token_env`) | Both: the customer generates it (`neubird-proxy token`) and gives it to NeuBird | Yes. The proxy checks it and removes it; it never reaches a system |
| Tunnel key | The customer; made in the cluster, never sent | No; only its public fingerprint. Guard it like the proxy token: whoever holds it can open a tunnel as this proxy and receive a share of NeuBird's requests, with the proxy token and the systems' credentials in them |
| Join token | Issued by NeuBird, used once by the proxy | Yes (NeuBird issued it); the relay keeps only its hash |
| `REDACTION_HMAC_KEY` | The customer | No |

NeuBird also knows the systems' hostnames: they're the URLs of its
connections, and every request names one.

How the proxy handles the systems' credentials:
- **Only as credential headers.** NeuBird sends them as
  `X-Neubird-Upstream-<Header>` and the proxy forwards them as `<Header>`:
  any header by default (`credential_headers: ["*"]`, like `hosts`), or
  only those you list. `Host`, `Cookie`, `X-Forwarded-*`, `X-Neubird-*`,
  APIM trace headers and transport headers are never forwarded, whatever
  the setting.
- **Only to allowed hosts.** A credential goes only to the host the request
  names, after the host check. The proxy never follows a redirect, so it
  never carries a credential to another host.
- **Nothing echoes or logs them.** `Set-Cookie` and `Ocp-Apim-*` response
  headers are stripped, secrets that appear in response bodies are masked
  by the secret rules (see Rules), and the audit line holds no credentials,
  query values or header values other than the sanitized `X-Forwarded-For`.
- **Proxy values only from the environment.** Every `*_env` field and
  `${VAR}` resolves from the pod's environment; the config file holds
  names, never values.

## Status API

`GET /_neubird/status` with `Authorization: Bearer <proxy token>` tells
NeuBird how to send requests: how the token is sent (`client_auth`) and
which credential headers the proxy forwards. Nothing about hosts or
secrets. Any other token gets a 401. With `client_auth: none` it answers
without a token and reports `"client_auth": "none"`, so NeuBird sends none.

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
  `event:` and `id:` lines, and each event is flushed immediately. A
  `retry:` line passes only as a number.
- **Gzip** is decoded.
- **Field allowlist.** With `response_fields`, only the listed JSON fields
  leave unmasked, in every host's responses. Every other string or number becomes `[REDACTED:FIELD]`,
  whatever it contains, and allowed fields still get every rule. A response
  that isn't JSON is refused (`not_json`), because the allowlist can't be
  checked. For SSE, a data payload that isn't JSON is masked whole. Patterns
  are dot paths of keys, where `*` matches any one key. Array elements add
  no segment, so `result.number` covers every element of a `result` array.
  A pattern allows everything beneath it. Object keys that aren't on a
  pattern's path are masked too, since a query can turn values into keys
  (`chart … by name`); keys at a `*` position pass as they are. Under an
  allowlist, SSE comment and unknown lines are dropped, `id:` values and
  event names that aren't short names are masked.
- **Before matching**, text is normalized: percent-escapes (`%40`), HTML
  entities (`&#64;`, `&commat;`), full-width characters (`２１９`), other
  scripts' digits (`٢١٩`, `𝟐𝟏𝟗`), and invisible characters (zero-width
  space, soft hyphen, bidi marks, variation selectors) are decoded or
  removed, in values and in JSON keys. URL credentials and `password=`-style
  values are also matched as written, so an encoded `%40` or `%2F` in a
  password doesn't end the match. A leading BOM doesn't stop a JSON body or
  SSE stream from being read as one. The mask replaces the original bytes.

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

For free text, use `neubird_destinations.response_fields`: fields nobody
approved never leave in the clear. The fields that must pass as free text, like Splunk `_raw` and
MCP tool output, still depend on the rules, and NER is the remaining gap
there; see the plan.

To measure the rules on your own data without sending it anywhere:

```bash
neubird-proxy -config config.yaml -redact sample.json > redacted.json   # counts per rule on stderr
```

`-redact` reads only the `redaction` section, so it needs no secrets.

## Config

See [`deploy/config.example.yaml`](deploy/config.example.yaml), a complete
example for the tunnel. Secrets never appear in the file. Every `*_env` field and
every `${VAR}` must resolve to a non-empty environment variable, or the proxy
refuses to start. Unknown YAML fields are errors.

| Field | Default | Meaning |
|---|---|---|
| `listen` | `:8443` | Inbound listener; `off` for tunnel only (what the Helm chart sets) |
| `admin_listen` | `:9090` | Health and metrics listener |
| `tls.cert_file`, `tls.key_file`, `tls.client_ca_file` | none | TLS, and optionally client certificates, on the inbound listener. Re-read every minute: a renewed certificate or CA takes effect without a restart, and files that stop loading keep the previous ones |
| `upstream_ca_file` | system roots | Extra PEM CA bundle to trust for the systems |
| `allow_http_upstreams` | `false` | Allow `http://` destinations; otherwise only `https://` |
| `client_token_env` | none | Env var with the proxy token, 32+ characters |
| `client_token_previous_env` | none | Also accepted during a rotation; remove it afterwards |
| `max_body_bytes` | 20 MiB | Cap for request bodies, buffered response bodies, each SSE event and each streamed JSON document |
| `max_concurrent_requests` | 256 | In-flight requests before the proxy returns 503 |
| `max_concurrent_buffered` | 4 | Response bodies buffered for redaction at once; others wait |
| `neubird_destinations.hosts` | `["*"]` | Host patterns NeuBird may name: `*`, `*.domain`, `host`, or an exact IP; each may end in `:port` |
| `neubird_destinations.methods` | `[GET, HEAD]` | Allowed methods, for every host; `"*"` is GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS |
| `neubird_destinations.request_deny_patterns` | none | RE2 patterns; a match anywhere in the query or body, raw or URL-decoded, is refused |
| `neubird_destinations.credential_headers` | `["*"]` | Headers NeuBird may set for the system, as `X-Neubird-Upstream-<Header>`: `"*"` is any header except those never allowed (`Host`, `Cookie`, `X-Forwarded-*`, `X-Neubird-*`, APIM trace and transport headers); a list allows only those |
| `neubird_destinations.request_headers` | none | Client headers to forward in addition to the defaults (Accept, Content-Type, User-Agent, conditional and MCP headers). Credentials, cookies and APIM trace headers are refused |
| `neubird_destinations.rate_limit` | none | `{requests_per_second, burst}` per pod, shared by every host |
| `neubird_destinations.response_fields` | none | JSON field allowlist for every host's responses; see Redaction |
| `neubird_destinations.client_auth` | `bearer` | How the proxy token is sent: `bearer`, `basic` (as the password) or `header`; or `none` on a tunnel-only proxy (`listen: "off"`): no token, and `client_token_env` isn't needed |
| `neubird_destinations.client_auth_header` | none | Header name when `client_auth: header` |
| `neubird_destinations.client_token_env` | top-level | A token for this section instead of the top-level one |
| `tunnel.relays` | none | Relay `host:port` addresses; setting `tunnel` enables the outbound tunnel |
| `tunnel.tenant`, `tunnel.proxy` | no (both or neither) | Optional: the relay names the proxy from its records, by key (by the join token's record on first connect). Set, the minted certificate names them and the records must agree |
| `tunnel.key_file` | required with `tunnel` | The tunnel key, from `neubird-proxy keygen`; NeuBird records its fingerprint |
| `tunnel.cert_file` | none | A certificate for the key to present instead of minting one |
| `tunnel.ca_file` | required with `tunnel` | CA that signs the relays' certificates, pinned |
| `tunnel.connections_per_relay` | 1 | Tunnels each pod keeps to each relay (1 to 8) |
| `tunnel.join_token_env` | none | Env var with a join token from NeuBird; the proxy enrolls its key with it on first connect. Unlike other `*_env` fields it may be unset or empty |
| `redaction.builtins` | default set | Built-in rules, in precedence order |
| `redaction.blocked_key_patterns` | none | RE2 patterns matched against JSON keys; every value under a matching key is masked |
| `redaction.custom[]` | none | `{name, regex}` value rules, applied after the builtins |
| `redaction.allowed_values` | none | RE2 patterns; a match is left unmasked when a pattern matches all of it |
| `redaction.mask` | `label` | `label` or `hmac` |
| `redaction.hmac_key_env` | `REDACTION_HMAC_KEY` | Env var holding the HMAC key when `mask: hmac`; at least 32 characters (`neubird-proxy token` makes one) |

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
then summarizes the config and prints the startup warnings. With
`-offline` it needs no secrets: missing variables get placeholders and are
listed.

```
$ neubird-proxy validate -offline -tunnel -config config.yaml
VALID config.yaml

CONNECTION            UPSTREAM                                     AUTH  METHODS        PATHS  MCP TOOLS  FIELDS  MODE
neubird_destinations  *.apis.metlife.com,maestro.corp.metlife.com  none  GET,HEAD,POST  any    -          all     NeuBird credentials
...
tunnel: 1 relay(s) x 1 connection(s), no inbound listener
  tunnel section added as the Helm chart adds it (relay, tenant and key come from its values)

warnings:
  - neubird_destinations: client_auth: none: requests from the NeuBird relay need no proxy token; cut NeuBird off by scaling to 0 or by NeuBird revoking the tunnel key
  - neubird_destinations: NeuBird chooses the destination host within *.apis.metlife.com, maestro.corp.metlife.com and supplies the credentials
```

**`test`: can the proxy reach the relay and the systems?** Without
arguments it checks the tunnel to each relay: the identity, DNS, and the
mutual-TLS handshake. Given a system's URL, it checks that `hosts` allows
it, then DNS, TCP and TLS (with the certificate and its expiry), so a
failure names where it broke. It sends no request to the system: the
credentials are NeuBird's. The exit status is non-zero if any check fails.

```
$ neubird-proxy test -config config.yaml https://splunk.apis.metlife.com
https://splunk.apis.metlife.com -> neubird_destinations
  ok    hosts      allowed by neubird_destinations.hosts
  ok    dns        splunk.apis.metlife.com -> 10.20.30.40
  ok    tcp        splunk.apis.metlife.com:443 connected in 18ms
  ok    tls        TLS 1.3, certificate "*.apis.metlife.com" from "MetLife Issuing CA", expires in 106 days

all 1 destinations OK
```

**`preview`: what will NeuBird see?** Shows a response next to what NeuBird
would receive for it, line by line, with the rules that matched. The sample
goes through the proxy's real handler, so the output is exactly what
NeuBird gets, including a refusal (a binary body, say).
- **The sample** is a file: save a typical response from a system.
- **`-html report.html`** writes a side-by-side report for a security
  review. `-html -` writes only the report to stdout, for
  `kubectl exec … > report.html`.
- **Both show the original data**, so treat the output as sensitive.

```
$ neubird-proxy preview -config config.yaml sample.json
redactions: field_not_allowed 1, member_id 1
            (field_not_allowed: a field not in response_fields, masked whole as [REDACTED:FIELD] before any other rule)
legend:     - returned by the system   + received by NeuBird
    8 -       "short_description": "Member portal login fails for MET220019384",
      +       "short_description": "Member portal login fails for [REDACTED:MEMBER_ID]",
    9 -       "description": "Caller Dana Whitfield (dana.whitfield@example.org, 646-555-0192) ...",
      +       "description": "[REDACTED:FIELD]",
```

**`keygen`** makes the tunnel's private key and prints its fingerprint for
NeuBird to record (see Outbound tunnel). **`fingerprint <file>`** prints the
fingerprint of a key or certificate.

**`token`** prints a new random 64-character token: a proxy token for an
inbound listener, or an HMAC key (`REDACTION_HMAC_KEY`).

**`netpol`** generates egress rules that allow only the relay and the
hosts in `neubird_destinations.hosts`: a CiliumNetworkPolicy, a
NetworkPolicy, or a host list for a firewall. See Kubernetes hardening.

**`metrics`** sums `/metrics` from one or more pods (URLs, files, or `-`)
into tables of requests by status, redactions by rule, blocks by reason,
and bytes:

```bash
for p in $(kubectl -n NS get pods -l app=neubird-proxy -o name); do
  kubectl get --raw /api/v1/namespaces/NS/${p/pod\//pods/}:9090/proxy/metrics
done | neubird-proxy metrics -
```

## Responses the proxy generates

Connectors see these in addition to upstream responses. Upstream error
responses such as 4xx and 5xx pass through, and their bodies are redacted
too. Every response past the token check carries `X-Request-Id` (a 401
has none, so it can't tell names apart): the caller's own if it sent a
short plain one (the relay always does, so one ID follows a request through
the relay's log, the audit line and the system), otherwise a new one.

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_path` | Path has a `.` or `..` segment, in any encoding |
| 400 | `upgrade_not_supported` | WebSocket or another protocol upgrade |
| 401 | `unauthorized` | Missing or wrong proxy token, or the token sent in the wrong form |
| 403 | `destination_not_allowed` | `X-Neubird-Destination` missing, not `scheme://host[:port]`, plain `http` without `allow_http_upstreams`, or a host not in `hosts` (checked after the token) |
| 403 | `request_denied` | Query or body matched `request_deny_patterns[i]` (the index is in `reason`) |
| 404 | `unknown_connection` | The path isn't under `/_neubird/dest`, with a valid token (without one, 401) |
| 405 | `method_not_allowed` | Method not in `methods`; `Allow` lists the ones that are |
| 413 | `request_too_large` | Request body over `max_body_bytes` |
| 429 | `rate_limited` | Rate limit exceeded; `Retry-After: 1` |
| 502 | `redaction_blocked` | Fail closed; `reason` is one of `body_too_large`, `not_text`, `unsupported_content_type`, `unsupported_content_encoding`, `bad_gzip`, `partial_content`, `upgrade_not_supported`, `not_json` (with `response_fields`) |
| 502 | `upstream_unavailable` | The system is unreachable, refused as an internal address, or the request to it failed; the cause is logged, not returned |
| 503 | `overloaded` | `max_concurrent_requests` reached; `Retry-After: 1` |

## Operations

- **Tunnel only** (the Helm chart): no proxy port at all; requests arrive
  over the outbound tunnel.
- **`:9090`** serves `/healthz`, `/readyz` and `/metrics` without auth. It
  has no Service; the chart's NetworkPolicy (`networkPolicy.enabled`) limits
  it to `metricsFrom`.
- **Startup** logs the config's SHA-256, so every ConfigMap change is visible
  in the logs. It also logs a warning naming the hosts NeuBird may reach
  (and another when `hosts` includes `*`), `allow_http_upstreams`, and a
  pending token rotation.
- **Audit:** one JSON line per request with `request_id`, `destination`
  (the system's `scheme://host[:port]`), `via: tunnel`, `remote_addr`,
  method, path (itself redacted), `query_keys` (parameter names, never
  values), status, bytes, duration, per-rule match counts, and the block
  reason. Credentials, matched values and query values are never logged.
  Upstream errors log their cause, never the URL.
- **Metrics:** `neubird_proxy_requests_total{connection,code}`,
  `neubird_proxy_redactions_total{connection,rule}`,
  `neubird_proxy_blocked_total{connection,reason}`,
  `neubird_proxy_response_bytes_total{connection}`, and, with `tls`,
  `neubird_proxy_tls_cert_expiry_days`, where `connection` is
  `_destinations` for requests to the systems (labels never carry hosts, so
  NeuBird can't grow them).
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
- The upstream gets a minute to send a buffered body, or each document or
  event of a stream once it has started; otherwise the response is cut. A
  stream may idle as long as it likes between documents and events.

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

Redacting a buffered body takes 5–11× its size in memory, and up to about
16× for adversarial bodies (measured; JSON held in strings and
entity-heavy text are the worst cases). So memory is budgeted, not just
counted:
- At startup the proxy reads its container's memory limit, sets the Go
  runtime's to 90% of it (unless `GOMEMLIMIT` is set), and lets buffered
  bodies take three quarters of it together.
- Each buffered body reserves 20× its size (26× with `mask: hmac`, whose
  masks are longer) (its `Content-Length`, or
  `max_body_bytes` if it has none) and waits if there isn't room. Small API
  and MCP responses run side by side; large ones take turns.
- If one body of `max_body_bytes` couldn't fit even alone, bodies are capped
  lower to fit, and larger ones fail closed with `body_too_large`. The
  startup log says so. With the 512 MiB limit the cap is about 19.2 MiB,
  just under the 20 MiB default (14.8 MiB with `mask: hmac`); at 256 MiB it
  would be about 9.6 MiB (7.4 MiB).
- A body over the cap is refused as soon as the proxy has read past the
  cap, not after decoding it.
- `max_concurrent_buffered` (default 4) still limits how many are buffered at
  once. A streamed response holds a slot only while its first document is
  decoded; later documents and SSE events (and the input buffered while
  one arrives) reserve memory from the same budget while they're
  processed. Request bodies that are checked have their own budget, an
  eighth of the memory limit, held until the response is done; request
  bodies are capped to fit it (a fifth of that budget, 12.8 MiB at 512 MiB). Redaction is single-threaded per response; see the plan
for the throughput work.

## Kubernetes hardening

The Helm chart ([`deploy/helm/neubird-proxy`](deploy/helm/neubird-proxy),
the only supported way to deploy) enforces these at the cluster level,
independently of the proxy's own checks:

| Control | What it enforces |
|---|---|
| Own namespace, Pod Security `restricted` | The customer labels the namespace; the chart's pods meet `restricted`, so the cluster rejects any pod there that runs as root, escalates privileges, keeps Linux capabilities, mounts host paths or skips seccomp |
| Pod security context | Non-root user 65532, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp. The user and `allowPrivilegeEscalation: false` are set on each container too, for admission policies (OPA Gatekeeper) that check every container's own `securityContext` |
| Service account | A dedicated one with no Role bindings, and its token isn't mounted: the proxy can't talk to the Kubernetes API |
| No inbound port | Tunnel-only: the proxy dials out to the relay; nothing connects in |
| NetworkPolicy (`networkPolicy.enabled`) | In: only the admin port, from `metricsFrom`. Out: DNS, the relay's addresses on 443, and the systems' listed ranges. Or a hostname policy from `neubird-proxy netpol` (below) |
| Resources | A 512 MiB memory limit; response buffering is sized to it (see Latency and capacity) |

**Restricting egress by hostname.** A standard NetworkPolicy matches IP
ranges and ports, not hostnames. The chart's policy allows CIDRs, which may
be wider than the hosts NeuBird needs. To allow exactly the hosts in
`neubird_destinations.hosts` and the relay, generate the rules from the
running config (`/etc/neubird-proxy/config.yaml` in the pod, which includes
the tunnel section); they select the chart's pods by `app: neubird-proxy`:

```bash
neubird-proxy netpol -config config.yaml -namespace neubird                    # CiliumNetworkPolicy (default)
neubird-proxy netpol -config config.yaml -namespace neubird -format kubernetes # NetworkPolicy with the hosts' current IPs
neubird-proxy netpol -config config.yaml -format list                          # host:port lines for a firewall
```

- **Cilium**, including Azure CNI powered by Cilium: the generated policy
  allows only those hostnames and ports, and `*.domain` as an FQDN pattern.
  Cilium's `*` matches one label only, so `a.b.domain` needs its own entry.
  It also lets the pod *resolve* only those names, so a lookup of anything
  else fails.
- **No FQDN-aware CNI:** `-format kubernetes` resolves the exact hosts now
  and allows their current addresses; patterns are left out with a warning.
  That suits a private APIM endpoint with stable IPs. Regenerate it when
  they change; for anything behind a CDN, use hostname rules instead.
- **Azure Firewall application rules, AWS Network Firewall, or Route 53
  Resolver DNS Firewall:** `-format list` prints what to allow.
- **`hosts` with `*`** can't be expressed as a host rule (`netpol` warns):
  allow the systems' address ranges instead.

Regenerate the policy whenever `hosts` changes, so the network and the
proxy agree on what's reachable.

**Paths stay with the proxy.** The systems are HTTPS, so the network can't
see request paths without breaking TLS to inspect it. So the network
enforces which hosts the pod can reach, and the proxy enforces which
methods and requests are allowed on them (see What NeuBird can reach).
Either layer still contains the other if one is misconfigured.

**Image admission.** Deploy by digest, not tag. Enforce signed images, or
images from MetLife's own registry, with their admission policy (for
example Kyverno, Gatekeeper, or Azure Policy for AKS); see the security
plan, item 5.

## Deploy

With the Helm chart only: see its
[README](deploy/helm/neubird-proxy/README.md) and the
[getting started guide](deploy/helm/neubird-proxy/docs/getting-started.md).
`make chart-check` lints and renders it, and validates the rendered config
with this build.

To rotate the proxy token (inbound listener only; a tunnel-only proxy has none):
1. Add the new value as `NEUBIRD_PROXY_TOKEN` and move the old one to
   `NEUBIRD_PROXY_TOKEN_PREVIOUS`, with `client_token_previous_env` set, then
   restart.
2. Update whatever sends it (your gateway).
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

For NeuBird engineering: what is the largest expected response body (this
sets `max_body_bytes`)? Which methods does each connector need (this sets
`methods`)?

For MetLife: what are the real member ID and PHI formats? Is regex-only detection
acceptable? What is the status of Cribl for Splunk?
