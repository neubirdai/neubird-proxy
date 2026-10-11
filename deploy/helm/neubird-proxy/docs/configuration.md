# neubird-proxy configuration reference

The chart's `config` value is the proxy's configuration, minus what the
chart sets itself: the `tunnel` section (from `tunnel.*`, including
`join_token_env`), `listen: off` and `admin_listen: :9090`. This page covers what you
set there. Check any configuration with the image before rolling it out
(see Checking a configuration).

## How requests are confined

A request from NeuBird can only reach URLs under one of your connections,
and only what that connection allows:

1. **The destination never comes from the request.** Each connection has a
   fixed `upstream` base URL. A request only names a connection (the first
   path segment); an unknown name gets `404 unknown_connection` and nothing
   is sent. Host headers and absolute URLs never change the destination.
2. **A request can't leave its connection's base path.** `.`/`..` segments
   (including encoded forms) are refused; upstream redirects are rewritten
   back through the proxy.
3. **`paths`, `methods` and `mcp_tools` narrow it further.** `paths` are RE2
   patterns matched against the whole path after the connection name; other
   paths get `403 path_not_allowed`. `methods` defaults to GET and HEAD.

**Without `paths`, every URL under the upstream is reachable** with the
allowed methods. List `paths` for production; the proxy warns at start when
a connection has none.

## Top-level fields

| Field | Default | Meaning |
|---|---|---|
| `client_token_env` | | Env var with NeuBird's token (32+ characters), e.g. `NEUBIRD_PROXY_TOKEN` |
| `client_token_previous_env` | | Also accepted during a token rotation; remove afterwards |
| `upstream_ca_file` | system roots | Don't set it: use the chart's `upstreamCA` value, which mounts the bundle and sets this |
| `max_body_bytes` | 20 MiB | Largest request or response body; larger responses are refused, never passed through |
| `max_concurrent_requests` | 256 | In-flight requests before `503` |
| `max_concurrent_buffered` | 4 | Responses buffered for redaction at once |
| `upstream_defaults.headers` | | Headers on every upstream request; values may use `${VAR}` |
| `neubird_destinations` | off | Open mode: `{hosts, methods, request_deny_patterns, rate_limit, credential_headers, client_token_env, client_auth}`. NeuBird names the destination host within `hosts` (`*`, `*.domain`, `host[:port]`, exact IPs) and sends its own credentials; no per-backend entries (README: Open mode) |

## Connections (`connections[]`)

| Field | Default | Meaning |
|---|---|---|
| `name` | required | The connection's name, which NeuBird uses in its URL: `[a-z0-9][a-z0-9_-]*` |
| `upstream` | required | `https://` base URL of your API; no query string |
| `client_auth` | `bearer` | How NeuBird presents its token: `bearer`, `basic` (as password), or `header` |
| `client_auth_header` | | Header name when `client_auth: header` |
| `client_token_env` | top-level | A token for this connection only |
| `methods` | `[GET, HEAD]` | Allowed HTTP methods |
| `paths` | any | Allowed paths (RE2, whole-path match) |
| `request_deny_patterns` | | RE2 patterns; a match anywhere in the query or body is refused (e.g. SPL commands that write or send) |
| `mcp_tools` | | MCP tools a `tools/call` may name (MCP connections; needs `POST`) |
| `headers` | | Headers added toward your API, e.g. `Authorization: Bearer ${SPLUNK_TOKEN}` or a gateway key |
| `upstream_basic_auth` | | `{username_env, password_env}` for upstream Basic auth |
| `request_headers` | | Extra client headers to forward; credentials and cookies are always refused |
| `rate_limit` | | `{requests_per_second, burst}`, per replica |
| `response_fields` | | JSON field allowlist: every other field is masked whatever it contains |
| `passthrough` | `false` | Skip redaction for this connection. Avoid |

NeuBird's token is checked and removed; your credentials (`headers`,
`upstream_basic_auth`) are added here and never leave the cluster. Every
`${VAR}` and `*_env` must be set in your `env.existingSecret`, or the proxy
refuses to start and names the missing one.

## Redaction (`redaction`)

Responses are redacted before they leave: JSON value by value (including
JSON inside strings), text and CSV whole-body, MCP event streams event by
event, gzip decoded first. Encoded forms (`%40`, `&#64;`, full-width digits,
zero-width characters) are normalized before matching.

| Field | Default | Meaning |
|---|---|---|
| `builtins` | all below except `windows_account` | Built-in rules: `private_key`, `jwt`, `aws_access_key`, `azure_key`, `vendor_token`, `url_credentials`, `bearer_token`, `secret_assignment`, `email`, `us_ssn`, `credit_card`, `phone_us`, `ipv4`, `date_of_birth`; opt-in `windows_account` |
| `custom[]` | | `{name, regex}` rules for your identifiers; a named group `v` masks only that group |
| `blocked_key_patterns` | | JSON keys whose values are always masked |
| `allowed_values` | | Values left unmasked when a pattern matches all of them |
| `mask` | `label` | `label` → `[REDACTED:EMAIL]`; `hmac` → `[REDACTED:EMAIL:3f1c…]`, the same value always giving the same token |
| `hmac_key_env` | `REDACTION_HMAC_KEY` | Env var with the HMAC key, for `mask: hmac` |

**Fail closed.** A response the proxy can't redact (too large, binary,
unsupported type or encoding, partial) is refused with `502 redaction_blocked`,
never passed through.

**What rules don't catch:** free-text names, addresses, and hostnames
without a custom rule. Use `response_fields` to let only approved fields
through, and `custom` rules for your own identifiers and host names.

## Checking a configuration

The image includes the tools; run them before installing or upgrading.
Write `config.yaml` (your `config` value, without the chart's part), then:

```sh
IMG=<your registry>/neubird-proxy@sha256:...
docker run --rm --entrypoint /neubird-proxy -v $PWD:/w -w /w \
  -e NEUBIRD_PROXY_TOKEN=check-only-0123456789abcdef0123456 -e REDACTION_HMAC_KEY=x \
  -e SPLUNK_TOKEN=x \
  $IMG validate -config config.yaml           # connections, paths, risky settings
# Ignore "tls is not set": that's the request listener, which the chart turns off.

docker run --rm --entrypoint /neubird-proxy -v $PWD:/w -w /w \
  $IMG -config config.yaml -redact sample.json # redact your own sample data, counts per rule
```

In the cluster, the running config:

```sh
kubectl -n <ns> exec deploy/neubird-proxy -- /neubird-proxy validate -config /etc/neubird-proxy/config.yaml
```

## Egress by hostname

A NetworkPolicy matches addresses, not hostnames. To allow exactly your
connections' hosts and NeuBird's relay, generate a policy from the running
configuration (it includes the tunnel section the chart adds):

```sh
kubectl -n <ns> exec deploy/neubird-proxy -- /neubird-proxy \
  netpol -config /etc/neubird-proxy/config.yaml -namespace <ns>          # CiliumNetworkPolicy (FQDN rules)
#  ... -format kubernetes   NetworkPolicy with the hosts' current IPs
#  ... -format list         host:port lines for a firewall
```

It selects the chart's pods by their `app: neubird-proxy` label. Apply it
instead of the chart's `networkPolicy` (leave that disabled), and
regenerate it when connections change.
