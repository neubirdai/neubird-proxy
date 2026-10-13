# neubird-proxy configuration reference

The chart's `config` value is the proxy's configuration, minus what the
chart sets itself: `admin_listen: :9090`, and either the `tunnel` section
(from `tunnel.*`, including `join_token_env`) with `listen: off`, or, with
`mode: inbound`, `listen: :8443` and `tls` (from `inbound.*`). This page
covers what you set there. Check any configuration with the image before rolling it out
(see Checking a configuration).

## How requests are confined

NeuBird names the system each request is for: the request goes to
`/_neubird/dest/<path>` with `X-Neubird-Destination: https://host[:port]`,
the endpoint URL of NeuBird's connection for that system. The proxy forwards
it only within what you set in `neubird_destinations`:

1. **Only hosts you allow.** The host must match `hosts`: `*.example.com`
   (any name under that domain), `host.example.com` (exactly), either with an
   optional `:port`, or `*` (any host name). IP addresses are reached only
   when listed exactly; wildcards never match them. Without `hosts`, any
   host name is allowed. A disallowed host gets `403 destination_not_allowed`,
   and only after the token check, so a caller without the token learns
   nothing about your hosts.
2. **Never internal addresses.** Connections to loopback, link-local
   (including the cloud metadata address `169.254.169.254`) and unspecified
   addresses are refused, whatever a name resolves to.
3. **Only allowed requests.** `methods` defaults to GET and HEAD.
   `request_deny_patterns` refuse requests whose query or body matches.
   `.`/`..` path segments (including encoded forms) are refused, and
   redirects are rewritten back through the proxy.

**Restrict egress at the network too** (see Egress below): `hosts` decides
what the proxy will forward, the network what the pod can reach at all.

## Top-level fields

| Field | Default | Meaning |
|---|---|---|
| `client_token_env` | | Env var with NeuBird's token (32+ characters), e.g. `NEUBIRD_PROXY_TOKEN` |
| `client_token_previous_env` | | Also accepted during a token rotation; remove afterwards |
| `upstream_ca_file` | system roots | Don't set it: use the chart's `upstreamCA` value, which mounts the bundle and sets this |
| `allow_http_upstreams` | `false` | Allow `http://` systems; otherwise only `https://` |
| `max_body_bytes` | 20 MiB | Largest request or response body; larger responses are refused, never passed through |
| `max_concurrent_requests` | 256 | In-flight requests before `503` |
| `max_concurrent_buffered` | 4 | Responses buffered for redaction at once |

## Destinations (`neubird_destinations`)

| Field | Default | Meaning |
|---|---|---|
| `hosts` | `["*"]` | Host patterns NeuBird may name: `*`, `*.domain` (two or more labels), `host`, or an exact IP; each may end in `:port` |
| `methods` | `[GET, HEAD]` | Allowed HTTP methods, for every host |
| `host_methods` | | Narrower methods for some hosts: a list of `{hosts, methods}`; the first rule whose `hosts` match the destination replaces `methods` for it, and may only list methods `methods` allows (e.g. ServiceNow read-only next to a Splunk that needs POST) |
| `request_deny_patterns` | | RE2 patterns; a match anywhere in the query or body, raw or URL-decoded, is refused (e.g. SPL commands that write or send) |
| `credential_headers` | `[Authorization]` | Headers NeuBird may set for the system, sent as `X-Neubird-Upstream-<Header>` and forwarded as `<Header>`; `Host`, `Cookie`, `X-Forwarded-*`, APIM trace headers and transport headers are refused |
| `request_headers` | | Extra client headers to forward; credentials and cookies are always refused |
| `rate_limit` | | `{requests_per_second, burst}`, per replica, shared by every host |
| `response_fields` | | JSON field allowlist for every host's responses: every other field is masked whatever it contains |
| `client_auth` | `bearer` | How NeuBird presents the proxy token: `bearer`, `basic` (as password), or `header`; or `none` in mode `tunnel` (no inbound listener): no proxy token, since every request comes down the proxy's own mutually authenticated tunnel |
| `client_auth_header` | | Header name when `client_auth: header` |
| `client_token_env` | top-level | A token for this section only |

## Credentials

| Credential | Held by | NeuBird sees it |
|---|---|---|
| Your systems' credentials (API tokens, OAuth tokens, gateway keys) | NeuBird, in each of its connections | Yes: it sends them with each request, in `credential_headers` |
| Proxy token (`client_token_env`) | Both: you generate it and enter it in NeuBird; none with `client_auth: none` | Yes; the proxy checks it and removes it, it never reaches your systems |
| Tunnel key | You; generated in the cluster | No; only its public fingerprint |
| `REDACTION_HMAC_KEY` | You | No |

NeuBird also knows your systems' hostnames: they're the URLs of its
connections. Every `${VAR}` and `*_env` must be set in your
`env.existingSecret`, or the proxy refuses to start and names the missing
one. Credential values are never logged.

## Redaction (`redaction`)

Responses are redacted before they leave: JSON value by value (including
JSON inside strings), text and CSV whole-body, MCP event streams event by
event, gzip decoded first. Encoded forms (`%40`, `&#64;`, full-width and other scripts' digits,
zero-width and other invisible characters) are normalized before matching.

| Field | Default | Meaning |
|---|---|---|
| `builtins` | all below except `windows_account` | Built-in rules: `private_key`, `jwt`, `aws_access_key`, `azure_key`, `vendor_token`, `url_credentials`, `bearer_token`, `secret_assignment`, `email`, `us_ssn`, `credit_card`, `phone_us`, `ipv4`, `date_of_birth`; opt-in `windows_account` |
| `custom[]` | | `{name, regex}` rules for your identifiers; a named group `v` masks only that group |
| `blocked_key_patterns` | | JSON keys whose values are always masked |
| `allowed_values` | | Values left unmasked when a pattern matches all of them |
| `mask` | `label` | `label` → `[REDACTED:EMAIL]`; `hmac` → `[REDACTED:EMAIL:3f1c…]`, the same value always giving the same token |
| `hmac_key_env` | `REDACTION_HMAC_KEY` | Env var with the HMAC key (32+ characters), for `mask: hmac` |

**Fail closed.** A response the proxy can't redact (too large, binary,
unsupported type or encoding, partial) is refused with `502 redaction_blocked`,
never passed through.

**What rules don't catch:** free-text names, addresses, and hostnames
without a custom rule. Use `neubird_destinations.response_fields` to let
only approved fields through, and `custom` rules for your own identifiers
and host names.

## Checking a configuration

The image includes the tools; run them before installing or upgrading.
Write `config.yaml` (your `config` value, without the chart's part), then:

```sh
IMG=<your registry>/neubird-proxy@sha256:...
docker run --rm --entrypoint /neubird-proxy -v $PWD:/w -w /w \
  -e NEUBIRD_PROXY_TOKEN=check-only-0123456789abcdef0123456 -e REDACTION_HMAC_KEY=check-only-0123456789abcdef0123456 \
  $IMG validate -config config.yaml           # hosts, methods, risky settings
# Ignore "tls is not set": that's the request listener, which the chart turns off.

docker run --rm --entrypoint /neubird-proxy -v $PWD:/w -w /w \
  $IMG -config config.yaml -redact sample.json # redact your own sample data, counts per rule

docker run --rm --entrypoint /neubird-proxy -v $PWD:/w -w /w \
  $IMG preview -config config.yaml sample.json # side by side; -html - for a report
```

In the cluster, the running config:

```sh
kubectl -n <ns> exec deploy/neubird-proxy -- /neubird-proxy validate -config /etc/neubird-proxy/config.yaml
```

## Egress

A NetworkPolicy matches addresses, not hostnames. Generate one from the
running configuration (it includes the tunnel section the chart adds):

```sh
kubectl -n <ns> exec deploy/neubird-proxy -- /neubird-proxy \
  netpol -config /etc/neubird-proxy/config.yaml -namespace <ns>          # CiliumNetworkPolicy (FQDN rules)
#  ... -format kubernetes   NetworkPolicy with the hosts' current IPs
#  ... -format list         host:port lines for a firewall
```

It covers the relay and every host in `hosts`. With Cilium, `*.domain`
becomes an FQDN pattern, which matches one label only (`a.domain`, not
`a.b.domain`): list deeper names separately. `-format kubernetes` can't
resolve a pattern, and no format can express `*`: allow your systems'
address ranges instead (the chart's `networkPolicy.upstreams`, or your
firewall). The policy selects the chart's pods by their
`app: neubird-proxy` label. It covers egress only: keep the chart's
`networkPolicy` for ingress, or add your own, and regenerate the egress
policy when `hosts` changes.
