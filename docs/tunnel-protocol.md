# Tunnel protocol, version 1

The wire contract between neubird-proxy (the tunnel client) and
neubird-relay. This file is the single source of truth: both repos
implement it independently and test against the vectors below. The design
and its reasons are in [outbound-tunnel-design.md](outbound-tunnel-design.md).

## Connection

1. The proxy opens TCP to a relay address (`host:port`), through an
   outbound HTTP proxy with `CONNECT` if one is configured.
2. TLS 1.3, mutual:
   - **ALPN** is `neubird-tunnel/1`. Both sides refuse a connection that
     negotiates anything else.
   - **The proxy** presents its client certificate (self-signed, minted from
     its key on every connect) and verifies the relay's server certificate
     against its pinned CA (`tunnel.ca_file`), for the relay host name it
     dialed.
   - **The relay** accepts the client certificate only if its key's
     fingerprint (`sha256:` and the SHA-256 of the DER SubjectPublicKeyInfo)
     is recorded, unrevoked and unretired, under the identity below. It also
     requires the certificate to be current and allow client
     authentication. No CA is involved.
3. HTTP/2 then runs on the TLS connection **with the roles reversed**: the
   relay is the HTTP/2 client and sends the connection preface, and the
   proxy is the HTTP/2 server.

## Identity

The proxy's certificate carries exactly one URI SAN:

```
spiffe://neubird.ai/tenant/<tenant>/proxy/<proxy>
```

Both `<tenant>` and `<proxy>` match `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`:
a valid DNS label. That's why they can appear in relay hostnames,
`<proxy>.<tenant>.relay.neubird.ai`. Anything else is rejected: other URI
SANs, more than one, another trust domain, extra path segments, upper case,
a query or fragment.

### Test vectors

| Input | Result |
|---|---|
| `spiffe://neubird.ai/tenant/metlife/proxy/aks-prod` | tenant `metlife`, proxy `aks-prod` |
| `spiffe://neubird.ai/tenant/a/proxy/b` | tenant `a`, proxy `b` |
| `spiffe://neubird.ai/tenant/metlife/proxy/aks-prod/extra` | invalid |
| `spiffe://example.com/tenant/metlife/proxy/aks-prod` | invalid (trust domain) |
| `spiffe://neubird.ai/tenant/MetLife/proxy/aks-prod` | invalid (upper case) |
| `spiffe://neubird.ai/tenant/metlife/proxy/-aks` | invalid (leading hyphen) |
| `spiffe://neubird.ai/tenant/metlife/proxy/` | invalid (empty) |
| `spiffe://neubird.ai/tenant/metlife/proxy/aks?x=1` | invalid (query) |
| `https://neubird.ai/tenant/metlife/proxy/aks-prod` | invalid (scheme) |

## Requests

- **Requests are forwarded as the connector sent them:** method, path,
  query, headers (including the proxy token in `Authorization`) and body.
  The path starts with the proxy connection's name, exactly as it would
  for a direct inbound request.
- **The relay sets `:authority` to `tunnel`.** The proxy routes by host
  first and then by path; `tunnel` matches no connection's host (don't
  name one that), so tunnel requests are routed by path.
- **Hop-by-hop headers are removed,** as for any proxy.
- **One request ID end to end:** the relay keeps the connector's
  `X-Request-Id` if it is a short plain token (up to 64 of `A-Z a-z 0-9 . _ : -`)
  and sets its own otherwise; the proxy keeps it. The same ID is in the
  relay's log, the proxy's audit line, the upstream request and the response.
- **Responses stream:** the relay copies and flushes response bodies as
  they arrive, so SSE and newline-delimited JSON stay incremental.

## Only plain HTTP

Only plain HTTP requests and responses cross the tunnel; nothing can turn
it into a byte stream. This doesn't depend on a connection's `methods` or
`passthrough`.

- **The relay**, before it chooses a tunnel, refuses `CONNECT` and `TRACE`
  (405 `method_not_allowed`) and protocol upgrades: an `Upgrade` header, or
  `upgrade` in `Connection`, such as WebSocket or h2c (400
  `upgrade_not_supported`).
- **The proxy** refuses `CONNECT` and `TRACE` again as they arrive on a
  tunnel (405). Upgrades can't arrive: HTTP/2 forbids those headers, the
  HTTP/2 server answers them itself, and it resets extended CONNECT.

## Encryption on each hop

| Hop | On the wire | Who can read it |
|---|---|---|
| NeuBird's agent (ace) → relay, inside NeuBird's cluster | plain HTTP | the relay |
| relay ↔ proxy, the tunnel | one mutual TLS 1.3 connection carrying plain HTTP/2 requests and responses | only the relay and the proxy |
| proxy → backend (e.g. Splunk), inside the customer's network | HTTPS if the backend requires it | the proxy and the backend |

The proxy decrypts the backend's response, redacts it, and writes plain
HTTP into the tunnel; the tunnel's TLS is the only encryption on that hop.
The HTTPS to the backend is a separate hop on the customer's side, not a
second layer. The load balancer in front of the relay doesn't decrypt;
TLS ends at the relay, which needs the client certificate and routes on
the plain HTTP inside.

## Accepting a tunnel

With TLS 1.3 the proxy's handshake completes before the relay has checked
the proxy's certificate; a refusal (revoked, unrecorded, expired, another
tenant) arrives as a TLS alert on the proxy's first read. The relay starts
HTTP/2 as soon as it accepts a tunnel, so the proxy counts a tunnel as
connected only once the relay's first bytes arrive (within 10 s), and
`neubird-proxy test` does the same.

## Liveness and shutdown

- **Pings:** both sides send HTTP/2 PING after 5 s without traffic, and
  drop the connection when no answer arrives within 5 s. A path that dies
  silently (packets dropped by a firewall or NAT) is noticed within about
  10 s; until then, requests sent down that tunnel wait.
- **Proxy shutdown** sends GOAWAY: the relay stops sending new requests on
  that connection, and in-flight ones finish.
- **Relay restarts** send GOAWAY: in-flight requests finish, then the
  connection closes. The relay stops accepting tunnels first, so the
  proxy's reconnect reaches another replica.
- **Reconnects** use exponential backoff (1 s doubling to 15 s, with equal
  jitter: half of each wait is random). A tunnel that stayed up 10 s resets the backoff, so the
  reconnect after a relay restart takes about a second.

## Versioning

A breaking change gets a new ALPN name (`neubird-tunnel/2`). During a
transition the relay accepts both; the proxy offers the newest it
supports.
