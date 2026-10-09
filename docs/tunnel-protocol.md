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
   - **The proxy** presents its client certificate and verifies the relay's
     server certificate against its pinned CA (`tunnel.ca_file`), for the
     relay host name it dialed.
   - **The relay** verifies the client certificate against the tenant CA,
     requires the `clientAuth` extended key usage, rejects revoked serial
     numbers, and reads the identity below.
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
- **Hop-by-hop headers are removed,** as for any proxy. The relay adds
  `X-Request-Id` if the connector didn't send one.
- **Responses stream:** the relay copies and flushes response bodies as
  they arrive, so SSE and newline-delimited JSON stay incremental.

## Accepting a tunnel

With TLS 1.3 the proxy's handshake completes before the relay has checked
the proxy's certificate; a refusal (revoked, unrecorded, expired, another
tenant) arrives as a TLS alert on the proxy's first read. The relay starts
HTTP/2 as soon as it accepts a tunnel, so the proxy counts a tunnel as
connected only once the relay's first bytes arrive (within 10 s), and
`neubird-proxy test` does the same.

## Liveness and shutdown

- **Pings:** both sides send HTTP/2 PING after 15 s without traffic, and
  drop the connection when no answer arrives within 10 s.
- **Proxy shutdown** sends GOAWAY: the relay stops sending new requests on
  that connection, and in-flight ones finish.
- **Relay restarts** send GOAWAY: in-flight requests finish, then the
  connection closes. The relay stops accepting tunnels first, so the
  proxy's reconnect reaches another replica.
- **Reconnects** use exponential backoff (1 s doubling to 60 s, with equal
  jitter: half of each wait is random). A tunnel that stayed up 10 s resets the backoff, so the
  reconnect after a relay restart takes about a second.

## Versioning

A breaking change gets a new ALPN name (`neubird-tunnel/2`). During a
transition the relay accepts both; the proxy offers the newest it
supports.
