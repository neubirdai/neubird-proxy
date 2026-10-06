# Outbound tunnel and relay: design and scope

**Status: proposed.** Oct 2, 2026. Two reasons to build it:

- **Customers that allow no inbound path.** MetLife may require the proxy
  to connect *out* to NeuBird, with nothing exposed inbound. If an inbound
  path from NeuBird's egress IPs is acceptable, the proxy already supports
  that with mutual TLS (`tls.client_ca_file`), so MetLife's timeline
  doesn't depend on this.
- **Replacing Teleport as the way into customer networks.** Security teams
  have rejected Teleport (GM and MetLife among them) because it can do far
  more than NeuBird needs, SSH and shell access included. The proxy plus
  relay reaches only allowlisted HTTP endpoints and MCP tools, and redacts
  before anything leaves. See Coverage and the tunnel-only requirement for
  what it doesn't cover yet.

## Summary

The proxy keeps a few long-lived connections open *to* a NeuBird relay,
authenticated with mutual TLS. Over each connection the roles flip: the
relay acts as the HTTP/2 client and the proxy as the server, so every
NeuBird request becomes one HTTP/2 stream down the tunnel. Each request
goes through the proxy's normal handler unchanged: token check,
allowlists, redaction.

MetLife opens one outbound port to one hostname. No load balancer, inbound
firewall rule or public endpoint is needed on their side.

A prototype (Oct 2, outside the repo) confirmed the approach:
- **Identity:** the relay read MetLife's identity from the proxy's client
  certificate (a SPIFFE URI).
- **Requests:** they went down the tunnel to the proxy's handler with the
  path and token intact.
- **Streaming:** SSE events arrived at 0, 101 and 202 ms, as sent.
- **Concurrency:** 50 concurrent requests shared one tunnel in 11 ms.

## Architecture

```
 MetLife (AKS)                              │  NeuBird
                                            │
 backends ◀── APIM ◀── neubird-proxy ──mTLS─┼──▶ relay ◀── NeuBird connectors
                        (dials out,         │    (maps cert → tenant,       (call the relay
                         serves HTTP/2      │     forwards requests          per tenant, with
                         on the tunnel)     │     down that tenant's         the proxy token)
                                            │     tunnels)
```

1. **The proxy dials out** to `tunnel.neubird.ai:443` with its client
   certificate: MetLife's key, signed by a NeuBird tenant CA. It checks the
   relay's server certificate against a pinned NeuBird CA.
2. **The relay verifies the certificate** and reads the tenant from it,
   then registers the connection as one of that tenant's tunnels.
3. **A NeuBird connector calls the tenant's relay hostname**, e.g.
   `https://metlife.relay.neubird.ai/splunk/services/mcp`, sending the proxy
   token as it does today (see Connecting NeuBird's connectors).
4. **The relay forwards the request** as an HTTP/2 stream down one of the
   tenant's tunnels. The proxy handles it exactly as an inbound request,
   and the response streams back the same way.

The protocol is plain HTTP/2 (`golang.org/x/net/http2`: the proxy's
`Server.ServeConn` on the dialed connection, the relay's
`Transport.NewClientConn` on the accepted one). That gives multiplexing,
flow control and streaming without a custom framing protocol.

## Connecting NeuBird's connectors

The relay is transparent to connector code. Each tenant gets its own
hostname on the relay, and a connector sees exactly what it sees with a
direct proxy: a base URL plus the proxy token.

```
direct (inbound):   https://proxy.metlife.com/splunk/services/mcp
through the relay:  https://metlife.relay.neubird.ai/splunk/services/mcp
```

- **The hostname picks the tenant.** The relay reads it from the request's
  `Host` and forwards only down tunnels whose certificate names that
  tenant.
- **The path is unchanged.** `/splunk/...` still selects the connection on
  the proxy, and the proxy still applies the token check, allowlists and
  redaction. Moving a customer from direct to relay changes only the base
  URL in the connection's configuration.
- **Onboarding is automatic.** A wildcard DNS name and certificate
  (`*.relay.neubird.ai`) cover every tenant, and a tenant's hostname starts
  working when its first tunnel connects. A new customer needs only a
  signed certificate; nothing is configured on the relay.
- **Several proxies per customer** (prod and dev, two regions) get one
  hostname each, taken from the certificate's proxy name, e.g.
  `aks-prod.metlife.relay.neubird.ai` for
  `spiffe://neubird.ai/tenant/metlife/proxy/aks-prod`. The bare tenant
  hostname spreads load across all of that tenant's proxies.

Hostnames are better than a path prefix (`relay.neubird.ai/t/metlife/…`)
because not every connector accepts a base URL with a path.

### Two faces, kept apart

The relay has two endpoints with different audiences, and they must never
be mixed:

| Endpoint | Who connects | Reachable from |
|---|---|---|
| `tunnel.neubird.ai` | Customers' proxies, with mutual TLS | The internet |
| `*.relay.neubird.ai` | NeuBird's connectors | NeuBird's platform network only: private DNS and an internal load balancer |

If the per-tenant hostnames were public, the relay would be a public way
into every customer's network, guarded only by the proxy token.

### Don't trust the Host header alone

Anything inside NeuBird's network can send `Host: metlife.relay…`, so the
hostname says which tenant a request is *for*, not whether the caller may
reach it. Two layers guard that:

1. **Proxy tokens are per customer** (already true). A connector for
   another tenant doesn't hold MetLife's token, so MetLife's proxy refuses
   the request with a 401.
2. **The relay checks the caller** (phase 2). It authenticates the calling
   workload (mTLS or a workload identity token inside the platform) and
   checks that the workload may reach that tenant before forwarding. A
   mistake in one layer then doesn't expose a customer.

## Proxy changes

A new optional `tunnel` section. With it set, the inbound listener can be
turned off (`listen: ""`).

```yaml
tunnel:
  relays: [tunnel.neubird.ai:443]
  cert_file: /etc/neubird-proxy/tunnel/tls.crt   # NeuBird-signed
  key_file: /etc/neubird-proxy/tunnel/tls.key    # generated by MetLife, never leaves the cluster
  ca_file: /etc/neubird-proxy/tunnel/neubird-ca.crt   # pinned CA for the relay's certificate
  connections_per_relay: 1
```

- **Connections:** each pod keeps `connections_per_relay` tunnels (2 in
  production) to the relay hostname. The load balancer spreads them across
  relay replicas, and the replicas forward requests between themselves, so
  losing a replica or a pod leaves the other tunnels working.
- **Reconnects** with exponential backoff and jitter. HTTP/2 PINGs every
  15 s detect dead connections and keep idle firewalls from dropping them.
- **Same handler:** tunnel requests run through the existing `ServeHTTP`.
  The proxy token is still required, so a stolen certificate alone gets
  nothing, and every allowlist, limit and redaction rule applies
  unchanged.
- **Metrics:** tunnels up per relay, reconnects, and days until the
  certificate expires. The audit line gains `via: tunnel`.
- **Tools:**
  - `neubird-proxy csr` generates the key and a CSR with the right subject,
    which is MetLife's step in the certificate exchange.
  - `neubird-proxy test` checks DNS, TCP and TLS to each relay, and that
    the tunnel registers.
  - `neubird-proxy netpol` emits the egress rule for the relay hostnames.

## Relay (NeuBird side, new service)

A small Go service, ideally sharing code with the proxy repo.

- **Mutual TLS** against the tenant CA. The tenant comes from the
  certificate's SPIFFE URI, for example
  `spiffe://neubird.ai/tenant/<tenant-id>/proxy/<name>`.
- **Revocation:** a denylist of certificate serial numbers, checked at
  every handshake, so a compromised certificate can be cut off immediately
  without waiting for it to expire.
- **Tenant isolation:** a request for tenant A is only ever sent down
  tenant A's tunnels. That rule lives in one small, reviewed function with
  its own tests, because it's the relay's most important property.
- **Load spreading:** across a tenant's tunnels, with a retry on another
  tunnel if one fails before the request is sent. It never retries after
  the request was sent: a write must not run twice.
- **Deployment:** 3 replicas behind one TCP (passthrough) load balancer
  and one hostname, so the relay itself terminates TLS and sees client
  certificates. A proxy's tunnels can land on any replica; a request that
  arrives at a replica without that tenant's tunnel is forwarded to a
  replica that has one. Customers configure one hostname and one port.
  (Updated Oct 2026; earlier drafts used one hostname per replica. See
  neubird-relay docs/production-plan.md.)
- **Metrics:** tunnels per tenant, requests, latency, errors, and tenants
  with no live tunnel, which should alert.
- **Routing** by hostname, as described in Connecting NeuBird's
  connectors: the tenant from `Host`, checked against the tunnel
  certificates' tenant, never anything else in the request.

## Coverage and the tunnel-only requirement

Through the proxy, the tunnel carries HTTP APIs and MCP servers. That's
most connectors, and all three in MetLife's pilot. To replace Teleport for
every customer, it also needs to carry connections that don't speak HTTP:
databases over their own protocols (Postgres, MySQL, SQL Server, Oracle),
and any other TCP service a connector reaches today through Teleport.

The proxy can't redact those. Its masking works on HTTP responses (JSON,
text, SSE). A database's wire protocol is a binary format the proxy doesn't
parse, often encrypted end to end with the database's own TLS. So these
connections need a **tunnel-only** mode: bytes carried through the tunnel
as they are, with no redaction.

**Requirements for tunnel-only connections:**

- **Explicit opt-in, per connection, by the customer.** A separate
  `tcp_connections` section, so a raw connection can't be mistaken for a
  redacting one in review:

  ```yaml
  tcp_connections:
    - name: claims-db
      upstream: claims-db.internal:5432    # fixed host and port, as for HTTP
  ```

- **The destination still never comes from the request.** Each
  tunnel-only connection reaches exactly one configured host and port, the
  same guarantee as HTTP connections. There's no general-purpose TCP
  forwarding.
- **Customers must be told plainly that nothing is redacted.**
  `validate` lists tunnel-only connections, the pod warns at every start,
  and the docs say so. Customers who require redaction for everything, as
  MetLife does, can simply not configure any.
- **Least privilege moves to the backend.** Without an HTTP layer there
  are no path, method or tool allowlists, so the account the connector
  uses must be read-only, with access limited to what's needed. For
  databases that means a dedicated user with SELECT on specific schemas.
- **The backend credential sits with NeuBird.** The proxy injects
  credentials for HTTP connections, but for a raw database connection the
  login happens inside the database's own protocol. So NeuBird's connector
  holds the database credential, as with Teleport today. A protocol-aware
  mode that keeps credentials at the customer (the proxy logging in to
  Postgres on NeuBird's behalf) is possible later, one protocol at a time.
- **Audit and limits without content.** One line per connection (who,
  which connection, start, duration, bytes each way), connection counts and
  bytes in metrics, a cap on concurrent connections per tunnel-only
  connection, and an idle timeout.

**How it works:** each raw connection is one HTTP/2 stream on the existing
tunnel, so it needs no new ports on the customer side.
- **Proxy side:** opens a TCP connection to the configured upstream and
  copies bytes both ways.
- **Relay side:** the connector needs a hostname and port to connect to.
  The relay listens on one internal port per tenant tunnel-only connection,
  published as `claims-db.metlife.relay.neubird.ai:<port>`. Each tunnel-only
  connection gets its own port, because database protocols carry no
  hostname the relay could route on, the way HTTP routes on `Host`.

**Open question:** which of NeuBird's connectors (see
`raven-fdw-bridge/plugins`) speak a non-HTTP protocol today, and for which
customers? That decides whether tunnel-only belongs in the first release of
the relay or a later one.

## Certificates

This is the flow Sreekanth described:
1. MetLife runs `neubird-proxy csr`, keeps the key in a Kubernetes Secret,
   and sends NeuBird the CSR.
2. NeuBird signs it with the tenant CA, embedding the tenant identity, and
   returns the certificate along with NeuBird's CA certificate.
3. MetLife adds both to the Secret, and the CA to the proxy's trust store.

NeuBird needs to stand up the tenant CA, probably on AWS Private CA (or
step-ca), plus a signing runbook: who may sign, how a request is verified,
and audit of every certificate issued. Certificates should last 90 days, and
the proxy warns from 30 days before expiry. Renewal is the same CSR flow for
v1, and can be automated later.

## Security properties

- **Nothing inbound at MetLife.** Egress goes to the relay hostnames on 443
  only, and `netpol` generates that rule.
- **Two factors per request:** the tunnel certificate (which proxy) and the
  proxy token (which client). Neither alone is enough.
- **The relay never sees unredacted data.** Redaction happens in MetLife's
  cluster before the tunnel, so a compromised relay sees exactly what NeuBird
  already receives today. It's still a high-value target, because it can
  send requests to every tenant's proxy. Those requests are bounded by each
  proxy's allowlists, so tight `paths`, `methods` and `mcp_tools` matter even
  more in this mode.
- **MetLife keeps the off switch:** scale the deployment to zero, remove
  the egress rule, or delete the key.

## Risks

| Risk | Mitigation |
|---|---|
| **MetLife inspects outbound TLS** (a corporate proxy re-signing traffic). That breaks mutual TLS outright | Ask early. The relay hostnames need a TLS-inspection bypass. If outbound traffic must go through an HTTP proxy, the tunnel needs `HTTPS_PROXY` support via CONNECT (in scope, small) |
| **Firewalls drop long-lived idle connections** | 15 s PINGs, immediate reconnect, several tunnels per pod |
| **The relay becomes a single point of failure** for every tenant | Replicas, alerts on tenants without a tunnel, and a runbook |
| **Approving a new NeuBird-hosted component** may need MetLife review | The relay never sees unredacted data, and the design matches the vendor-connector pattern they already approved (to confirm) |
| **One more network hop** | Measured in a load test; expected to be milliseconds, well under Splunk query times |

## Effort

These are estimates for one engineer, not yet sized by the team:

| Work | Estimate |
|---|---|
| Proxy: tunnel client, config, reconnects, metrics, `csr` and `test` support, tests | 3–4 days |
| Relay MVP: mTLS, tenant mapping, revocation list, forwarding, streaming, tests | 4–6 days |
| Tenant CA, signing runbook, first MetLife certificate | 1–2 days |
| NeuBird connectors pointed at the relay per tenant (depends on how connections are configured in the platform) | 1–3 days |
| Hardening: replicas, alerts, outbound HTTP proxy support, load test, docs | 3–5 days |
| Per-tenant hostnames: wildcard DNS and certificate, internal load balancer, Host-based routing | 1–2 days |
| **Total, HTTP and MCP** | **about 3–4 weeks for one engineer; about 2 weeks for two** |
| Tunnel-only (TCP) connections: proxy stream-to-TCP copy, relay per-connection ports, audit and limits, docs | 1–2 weeks more |
| Relay checks the caller's workload identity (phase 2) | 3–5 days more |

A pilot-only MVP (one relay instance, manual signing, no outbound HTTP
proxy support) is about 1.5 weeks. It's enough for MetLife's first
end-to-end test, but not for production.

## Open questions for NeuBird

- Which connectors speak a non-HTTP protocol, and which customers use them
  (decides when tunnel-only ships)?
- What do NeuBird's platform workloads use for identity today? That decides
  how the relay checks callers in phase 2.
- Where does connection configuration live in the platform, so moving a
  customer from Teleport or direct to the relay is a base URL change?

## Open questions for MetLife

- Is outbound-only a hard requirement, or is inbound from NeuBird's IPs
  acceptable? This decides whether any of this is built.
- Does outbound traffic go through an HTTP proxy, or through TLS
  inspection? If so, can the relay hostnames bypass it?
- What did the other vendor's connector use? SPIFFE identities, and
  certificate fields such as tenant ID and tenant name?
- Certificate requirements: key type and size, validity, renewal process.
