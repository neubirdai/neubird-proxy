# Outbound tunnel and relay: design and scope

**Status: built; production infrastructure pending.** Proposed Oct 2,
2026. The proxy's tunnel client shipped in v0.1.1, and the relay is
neubird-relay, one dedicated relay per customer. Not built yet: tunnel-only
TCP connections and the relay checking its callers (phase 2). Two reasons
to build it:

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
 MetLife (AKS)                              │  NeuBird (namespace metlife: MetLife's tenant stack)
                                            │
 backends ◀── APIM ◀── neubird-proxy ──mTLS─┼──▶ relay ◀────────── ace ◀── falcon
                        (dials out,         │    (maps cert → tenant,   (calls the relay's
                         serves HTTP/2      │     forwards requests      Service with the
                         on the tunnel)     │     down MetLife's         proxy token)
                                            │     tunnels)
```

1. **The proxy dials out** to `metlife.tunnel.neubird.ai:443`, MetLife's
   dedicated relay, with its client certificate: MetLife's key, signed by a
   NeuBird tenant CA. It checks the relay's server certificate against a
   pinned NeuBird CA.
2. **The relay verifies the certificate** and reads the tenant from it,
   then registers the connection as one of that tenant's tunnels.
3. **MetLife's ace calls the relay's Service** in MetLife's namespace,
   e.g. `http://neubird-relay.metlife.svc.cluster.local:8080/splunk/services/mcp`,
   sending the proxy token as it does today (see Connecting NeuBird's
   connectors).
4. **The relay forwards the request** as an HTTP/2 stream down one of the
   tenant's tunnels. The proxy handles it exactly as an inbound request,
   and the response streams back the same way.

The protocol is plain HTTP/2 (`golang.org/x/net/http2`: the proxy's
`Server.ServeConn` on the dialed connection, the relay's
`Transport.NewClientConn` on the accepted one). That gives multiplexing,
flow control and streaming without a custom framing protocol.

## Connecting NeuBird's connectors

Every NeuBird tenant runs its own stack (ace, falcon, …) in its own
namespace, and a customer's relay runs in that namespace too, deployed
with the stack. The relay is transparent to connector code: a connector
sees exactly what it sees with a direct proxy, a base URL plus the proxy
token.

```
direct (inbound):   https://proxy.metlife.com/splunk/services/mcp
through the relay:  http://neubird-relay.metlife.svc.cluster.local:8080/splunk/services/mcp
```

- **The relay serves one tenant.** It's configured with `tenant: metlife`,
  takes any request on its Service as MetLife's, and forwards only down
  tunnels whose certificate names MetLife.
- **The path is unchanged.** `/splunk/...` still selects the connection on
  the proxy, and the proxy still applies the token check, allowlists and
  redaction. Moving a customer from direct to relay changes only the base
  URL in the connection's configuration.
- **No load balancer, DNS or certificate on the request side.** The call
  stays inside the tenant's namespace. (Earlier drafts had a shared
  internal load balancer on `*.relay.neubird.ai`.)
- **Several proxies per customer** (prod and dev, two regions): requests
  spread across all of them; a caller that sets the Host header
  `aks-prod.metlife.relay.neubird.ai` reaches only the proxy whose
  certificate is `spiffe://neubird.ai/tenant/metlife/proxy/aks-prod`.

### Two faces, kept apart

The relay has two endpoints with different audiences, and they must never
be mixed:

| Endpoint | Who connects | Reachable from |
|---|---|---|
| `<tenant>.tunnel.neubird.ai:443` | That customer's proxies, with mutual TLS, to that customer's dedicated relay | The internet |
| The relay's Service, port 8080 | That tenant's ace | Only pods labelled `app.kubernetes.io/name: ace` in the tenant's namespace (NetworkPolicy) |

If the request port were reachable from elsewhere, the relay would be a
way into the customer's network guarded only by the proxy token.

### Who may call the relay

Two layers, so a mistake in one doesn't expose a customer:

1. **The network:** the relay's NetworkPolicy admits its request port only
   from its own tenant's ace. Another tenant's ace, or any other pod, can't
   connect. This needs NetworkPolicy enforcement in the cluster (prod_cluster
   runs the VPC CNI network policy agent).
2. **Proxy tokens are per customer** (already true). A caller without
   MetLife's token gets a 401 from MetLife's proxy.

A third layer, the relay verifying a Kubernetes service account token
from ace, is possible later if the network check isn't considered enough.

## Proxy changes

A new optional `tunnel` section. With it set, the inbound listener can be
turned off (`listen: ""`).

```yaml
tunnel:
  relays: [metlife.tunnel.neubird.ai:443]   # MetLife's dedicated relay
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
- **Revocation and rotation:** the tenant records list every certificate
  serial. A `revoked` one (compromised) is refused and its tunnels closed at
  once; a `retired` one (renewed, or a CA rollover) is refused for new
  tunnels and its open ones drain, so a planned rotation fails no requests.
- **Tenant isolation:** a request for tenant A is only ever sent down
  tenant A's tunnels. That rule lives in one small, reviewed function with
  its own tests, because it's the relay's most important property.
- **Load spreading:** across a tenant's tunnels, with a retry on another
  tunnel if one fails before the request is sent. It never retries after
  the request was sent: a write must not run twice.
- **Deployment: a dedicated relay per customer.** Each customer gets its
  own relay: 3 replicas in its own namespace, behind its own TCP
  (passthrough) load balancer with its own Elastic IPs and hostname,
  `<tenant>.tunnel.neubird.ai`, so the relay itself terminates TLS and sees
  client certificates. A failure, a heavy customer or a compromised relay
  process then affects only that customer. The relay is configured with
  `tenant: <tenant>` and refuses any other tenant's certificate. A proxy's
  tunnels can land on any of its relay's replicas; a request that arrives
  at a replica without the tunnel is forwarded to one that has it.
  Customers configure one hostname and one port. The relay runs in the
  NeuBird tenant's own namespace, deployed with the tenant's stack, and the
  tenant's ace calls its Service. (Updated Oct 2026; earlier drafts used one
  hostname per replica, then one relay shared by every customer. See
  neubird-relay deploy/production.)
- **Metrics:** tunnels per tenant, requests, latency, errors, and tenants
  with no live tunnel, which should alert.
- **Routing:** a dedicated relay serves its one tenant; a per-proxy Host
  (`<proxy>.<tenant>.relay.neubird.ai`) narrows it to one proxy. Another
  tenant's hostname is refused. Nothing else in the request is consulted.

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
  The relay listens on one port per tunnel-only connection, published on
  its Service in the tenant's namespace (e.g.
  `neubird-relay.metlife.svc:15432` for `claims-db`). Each tunnel-only
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

The CA private keys are AWS KMS keys that never leave KMS: `neubird-relay`
builds each certificate and asks KMS to sign it, so who may sign is an IAM
permission and every signature is in CloudTrail (about $1 a month per key,
against about $400 per CA for AWS Private CA). There are two: the tenant CA
signs proxies' certificates, the relay CA signs relays' server
certificates and is what proxies pin. Certificates last 90 days, and the
proxy warns from 30 days before expiry. Renewal is the same CSR flow: the
customer updates the proxy's Secret, the proxy picks the new certificate up
without a restart, and NeuBird retires the old serial so open tunnels move
to the new one with no failed requests.

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
| CAs with keys in KMS, signing runbook, first MetLife certificate | done in neubird-relay; the production keys remain |
| NeuBird connectors pointed at the relay per tenant (depends on how connections are configured in the platform) | 1–3 days |
| Hardening: replicas, alerts, outbound HTTP proxy support, load test, docs | 3–5 days |
| Relay in each tenant's namespace, NetworkPolicy limiting it to the tenant's ace | done |
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
