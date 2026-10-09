# Outbound tunnel and relay: design and scope

**Status: built; production infrastructure pending.** Proposed Oct 2,
2026. The proxy's tunnel client shipped in v0.1.1, and the relay is
neubird-relay, one dedicated relay per customer in its NeuBird tenant's
namespace, callable only by that tenant's ace. The tunnel carries HTTP and
MCP only (see Scope). Two reasons to build it:

- **Customers that allow no inbound path.** MetLife may require the proxy
  to connect *out* to NeuBird, with nothing exposed inbound. If an inbound
  path from NeuBird's egress IPs is acceptable, the proxy already supports
  that with mutual TLS (`tls.client_ca_file`), so MetLife's timeline
  doesn't depend on this.
- **Replacing Teleport as the way into customer networks.** Security teams
  have rejected Teleport (GM and MetLife among them) because it can do far
  more than NeuBird needs, SSH and shell access included. The proxy plus
  relay reaches only allowlisted HTTP endpoints and MCP tools, and redacts
  before anything leaves. See Scope: it carries HTTP and MCP only, never
  raw TCP.

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
   dedicated relay, with its client certificate: MetLife's key, signed by
   MetLife's own tenant CA. It checks the relay's server certificate against
   MetLife's relay CA, which it pins.
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

- **Mutual TLS** against the customer's own tenant CA (the only CA its relay
  trusts). The tenant comes from the
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
  own relay: 3 replicas in its own namespace, behind its own load balancer
  with its own Elastic IPs and hostname, `<tenant>.tunnel.neubird.ai`. The
  load balancer doesn't decrypt (layer 4): TLS ends at the relay, which sees
  client certificates and plain HTTP. There's one layer of encryption on
  the tunnel, not two (tunnel-protocol.md, "Encryption on each hop"). A failure, a heavy customer or a compromised relay
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

## Scope: HTTP and MCP only

The tunnel is an HTTP reverse proxy end to end, and nothing else:

- **The relay sends HTTP requests,** each as an HTTP/2 request down the
  tunnel. It has no way to open a connection to a host or port in the
  customer's network.
- **The proxy forwards them only to its configured upstreams,** through its
  path, method and MCP tool allowlists and deny patterns, and redacts every
  response.
- **There is no TCP or port forwarding,** and none will be added. Raw TCP
  (databases over their own protocols, for example) would carry bytes the
  proxy can't inspect, allowlist or redact, which is exactly what makes
  Teleport hard to approve. A backend that only speaks a binary protocol
  needs an HTTP or MCP front end on the customer's side, behind the proxy,
  so the same allowlists and redaction apply.

Through the proxy, that covers HTTP APIs and MCP servers: most connectors,
and all three in MetLife's pilot.

## Certificates

This is the flow Sreekanth described:
1. MetLife runs `neubird-proxy csr`, keeps the key in a Kubernetes Secret,
   and sends NeuBird the CSR.
2. NeuBird signs it with MetLife's own tenant CA, embedding the tenant
   identity, and returns the certificate along with MetLife's relay CA
   certificate.
3. MetLife adds both to the Secret, and the CA to the proxy's trust store.

**Every customer has its own two CAs;** none is shared, so a certificate
issued for one customer can't be valid on another's relay. The tenant CA
signs that customer's proxy certificates; the relay CA signs that
customer's relay's server certificate and is what their proxies pin. Each
CA certificate names its customer, a relay refuses to start with any other
customer's CA, and the signing tools refuse to sign across customers. The
CA private keys are AWS KMS keys that never leave KMS (and never sit in the
relay pod): `neubird-relay` builds each certificate and asks KMS to sign
it, so who may sign is an IAM permission and every signature is in
CloudTrail (about $2 a month per customer for two keys, against about $400
per CA for AWS Private CA). Certificates last 90 days, and the
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
| Relay checks the caller (phase 2) | largely covered: only the tenant's ace can reach its relay (NetworkPolicy); a service account token check would be 3–5 days more |

A pilot-only MVP (one relay instance, manual signing, no outbound HTTP
proxy support) is about 1.5 weeks. It's enough for MetLife's first
end-to-end test, but not for production.

## Open questions for NeuBird

- Which connectors speak a non-HTTP protocol, and which customers use
  them? Those need an HTTP or MCP front end on the customer's side; the
  tunnel won't carry raw TCP.
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
