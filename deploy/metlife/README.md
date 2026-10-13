# neubird-proxy at MetLife: through the tunnel

```
NeuBird ─▶ relay ⇄ tunnel (dialed out by the proxy, :443, mutual TLS) ⇄ neubird-proxy (AKS) ─▶ Splunk
```

The proxy runs in MetLife's AKS and opens outbound tunnels to NeuBird's relay for MetLife; NeuBird's requests come back down those tunnels. Nothing connects in to MetLife: no load balancer, no inbound firewall rule. The proxy checks every request and redacts every response before it leaves MetLife.

There is no proxy token (`client_auth: none`): a request is accepted because it arrives over a tunnel this proxy opened, to a relay it verified, with a key the relay has pinned. Cutting NeuBird off is scaling to 0 (below).

| File | What it is |
|---|---|
| [`values.yaml`](values.yaml) | Helm values for the chart's tunnel mode |
| [`apim/`](apim/README.md) | Alternative: the proxy behind Azure API Management, no tunnel |

## What NeuBird sends MetLife

| Item | Secret | Value |
|---|---|---|
| Relay address | no | `metlifemirror-tunnel.cluster.neubird.ai:443` |
| Relay IP addresses, for the egress firewall | no | `3.231.28.52`, `32.196.200.125` |
| Tenant | no | `metlifemirror` |
| Relay CA certificate, `relay-ca.crt` | no | "NeuBird relay CA for metlifemirror" |
| Join token (`nbjt_…`) | **yes**, works once, expires in 72 hours | For the proxy name MetLife will use, e.g. `aks-prod` |

The relay's IP addresses stay the same unless NeuBird recreates its load balancer; NeuBird tells MetLife before that happens.

Allow outbound TCP 443 to those addresses **without TLS inspection**: the tunnel is mutual TLS with pinned keys, so a proxy that re-signs TLS breaks it. A plain forwarding (CONNECT) proxy is fine; set it with `extraEnv` in the values.

MetLife sends nothing back: the proxy enrolls its own key with the join token.

## Enrolling the proxy's key: join token

The proxy's tunnel key is its identity at the relay. The chart generates it in a Secret in MetLife's cluster, and it never leaves that cluster. The join token lets the proxy enroll that key itself on its first connect.

**NeuBird, before MetLife installs:**

1. Make a join token for the proxy name MetLife will use:
   ```sh
   neubird-relay join-token -tenant metlifemirror -proxy <proxy name> -ttl 72h
   ```
2. Add the record it prints (the token's hash, not secret) under that proxy in the metlifemirror relay's `tenants.yaml`, ConfigMap `neubird-relay-tenants` in namespace `metlifemirror`. The relay picks it up without a restart.
3. Send MetLife the token through the agreed secure channel, with the items above.

**MetLife:** install the proxy with the token in its Secret (below). On first connect the proxy presents the token, the relay records the key, and the tunnels open within seconds.

**NeuBird, after:** check the relay log for `proxy enrolled`, remove the spent token's record from `tenants.yaml`, and set the proxy's `expected_tunnels` to replicas × `connectionsPerRelay` (2 × 2 = 4 with the defaults), so alerts cover it.

If the token expires or is refused, the proxy logs `enrollment: relay refused: …` (`join token expired`, `already used`, or `is for <tenant>/<proxy>`) and stays not ready; NeuBird makes a new token. A new key (a reinstall without the old Secret) needs a new token too.

## Deploy the proxy

Use the Helm chart (`deploy/helm/neubird-proxy`) with `mode: tunnel`.

### 1. Secret

```sh
kubectl create namespace neubird
read -rs JOIN   # paste the join token; it isn't echoed or kept in shell history
kubectl -n neubird create secret generic neubird-proxy-env \
  --from-literal=NEUBIRD_JOIN_TOKEN="$JOIN"
unset JOIN
```

Add `REDACTION_HMAC_KEY` (32+ characters) if the values use `mask: hmac`.

### 2. Values

Fill in [`values.yaml`](values.yaml), then:

```sh
helm install neubird-proxy ./neubird-proxy -n neubird -f values.yaml \
  --set-file relayCA.cert=relay-ca.crt
```

Notes:
- **`tunnel.proxy`** must be the name the join token is for.
- **Egress:** the cluster must reach the relay on 443 (the addresses above) and Splunk. `networkPolicy.relayCIDRs` and `upstreams` allow exactly those, plus the egress proxy if `extraEnv` sets one.
- **Memory limit:** keep the chart's default of 512 Mi or higher; responses are buffered up to `max_body_bytes`.

### 3. Check it

```sh
kubectl -n neubird rollout status deploy/neubird-proxy
kubectl -n neubird logs -l app=neubird-proxy --tail=-1 --prefix \
  | grep -E '"msg":"(starting|enrolled with the join token|key already enrolled|tunnel connected|tunnel connect failed|risky configuration)"'
kubectl -n neubird exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml
kubectl -n neubird exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml https://splunk.corp.example:8089
```

The pods turn ready only once a tunnel is up. The `starting` line should show `"tunnel":true`. A `risky configuration` warning for `client_auth: none` is expected. Once the proxy has enrolled, delete `NEUBIRD_JOIN_TOKEN` from the Secret; it can't be used again anyway.

## Connect NeuBird

In NeuBird, add Splunk as a connection, with its URL (for example `https://splunk.corp.example:8089/services/mcp`) and its token, then choose access through the NeuBird proxy. The relay is fixed for MetLife's NeuBird deployment, and there is no proxy token to enter.

On this path the Splunk token is held by NeuBird, in the connection, and sent with each request; the proxy forwards it only to hosts in `neubird_destinations.hosts`.

**Writes through MCP.** A tool call can carry any SPL. The proxy's `request_deny_patterns` block SPL that writes, sends data or reaches other systems (including `| rest`), and nothing else on this path does: there is no APIM to restrict paths. Give the Splunk token a read-only role, and extend the patterns if your Splunk has other write commands.

## Splunk directly or through APIM

The tunnel works either way; what differs is the proxy's upstream. This guide calls Splunk directly. metlifemirror's stand-in proxy (namespace `metlifemirror-proxy` on NeuBird's prod_cluster) goes through MetLife's APIM instead, because it runs outside MetLife's network.

| | Through APIM (metlifemirror stand-in) | Directly (this guide) |
|---|---|---|
| Proxy's upstream | `https://int.apis.metlife.com/external/poc/splunk` | `https://splunk.metlife.com:8089` |
| Network | Reachable from the internet | Only inside MetLife's network: the proxy must run there |
| Splunk credential | APIM adds it | Sent with each request: a token with a read-only role |
| APIM subscription key | Sent with each request | None |
| Splunk's certificate | Public (the gateway's) | Possibly MetLife's internal CA: add it as `upstreamCA` |
| Paths and methods | APIM's published operations, then the proxy | The proxy only |
| Writes inside searches | `request_deny_patterns` | `request_deny_patterns`: the only guard |
| Gateway or WAF refusals | Possible (fast 403s before Splunk sees the search) | None |

Unchanged either way: the relay, the tunnel and NeuBird's connection URL (`http://neubird-relay.metlifemirror.svc.cluster.local:8080/...`).

To move the stand-in from APIM to Splunk directly:
1. Point its upstream at `https://splunk.metlife.com:8089`.
2. Replace the APIM subscription key with a read-only Splunk token, sent as `Authorization: Splunk <token>`, and remove the key from the Secret.
3. Add MetLife's CA bundle if Splunk's certificate comes from it.
4. Give the proxy a route to `splunk.metlife.com:8089`. From NeuBird's prod_cluster there is none today; that needs a private link into MetLife, or the proxy moved into MetLife's network (the rest of this guide).

Check reachability from a proxy pod before switching (DNS, TCP and TLS only; no request is sent):

```sh
kubectl -n <namespace> exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml https://splunk.metlife.com:8089
```

## Cutting NeuBird off

Either, at any time:
- scale the Deployment to 0 (`kubectl -n neubird scale deploy/neubird-proxy --replicas=0`): the tunnels close and nothing reaches MetLife;
- ask NeuBird to revoke the key at the relay.

To rotate the tunnel key, see the chart's README (Operate).
