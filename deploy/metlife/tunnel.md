# neubird-proxy at MetLife: through the tunnel

This guide covers the path NeuBird → relay → tunnel → neubird-proxy → Splunk. The proxy runs in MetLife's AKS and opens outbound tunnels to NeuBird's relay for MetLife; NeuBird's requests come back down those tunnels. Nothing connects in to MetLife, and there is no APIM on this path. (For the APIM path, see [README.md](README.md).)

| File | What it is |
|---|---|
| [`values-tunnel.yaml`](values-tunnel.yaml) | Helm values for the chart's tunnel mode |

## What NeuBird sends MetLife

| Item | Secret | Value |
|---|---|---|
| Relay address | no | `metlifemirror-tunnel.cluster.neubird.ai:443` |
| Relay IP addresses, for the egress firewall | no | `3.231.28.52`, `32.196.200.125` |
| Tenant | no | `metlifemirror` |
| Relay CA certificate, `relay-ca.crt` | no | "NeuBird relay CA for metlifemirror" |
| Join token (`nbjt_…`) | **yes**, works once, expires in 72 hours | For the proxy name MetLife will use, e.g. `aks-prod` |

The relay's IP addresses stay the same unless NeuBird recreates its load balancer; NeuBird tells MetLife before that happens.

## Enrolling the proxy's key: join token

The proxy's tunnel key is its identity at the relay. The chart generates it in a Secret in MetLife's cluster, and it never leaves that cluster. The join token lets the proxy enroll that key itself on its first connect, so nothing has to be sent back to NeuBird.

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

### 1. Secrets

```sh
kubectl create namespace neubird
read -rs JOIN   # paste the join token; it isn't echoed or kept in shell history
kubectl -n neubird create secret generic neubird-proxy-env \
  --from-literal=NEUBIRD_PROXY_TOKEN=$(openssl rand -hex 32) \
  --from-literal=NEUBIRD_JOIN_TOKEN="$JOIN"
unset JOIN
```

The proxy token is the one NeuBird's connection sends; MetLife enters it in NeuBird (see Connect NeuBird).

### 2. Values

Fill in [`values-tunnel.yaml`](values-tunnel.yaml), then:

```sh
helm install neubird-proxy ./neubird-proxy -n neubird -f values-tunnel.yaml \
  --set-file relayCA.cert=relay-ca.crt
```

Notes:
- **`tunnel.proxy`** must be the name the join token is for.
- **Egress:** the cluster must reach the relay on 443 (the addresses above) and Splunk. `networkPolicy.relayCIDRs` and `upstreams` allow exactly those.
- **Memory limit:** keep the chart's default of 512 Mi or higher; responses are buffered up to `max_body_bytes`.

### 3. Check it

```sh
kubectl -n neubird rollout status deploy/neubird-proxy
kubectl -n neubird logs -l app=neubird-proxy --tail=-1 --prefix \
  | grep -E '"msg":"(starting|enrolled with the join token|key already enrolled|tunnel connected|tunnel connect failed|risky configuration)"'
kubectl -n neubird exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml
kubectl -n neubird exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml https://splunk.corp.example:8089
```

The pods turn ready only once a tunnel is up. The `starting` line should show `"tunnel":true`. Once the proxy has enrolled, delete `NEUBIRD_JOIN_TOKEN` from the Secret; it can't be used again anyway.

## Connect NeuBird

In NeuBird, add Splunk as a connection, with its URL (for example `https://splunk.corp.example:8089/services/mcp`) and its token, then choose access through the NeuBird proxy and enter:
- the **relay URL** NeuBird gives you;
- the **proxy token**:
  ```sh
  kubectl -n neubird get secret neubird-proxy-env -o jsonpath='{.data.NEUBIRD_PROXY_TOKEN}' | base64 -d
  ```

On this path the Splunk token is held by NeuBird, in the connection, and sent with each request; the proxy forwards it only to hosts in `neubird_destinations.hosts`.

**Writes through MCP.** A tool call can carry any SPL. The proxy's `request_deny_patterns` block SPL that writes, sends data or reaches other systems (including `| rest`), and nothing else on this path does: there is no APIM to restrict paths. Give the Splunk token a read-only role, and extend the patterns if your Splunk has other write commands.

## Cutting NeuBird off

Any of these, at any time:
- scale the Deployment to 0;
- change `NEUBIRD_PROXY_TOKEN` in the Secret and run `kubectl -n neubird rollout restart deploy/neubird-proxy` (pods read the token at startup);
- ask NeuBird to revoke the key at the relay.
