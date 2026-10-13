# neubird-proxy at MetLife: through the tunnel

```
NeuBird ─▶ relay ⇄ tunnel (dialed out by the proxy, :443, mutual TLS) ⇄ neubird-proxy (AKS) ─▶ Splunk, ServiceNow
```

The proxy runs in MetLife's AKS and opens outbound tunnels to NeuBird's relay for MetLife; NeuBird's requests come back down those tunnels. Nothing connects in to MetLife: no load balancer, no inbound firewall rule. The proxy calls Splunk and ServiceNow directly, with no gateway in between; it checks every request and redacts every response before it leaves MetLife.

There is no proxy token (`client_auth: none`): a request is accepted because it arrives over a tunnel this proxy opened, to a relay it verified, with a key the relay has pinned. Cutting NeuBird off is scaling to 0 (below).

| File | What it is |
|---|---|
| [`values.yaml`](values.yaml) | Helm values for the chart's tunnel mode |

## What NeuBird sends MetLife

| Item | Secret | Value |
|---|---|---|
| Relay address | no | `metlife-tunnel.neubird.ai:443` |
| Relay IP addresses, for the egress firewall | no | Fixed addresses, one per zone (NeuBird sends them) |
| Tenant | no | `metlife` |
| Relay CA certificate, `relay-ca.crt` | no | "NeuBird relay CA for metlife" |
| Join token (`nbjt_…`) | **yes**, works once, expires in 72 hours | For the proxy name MetLife will use, e.g. `aks-prod` |

The relay's IP addresses are reserved for MetLife and don't change; if they ever must, NeuBird tells MetLife first.

Allow outbound TCP 443 to those addresses **without TLS inspection**: the tunnel is mutual TLS with pinned keys, so a proxy that re-signs TLS breaks it. A plain forwarding (CONNECT) proxy is fine; set it with `extraEnv` in the values.

MetLife sends nothing back: the proxy enrolls its own key with the join token.

## Enrolling the proxy's key: join token

The proxy's tunnel key is its identity at the relay. The chart generates it in a Secret in MetLife's cluster, and it never leaves that cluster. The join token lets the proxy enroll that key itself on its first connect.

**NeuBird, before MetLife installs:**

1. Make a join token for the proxy name MetLife will use:
   ```sh
   neubird-relay join-token -tenant metlife -proxy <proxy name> -ttl 72h
   ```
2. Add the record it prints (the token's hash, not secret) under that proxy in the metlife relay's `tenants.yaml`, ConfigMap `neubird-relay-tenants` in namespace `metlife`. The relay picks it up without a restart.
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
- **Image:** use the release NeuBird names (with `client_auth: none` and `host_methods`), by digest.
- **Egress:** the proxy reaches the relay on 443 (the addresses above), Splunk, and ServiceNow.
  - ServiceNow is SaaS without fixed addresses, so a NetworkPolicy can't allow it by CIDR: send it, and the relay tunnel, through your egress proxy (`extraEnv` `HTTPS_PROXY`), and allow that proxy in `networkPolicy.upstreams`. `NO_PROXY` must cover the Splunk host.
  - The egress proxy must allow CONNECT to `metlife-tunnel.neubird.ai:443` and must not inspect TLS on it: the tunnel is mutual TLS end to end.
  - Without an egress proxy, use an FQDN-aware egress policy (Azure Firewall, Cilium) for `<instance>.service-now.com`.
- **Splunk's certificate:** it must name the host in `hosts` (Splunk's default certificate on 8089 names none and fails verification), and its CA goes in `upstreamCA`.
- **ServiceNow credentials:** an API key travels in `x-sn-apikey`, OAuth or basic auth in `Authorization`; both are in `credential_headers`. Give the key a read-only role.
- **Methods:** POST is allowed for Splunk (MCP and searches); `host_methods` keeps ServiceNow to GET and HEAD, so nothing can create records there. PUT, PATCH and DELETE are refused everywhere.
- **Memory limit:** 640 Mi (as in the values) buffers responses up to the 20 MiB `max_body_bytes`; at 512 Mi the proxy refuses responses over about 19 MiB (15 MiB with `mask: hmac`) and says so at startup.

### 3. Check it

```sh
kubectl -n neubird rollout status deploy/neubird-proxy
kubectl -n neubird logs -l app=neubird-proxy --tail=-1 --prefix \
  | grep -E '"msg":"(starting|enrolled with the join token|key already enrolled|tunnel connected|tunnel connect failed|risky configuration)"'
kubectl -n neubird exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml
kubectl -n neubird exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml \
  https://<splunk host>:8089 https://<instance>.service-now.com
```

The pods turn ready only once a tunnel is up. The `starting` line should show `"tunnel":true`. A `risky configuration` warning for `client_auth: none` is expected. Once the proxy has enrolled, delete `NEUBIRD_JOIN_TOKEN` from the Secret (`kubectl -n neubird patch secret neubird-proxy-env --type=json -p '[{"op":"remove","path":"/data/NEUBIRD_JOIN_TOKEN"}]'`); it can't be used again anyway.

## Locking down the network

In tunnel mode the proxy accepts no connections and needs only four outbound destinations. Box it in at three layers; the first comes with the chart.

| Direction | Peer | Port | Why |
|---|---|---|---|
| Inbound | nothing (optionally Prometheus) | 9090 | Health and metrics only; no Service, no load balancer |
| Outbound | cluster DNS | 53 | Name resolution |
| Outbound | relay `metlife-tunnel.neubird.ai` (the addresses NeuBird sends) | 443 | The tunnel |
| Outbound | Splunk | 8089 | Inside MetLife's network |
| Outbound | `<instance>.service-now.com` | 443 | SaaS, no fixed addresses |

**1. Kubernetes NetworkPolicy.** `networkPolicy.enabled: true` (as in the values) renders a policy with no ingress at all, and egress only to DNS, `relayCIDRs` on 443, and `upstreams` (Splunk, the egress proxy). Set `metricsFrom` to let Prometheus scrape :9090; leave it empty to block that too. Also:
- The cluster must enforce NetworkPolicy (AKS `--network-policy azure`, `calico` or `cilium`); without it the policy is stored but does nothing.
- Deny everything else in the namespace by default, so any other pod placed there is boxed in too:
  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata: {name: default-deny, namespace: neubird}
  spec: {podSelector: {}, policyTypes: [Ingress, Egress]}
  ```
- ServiceNow has no fixed addresses, so it can't be allowed by CIDR. Either send it (and the relay) through the egress proxy, so the pod reaches only that proxy and the proxy's allowlist decides; or, with Cilium, allow it by name:
  ```yaml
  apiVersion: cilium.io/v2
  kind: CiliumNetworkPolicy
  metadata: {name: neubird-proxy-fqdn, namespace: neubird}
  spec:
    endpointSelector: {matchLabels: {app.kubernetes.io/name: neubird-proxy}}
    egress:
      - toEndpoints: [{matchLabels: {k8s-app: kube-dns, io.kubernetes.pod.namespace: kube-system}}]
        toPorts: [{ports: [{port: "53", protocol: ANY}], rules: {dns: [{matchPattern: "*"}]}}]
      - toFQDNs: [{matchName: "<instance>.service-now.com"}, {matchName: "metlife-tunnel.neubird.ai"}]
        toPorts: [{ports: [{port: "443", protocol: TCP}]}]
  ```

**2. Azure network.** Route the node subnet's outbound traffic (a route for `0.0.0.0/0`) through Azure Firewall, with application rules for `metlife-tunnel.neubird.ai:443` and `<instance>.service-now.com:443` and a network rule for Splunk's range on 8089. No TLS inspection on the relay host (the tunnel is mutual TLS end to end); inspecting ServiceNow also breaks it unless the inspection CA is added to `upstreamCA`. No inbound rule, public IP or load balancer is needed. A dedicated node pool (taints and tolerations) keeps these rules from widening anything else.

**3. The proxy itself**, whatever the network allows:
- It calls only the hosts in `neubird_destinations.hosts`, never an IP address not listed, and never a loopback, link-local (including the cloud metadata address 169.254.169.254) or unspecified address, whatever a name resolves to. Through an egress proxy the proxy connects to that proxy instead, which resolves the name: the hosts allowlist still applies, and the egress proxy's own allowlist should match it.
- Methods are restricted (ServiceNow GET and HEAD via `host_methods`), SPL that writes or sends is refused, requests are rate limited, and responses are size-capped and redacted.
- The pod runs as a non-root user with a read-only filesystem, no capabilities, no privilege escalation and the runtime's default seccomp profile; it has no Kubernetes API token, and its tunnel key is readable only by its group.

With all three, the pod can reach only DNS, the egress proxy (or the firewall's allowed names) and Splunk.

## Connect NeuBird

In NeuBird, add each system as a connection and choose access through the NeuBird proxy. The relay is fixed for MetLife's NeuBird deployment, and there is no proxy token to enter.

| System | URL | Credential |
|---|---|---|
| Splunk | `https://<splunk host>:8089/services/mcp` | Splunk token (read-only role) |
| ServiceNow | `https://<instance>.service-now.com` | API access key (read-only role) |

On this path the credentials are held by NeuBird, in the connections, and sent with each request; the proxy forwards each only to its own system, which must be in `neubird_destinations.hosts`.

**Writes through MCP.** A tool call can carry any SPL. The proxy's `request_deny_patterns` block SPL that writes, sends data or reaches other systems (including `| rest`), and nothing in front of Splunk does. Give the Splunk token a read-only role, and extend the patterns if your Splunk has other write commands.

## Cutting NeuBird off

Either, at any time:
- scale the Deployment to 0 (`kubectl -n neubird scale deploy/neubird-proxy --replicas=0`): the tunnels close and nothing reaches MetLife;
- ask NeuBird to revoke the key at the relay.

To rotate the tunnel key, see the chart's README (Operate).
