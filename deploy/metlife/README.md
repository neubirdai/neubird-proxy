# neubird-proxy at MetLife

```
NeuBird ─▶ relay ⇄ tunnel (outbound :443, mutual TLS) ⇄ neubird-proxy (AKS) ─▶ Splunk, ServiceNow
```

The proxy runs in MetLife's AKS and dials out to NeuBird's relay; NeuBird's requests come back down that tunnel. Nothing connects in to MetLife. The proxy calls Splunk and ServiceNow directly, checks every request and redacts every response. There is no proxy token (`client_auth: none`).

| File | What it is |
|---|---|
| [`values.yaml`](values.yaml) | Helm values for the chart's tunnel mode |

## What NeuBird sends MetLife

| Item | Value |
|---|---|
| Relay address | `metlifemirror-tunnel.cluster.neubird.ai:443` |
| Relay IPs | `3.231.28.52`, `32.196.200.125` |
| Tenant | `metlifemirror` |
| Relay CA certificate | `relay-ca.crt` |
| Join token (**secret**, single use) | `nbjt_…`, for proxy `dryrun`; expires 2026-10-17 03:40 UTC |
| Helm chart | A neubird-proxy checkout (`deploy/helm/neubird-proxy`) |

Allow outbound TCP 443 to the relay IPs **without TLS inspection** (a plain CONNECT proxy is fine; uncomment `extraEnv` in the values). MetLife sends nothing back.

## Enrolling the proxy's key: join token

The chart generates the proxy's tunnel key in a Secret; it never leaves MetLife's cluster. Put the join token in the proxy's Secret (below): on first connect the proxy presents it, the relay records the key, and the tunnels open.

If enrollment fails, the proxy logs `enrollment: relay refused: …` (e.g. `join token expired` or `already used`) and stays not ready. Ask NeuBird for a new token; a reinstall with a new key needs one too.

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

**Optional, HMAC masking.** The proxy masks sensitive values in responses. With `mask: label` (the default) each becomes a label such as `[EMAIL]`. With `mask: hmac` each becomes a keyed code, so the same value always masks the same way and NeuBird can correlate it without seeing it. For `hmac`, add a key to the Secret and set `mask: hmac` in the values:

```sh
kubectl -n neubird patch secret neubird-proxy-env --type=merge \
  -p "{\"stringData\":{\"REDACTION_HMAC_KEY\":\"$(openssl rand -hex 32)\"}}"
```

The key must be at least 32 characters. Keep it in MetLife's secret store and never send it to NeuBird: anyone with the key can test guesses against masked values. Unlike the join token, leave it in place; changing it changes every code.

### 2. Values

[`values.yaml`](values.yaml) is filled in for MetLife except the hosts. Replace these two lines under `config.neubird_destinations.hosts` with your Splunk host and port and your ServiceNow instance:

```yaml
    hosts:
      - <splunk host>:8089
      - <instance>.service-now.com
```

**Dry run:** use NeuBird's dev systems instead:

```yaml
    hosts:
      - splunk-e2e.tools.neubird.ai
      - dev439803.service-now.com
```

Everything else is set: the image (by digest), the relay, tenant and proxy name (`dryrun`, which the join token is for), and the relay's IPs.

Optional, each commented in the file:
- `upstreamCA`: your internal CA bundle, if Splunk's certificate comes from it.
- `extraEnv`: your egress proxy, if the cluster reaches the internet through one.
- `networkPolicy`: off by default; turn it on with your Splunk range and egress proxy (see Locking down the network).
- `redaction.mask: hmac`, if you added the key in step 1.
- `image.repository`: your registry's copy, if the cluster can't pull from Docker Hub. Keep the digest.

Then install:

```sh
helm install neubird-proxy deploy/helm/neubird-proxy -n neubird -f values.yaml \
  --set-file relayCA.cert=relay-ca.crt
```

The join token isn't passed here: the chart reads it from the Secret in step 1.

Notes:
- **Egress:** ServiceNow has no fixed IPs, so a NetworkPolicy can't allow it by CIDR. Route it and the relay through your egress proxy, or use an FQDN-aware egress policy. The egress proxy must not inspect TLS to the relay.
- **Splunk's certificate** must name the host in `hosts`. Splunk's default certificate on 8089 names none and fails verification.
- **ServiceNow:** use a read-only API key (`x-sn-apikey`) or OAuth/basic auth. `host_methods` limits it to GET and HEAD.
- **Memory:** keep the 640 Mi limit for the 20 MiB `max_body_bytes`.

### 3. Check it

```sh
kubectl -n neubird rollout status deploy/neubird-proxy --timeout=5m
kubectl -n neubird exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml \
  https://<splunk host>:8089 https://<instance>.service-now.com
```

It passes if the rollout completes and the test reports no failures: the pods turn ready only once the proxy has enrolled and a tunnel is up, and the test checks each system answers. If it fails, the logs say why: `kubectl -n neubird logs -l app=neubird-proxy --tail=50 --prefix`. A `risky configuration` warning for `client_auth: none` is expected.

Once it passes, delete the spent join token from the Secret; it can't be used again anyway:

```sh
kubectl -n neubird patch secret neubird-proxy-env --type=json -p '[{"op":"remove","path":"/data/NEUBIRD_JOIN_TOKEN"}]'
```

## Locking down the network

In tunnel mode the proxy accepts no connections and needs only four outbound destinations. Box it in at three layers; the chart can render the first (off by default in the values).

| Direction | Peer | Port | Why |
|---|---|---|---|
| Inbound | nothing (optionally Prometheus) | 9090 | Health and metrics only; no Service, no load balancer |
| Outbound | cluster DNS | 53 | Name resolution |
| Outbound | relay `metlifemirror-tunnel.cluster.neubird.ai` (`3.231.28.52`, `32.196.200.125`) | 443 | The tunnel |
| Outbound | Splunk | 8089 | Inside MetLife's network |
| Outbound | `<instance>.service-now.com` | 443 | SaaS, no fixed addresses |

**1. Kubernetes NetworkPolicy.** Setting `networkPolicy.enabled: true` (off in the values) renders a policy with no ingress at all, and egress only to DNS, `relayCIDRs` on 443, and `upstreams` (Splunk, the egress proxy). Set `metricsFrom` to let Prometheus scrape :9090; leave it empty to block that too. Also:
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
      - toFQDNs: [{matchName: "<instance>.service-now.com"}, {matchName: "metlifemirror-tunnel.cluster.neubird.ai"}]
        toPorts: [{ports: [{port: "443", protocol: TCP}]}]
  ```

**2. Azure network.** Route the node subnet's outbound traffic (a route for `0.0.0.0/0`) through Azure Firewall, with application rules for `metlifemirror-tunnel.cluster.neubird.ai:443` and `<instance>.service-now.com:443` and a network rule for Splunk's range on 8089. No TLS inspection on the relay host (the tunnel is mutual TLS end to end); inspecting ServiceNow also breaks it unless the inspection CA is added to `upstreamCA`. No inbound rule, public IP or load balancer is needed. A dedicated node pool (taints and tolerations) keeps these rules from widening anything else.

**3. The proxy itself**, whatever the network allows:
- It calls only the hosts in `neubird_destinations.hosts`, never an IP address not listed, and never a loopback, link-local (including the cloud metadata address 169.254.169.254) or unspecified address, whatever a name resolves to. Through an egress proxy the proxy connects to that proxy instead, which resolves the name: the hosts allowlist still applies, and the egress proxy's own allowlist should match it.
- Methods are restricted (ServiceNow GET and HEAD via `host_methods`), SPL that writes or sends is refused, requests are rate limited, and responses are size-capped and redacted.
- The pod runs as a non-root user with a read-only filesystem, no capabilities, no privilege escalation and the runtime's default seccomp profile; it has no Kubernetes API token, and its tunnel key is readable only by its group.

With all three, the pod can reach only DNS, the egress proxy (or the firewall's allowed names) and Splunk.

## Connect NeuBird

In metlifemirror's NeuBird, add each system as a connection and choose access through the NeuBird proxy. Only metlifemirror's NeuBird can reach this relay. There is no proxy token to enter.

| System | URL | Credential |
|---|---|---|
| Splunk | `https://<splunk host>:8089/services/mcp` | Splunk token (read-only role) |
| ServiceNow | `https://<instance>.service-now.com` | API access key (read-only role) |

For the dry run: Splunk `https://splunk-e2e.tools.neubird.ai` and ServiceNow `https://dev439803.service-now.com`, with the dev credentials from NeuBird engineering.

On this path the credentials are held by NeuBird, in the connections, and sent with each request; the proxy forwards each only to its own system, which must be in `neubird_destinations.hosts`.

**Writes through MCP.** A tool call can carry any SPL. The proxy's `request_deny_patterns` block SPL that writes, sends data or reaches other systems (including `| rest`), and nothing in front of Splunk does. Give the Splunk token a read-only role, and extend the patterns if your Splunk has other write commands.
