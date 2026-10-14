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
| Relay address | `metlife-tunnel.neubird.ai:443` |
| Relay IPs | Fixed, one per zone (NeuBird sends them) |
| Tenant | `metlife` |
| Relay CA certificate | `relay-ca.crt` |
| Join token (**secret**, single use, 72 h) | `nbjt_…`, for the proxy name, e.g. `aks-prod` |

Allow outbound TCP 443 to the relay IPs **without TLS inspection** (a plain CONNECT proxy is fine; set it with `extraEnv`). MetLife sends nothing back.

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

Add `REDACTION_HMAC_KEY` (32+ characters) if the values use `mask: hmac`.

### 2. Values

Fill in [`values.yaml`](values.yaml), then:

```sh
helm install neubird-proxy ./neubird-proxy -n neubird -f values.yaml \
  --set-file relayCA.cert=relay-ca.crt
```

Notes:
- **`tunnel.proxy`** must be the name the join token is for. Use the image NeuBird names, by digest.
- **Egress:** relay on 443, Splunk and ServiceNow. ServiceNow has no fixed IPs, so route it and the relay through your egress proxy (`extraEnv` `HTTPS_PROXY`, `NO_PROXY` covering Splunk; allow the proxy in `networkPolicy.upstreams`), or use an FQDN-aware egress policy. The egress proxy URL must be `http://`, with Basic authentication at most (`http://user:password@host:3128`; not NTLM or Kerberos); with a password, put `HTTPS_PROXY` in the Secret rather than `extraEnv`.
- **Splunk's certificate** must name the host in `hosts` (the default one on 8089 doesn't); its CA goes in `upstreamCA`.
- **ServiceNow:** use a read-only API key (`x-sn-apikey`; needs an API Key authentication profile and REST API access policy) or basic auth. `host_methods` limits it to GET and HEAD, so not OAuth: its token refresh is a POST to the instance.
- **Splunk:** the MCP URL needs Splunk's MCP Server app; without it, add Splunk as a Splunk (REST) connection.
- **Memory:** keep 640 Mi for the 20 MiB `max_body_bytes`.

For an install NeuBird runs (or a test setup), `deploy/scripts/install-tunnel.sh` from NeuBird's repository does steps 1–3 in one go: it adds the join token to the Secret, installs, waits for enrollment and the tunnels, tests each system, and removes the spent token:

```sh
KUBE_CONTEXT=<context> NAMESPACE=neubird VALUES=values.yaml RELAY_CA=relay-ca.crt \
  JOIN_TOKEN_FILE=join.token UPSTREAM_CA=metlife-ca.pem deploy/scripts/install-tunnel.sh
```

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

### 4. If it doesn't work

| What you see | Usually | Fix |
|---|---|---|
| `ImagePullBackOff` / `CreateContainerConfigError` | Image not in your registry / Secret missing | Import the image (`imagePullSecrets`) / create the Secret |
| `tunnel connect failed … no such host`, `i/o timeout` | DNS or port 443 to the relay IPs blocked | Firewall, `networkPolicy.relayCIDRs`, or the egress proxy |
| `outbound proxy … refused CONNECT: 407` / `only http:// proxies` | Egress proxy login / URL scheme | Basic credentials in `HTTPS_PROXY` (in the Secret); an `http://` URL |
| `tls: … certificate signed by unknown authority` | TLS inspection on the relay host, or the wrong `relay-ca.crt` | No inspection for `metlife-tunnel.neubird.ai`; check `relayCA.cert` |
| `enrollment: relay refused: …` | Token expired or used, or `tunnel.proxy` not the token's name | New token from NeuBird; fix `tunnel.proxy` |
| `relay refused the tunnel (… unrecorded …)` | No join token in the Secret, or a new key | Add `NEUBIRD_JOIN_TOKEN` and restart |
| `test`: `FAIL dns` / `FAIL tcp` | The pod can't reach the system | `networkPolicy.upstreams`, `NO_PROXY`, the egress proxy's allowlist |
| `test`: `FAIL tls` | Splunk's certificate: not your CA in `upstreamCA`, or wrong name | `upstreamCA`; a certificate for the host in `hosts` |
| NeuBird: `destination_not_allowed` (403) | The connection's host isn't in `hosts` | Add it |
| NeuBird: 401/403 from Splunk or ServiceNow | The credential or its role | Fix it in the connection |
| NeuBird: 405 from ServiceNow | A write, or OAuth | Expected for writes; use an API key or basic auth |
| NeuBird: 404 on `/services/mcp` | No MCP Server app | A Splunk (REST) connection |

Log lines `GET`/`DELETE … /services/mcp 405` are MCP's stream and session calls: expected.

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
