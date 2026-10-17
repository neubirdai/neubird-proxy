# neubird-proxy at MetLife

```
NeuBird ─▶ relay ⇄ tunnel (outbound :443, mutual TLS) ⇄ neubird-proxy (AKS) ─▶ Splunk, ServiceNow, ...
```

The proxy runs in MetLife's AKS and dials out to NeuBird's relay; NeuBird's requests come back down that tunnel. Nothing connects in to MetLife. The proxy calls MetLife's systems directly, checks every request and redacts every response. There is no proxy token (`client_auth: none`): requests are accepted because they arrive over the tunnel this proxy opened.

| File | What it is |
|---|---|
| [`install.sh`](install.sh) | Installs and checks the proxy from a few parameters |
| [`values.yaml`](values.yaml) | Helm values for the chart's tunnel mode (install.sh starts from these) |

## What NeuBird sends MetLife

| Item | Value |
|---|---|
| Relay address | `metlife-tunnel.cluster.neubird.ai:443` |
| Relay IPs | `52.206.84.184`, `23.23.64.142` |
| Tenant and proxy name | `metlife` (the proxy is named after the tenant) |
| Relay CA certificate | `relay-ca.crt` (public) |
| Join token (**secret**, single use) | `nbjt_…`, for proxy `metlife/metlife`, with its expiry |
| Helm chart and scripts | A neubird-proxy checkout (`deploy/helm/neubird-proxy`, `deploy/metlife`, `deploy/scripts`) |

Allow outbound TCP 443 to the relay IPs **without TLS inspection**: the tunnel is mutual TLS end to end. A plain CONNECT proxy is fine (`--egress-proxy` below). MetLife sends nothing back: the proxy enrolls its own key with the join token.

## Install

Requires kubectl, helm 3 or later and python3 with PyYAML, from a checkout with `relay-ca.crt` and the join token (in a file, e.g. `join.token`) next to it:

```sh
deploy/metlife/install.sh --kube-context <ctx> --namespace neubird --join-token-file join.token
```

In a package from NeuBird, the relay, CA and join token are preset in its `<tenant>.env`, which the script loads itself: run `install.sh` with no options, from any directory, and it installs in your current kubectl context (after showing it and asking) and namespace `neubird`; `--kube-context` and `--namespace` choose others. `install.sh --help` lists every option.

The script builds the values, creates the namespace and Secret, installs the chart, waits until the key is enrolled and the tunnels are up, tests the tunnel and each listed system, and removes the spent join token from the Secret. It then confirms the running proxy and ends with a summary:

```
== confirm (namespace neubird)
  ok    pods ready: 2/2 (a pod is ready only with a tunnel up)
  ok    tunnel to metlife-tunnel.cluster.neubird.ai:443: mutual TLS accepted by the relay
  ok    identity metlife/metlife, key sha256:…
  ok    systems reachable (DNS, TCP, TLS): splunk.metlife.com:8089
  ok    join token removed from the Secret
```

Send NeuBird the key fingerprint from that summary (it isn't secret): NeuBird checks it matches the key its relay enrolled. The script prints nothing secret. `--dry-run` writes `./neubird-proxy-values.yaml` and renders it without installing; `--confirm-only` re-runs only the confirmation on an existing install.

| Option | Required / default | What |
|---|---|---|
| `-c`, `--kube-context` | the current context, after you confirm it | kubectl context of the cluster; required when not running interactively (a script) |
| `-n`, `--namespace` | `neubird` | Namespace to install in (created if missing) |
| `--join-token-file` | first install | File holding the join token |
| `--hosts` | no | The systems NeuBird may reach, comma-separated: `host[:port]`, `*.domain[:port]` or an IP; port 443 if omitted. Default `*`: any host name the proxy can reach (see Locking down the network) |
| `--egress-proxy` | no | Forwarding proxy for the tunnel and internet systems, e.g. `http://proxy.metlife.com:3128` |
| `--egress-no-proxy` | no | Hosts reached directly rather than through `--egress-proxy` (the pod's `NO_PROXY`), e.g. `splunk.metlife.com,.metlife.com`. Your shell's own `NO_PROXY` isn't used |
| `--upstream-ca` | no | CA bundle for systems whose certificates come from MetLife's internal CA |
| `--allow-cidrs` | no | Turns on the NetworkPolicy: ranges the proxy may reach besides DNS and the relay, as `cidr:port,...`, e.g. `10.20.0.0/16:8089`. With `--egress-proxy`, also `--egress-proxy-cidr` |
| `--mask` | no | `hmac` (default, below) or `label` |
| `--image-repo` | no | Your registry's copy of the image, if the cluster can't pull from Docker Hub. Keep the digest |
| `--relay-ca` | no | Path to the relay CA certificate (default `relay-ca.crt`) |
| `--timeout` | no | Seconds to wait for the tunnels (default 300) |

Each option can also be set as its environment variable (`--kube-context` as `KUBE_CONTEXT`, `--dry-run` as `DRY_RUN=1`, and so on); a command-line option wins, and the script says when a setting came from the environment. A package's presets (its `.env` file) win over the environment, with a note when one replaces a value you set. `--uninstall`, `--purge` and `--yes` are taken only from the command line, so a variable left in your shell can't turn an install into an uninstall.

For example, Splunk and ServiceNow only, through an egress proxy for internet traffic:

```sh
deploy/metlife/install.sh -c <ctx> -n neubird --join-token-file join.token \
  --hosts 'splunk.metlife.com:8089,<instance>.service-now.com' \
  --egress-proxy http://proxy.metlife.com:3128 --egress-no-proxy splunk.metlife.com
```

It passes when every confirmation line is `ok`; it exits non-zero otherwise. If enrollment fails, the proxy logs `enrollment: relay refused: …` (e.g. `join token expired` or `already used`) and stays not ready; ask NeuBird for a new token. A reinstall with a new key (the chart's key Secret deleted) needs a new token too. A `risky configuration` warning for `client_auth: none` (and for `*` hosts) is expected.

**Changing the install later** (another system, an egress proxy): rerun `install.sh` with the full set of options, without `--join-token-file` (a package's preset token is harmless: the relay already knows the key). The key is kept, so no new token is needed; the pods restart and reconnect. Options left out are removed: for example, a `--hosts` list without Splunk cuts Splunk off.

**Uninstalling.** `install.sh -c <ctx> -n neubird --uninstall` removes the proxy (the Helm release) and keeps two Secrets: the proxy's key (`neubird-proxy-tunnel-key`, its identity at the relay) and `neubird-proxy-env` (the HMAC key). A reinstall then needs no new join token, and the masking codes stay the same. `--uninstall --purge` deletes both Secrets too, after asking you to type the namespace (`--yes` skips the question, for scripts), and prints the key's fingerprint: send it to NeuBird so the relay revokes the key. A reinstall after a purge needs a new join token. Neither removes the namespace.

Notes:
- **Methods:** every system may get any method (`"*"`: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS). Give each credential a read-only role (Splunk token, ServiceNow API key or OAuth/basic user): the roles, not the proxy, keep the systems read-only. The SPL deny patterns still apply.
- **Splunk's certificate** must name the host NeuBird uses. Splunk's default certificate on 8089 names none and fails verification; its CA goes in `--upstream-ca`.
- **Memory:** the values set a 768 Mi limit, so responses up to the 20 MiB `max_body_bytes` fit with either `--mask`; at a lower limit the proxy refuses larger responses (`body_too_large`) and logs a `risky configuration` warning.

**HMAC masking (the default).** The proxy masks sensitive values in responses. With `--mask hmac` each becomes a keyed code, so the same value always masks the same way and NeuBird can correlate it without seeing it. The script generates the key (`REDACTION_HMAC_KEY` in the Secret) if it isn't there. Keep it in MetLife's secret store and never send it to NeuBird: anyone with the key can test guesses against masked values. Leave it in place; changing it changes every code. With `--mask label` each value becomes a label such as `[EMAIL]` instead, and no key is needed.

### Install by hand

The same install without the script:

```sh
kubectl create namespace neubird
read -rs JOIN   # paste the join token; it isn't echoed or kept in shell history
kubectl -n neubird create secret generic neubird-proxy-env --from-literal=NEUBIRD_JOIN_TOKEN="$JOIN" \
  --from-literal=REDACTION_HMAC_KEY="$(openssl rand -hex 32)"   # keep it; changing it changes every code
unset JOIN
helm install neubird-proxy deploy/helm/neubird-proxy -n neubird -f deploy/metlife/values.yaml \
  --set-file relayCA.cert=relay-ca.crt
kubectl -n neubird rollout status deploy/neubird-proxy --timeout=5m
kubectl -n neubird exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml
kubectl -n neubird patch secret neubird-proxy-env --type=json -p '[{"op":"remove","path":"/data/NEUBIRD_JOIN_TOKEN"}]'
```

Review `config.neubird_destinations.hosts` in `values.yaml` first (default `*`). The pods turn ready only once the proxy has enrolled and a tunnel is up; if not, `kubectl -n neubird logs -l app=neubird-proxy --tail=50 --prefix` says why.

## Locking down the network

In tunnel mode the proxy accepts no connections. With `--hosts` left at `*`, the network is what limits which systems NeuBird can reach, so box the proxy in at one or more of these layers.

| Direction | Peer | Port | Why |
|---|---|---|---|
| Inbound | nothing (optionally Prometheus) | 9090 | Health and metrics only; no Service, no load balancer |
| Outbound | cluster DNS | 53 | Name resolution |
| Outbound | relay `metlife-tunnel.cluster.neubird.ai` (`52.206.84.184`, `23.23.64.142`) | 443 | The tunnel |
| Outbound | Splunk (and other internal systems) | e.g. 8089 | Inside MetLife's network |
| Outbound | `<instance>.service-now.com` | 443 | SaaS, no fixed addresses |

**1. Kubernetes NetworkPolicy.** `--allow-cidrs` (or by hand: `networkPolicy.enabled: true`, uncomment `relayCIDRs` and `relayPorts` in `values.yaml`, `upstreams` your ranges) renders a policy with no ingress and egress only to DNS, the relay IPs on 443, and the listed ranges (plus the egress proxy). Also:
- The cluster must enforce NetworkPolicy (AKS `--network-policy azure`, `calico` or `cilium`); without it the policy is stored but does nothing.
- Deny everything else in the namespace by default:
  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata: {name: default-deny, namespace: neubird}
  spec: {podSelector: {}, policyTypes: [Ingress, Egress]}
  ```
- ServiceNow has no fixed addresses, so it can't be allowed by CIDR. Send it (and the relay) through the egress proxy, so the pod reaches only that proxy and the proxy's allowlist decides; or, with Cilium, allow it by name:
  ```yaml
  apiVersion: cilium.io/v2
  kind: CiliumNetworkPolicy
  metadata: {name: neubird-proxy-fqdn, namespace: neubird}
  spec:
    endpointSelector: {matchLabels: {app.kubernetes.io/name: neubird-proxy}}
    egress:
      - toEndpoints: [{matchLabels: {k8s-app: kube-dns, io.kubernetes.pod.namespace: kube-system}}]
        toPorts: [{ports: [{port: "53", protocol: ANY}], rules: {dns: [{matchPattern: "*"}]}}]
      - toFQDNs: [{matchName: "<instance>.service-now.com"}, {matchName: "metlife-tunnel.cluster.neubird.ai"}]
        toPorts: [{ports: [{port: "443", protocol: TCP}]}]
  ```

**2. Azure network.** Route the node subnet's outbound traffic (`0.0.0.0/0`) through Azure Firewall, with application rules for `metlife-tunnel.cluster.neubird.ai:443` and `<instance>.service-now.com:443` and network rules for internal systems such as Splunk on 8089. No TLS inspection on the relay host; inspecting ServiceNow also breaks it unless the inspection CA is added to `--upstream-ca`. No inbound rule, public IP or load balancer is needed. A dedicated node pool (taints and tolerations) keeps these rules from widening anything else.

**3. The proxy itself**, whatever the network allows:
- It calls only hosts matching `--hosts`; `*` and `*.domain` match names, never IP literals (an IP is reached only when listed). It never calls loopback, link-local (including the cloud metadata address 169.254.169.254) or unspecified addresses, whatever a name resolves to. Through an egress proxy, the egress proxy's own allowlist applies too.
- Methods are restricted (ServiceNow GET and HEAD), SPL that writes or sends is refused, requests are rate limited, and responses are size-capped and redacted.
- The pod runs as a non-root user with a read-only filesystem, no capabilities, no privilege escalation and the runtime's default seccomp profile; it has no Kubernetes API token, and its tunnel key is readable only by its group.

## Connect NeuBird

In MetLife's NeuBird, add each system as a connection and choose access through the NeuBird proxy. The relay is fixed for MetLife's NeuBird deployment, and there is no proxy token to enter. Only MetLife's NeuBird can reach this relay.

| System | URL | Credential |
|---|---|---|
| Splunk | `https://<splunk host>:8089/services/mcp` | Splunk token (read-only role) |
| ServiceNow | `https://<instance>.service-now.com` | API access key (read-only role) |

The credentials are held by NeuBird, in the connections, and sent with each request; the proxy forwards each only to a host matching `--hosts`.

**Writes through MCP.** A tool call can carry any SPL. The proxy's `request_deny_patterns` block SPL that writes, sends data or reaches other systems (including `| rest`), and nothing in front of Splunk does. Give the Splunk token a read-only role, and extend the patterns if your Splunk has other write commands.
