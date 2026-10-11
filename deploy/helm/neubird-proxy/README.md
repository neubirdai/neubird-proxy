# neubird-proxy Helm chart

NeuBird's proxy, run in **your** cluster. It opens outbound mTLS tunnels to
your dedicated NeuBird relay (port 443) and serves NeuBird's requests to the
internal APIs you allow, with your credentials added here and sensitive
values redacted before anything leaves. Nothing connects in to it.

```
NeuBird ── relay ⇄ (tunnel, opened from your side, :443) ⇄ neubird-proxy ──▶ your API (Splunk, ...)
```

## What you get from NeuBird

| Item | Used as |
|---|---|
| The image (shipped separately) | Load into your registry → `image.repository`, `image.digest` |
| Relay address, e.g. `acme.tunnel.neubird.ai:443`, and its IPs | `tunnel.relays`; `networkPolicy.relayCIDRs`, firewall egress |
| Your tenant name | `tunnel.tenant` |
| `relay-ca.crt` (public) | `--set-file relayCA.cert=relay-ca.crt` |
| A **join token** (secret, works once, expires) | `NEUBIRD_JOIN_TOKEN` in your env Secret |

## What you send NeuBird

**Nothing**, with a join token: the proxy enrolls its own key on first
connect. (Without one, only the key's **fingerprint**, after install.) The
key itself, the proxy token's value, and your API credentials stay with
you.

## Install

1. Create the environment Secret (or sync it from your secret store):
   ```sh
   kubectl create namespace neubird
   kubectl -n neubird create secret generic neubird-proxy-env \
     --from-literal=NEUBIRD_PROXY_TOKEN=$(openssl rand -hex 32) \
     --from-literal=REDACTION_HMAC_KEY=$(openssl rand -hex 32) \
     --from-literal=NEUBIRD_JOIN_TOKEN=nbjt_... \
     --from-literal=APIM_SUBSCRIPTION_KEY=...
   ```
   `NEUBIRD_JOIN_TOKEN` is the token NeuBird gave you; add one
   `--from-literal` per credential your connections use (here an API gateway
   key).
2. Write your values (start from `examples/splunk-apim.yaml`) and install:
   ```sh
   helm install neubird-proxy ./neubird-proxy -n neubird -f my-values.yaml \
     --set-file relayCA.cert=relay-ca.crt
   ```
   The proxy enrolls its key with the join token and the pods turn Ready
   within seconds (their log says `enrolled with the join token`).
3. Create the connection in NeuBird's UI with the URL NeuBird gives you and,
   as its token, `NEUBIRD_PROXY_TOKEN` from step 1.

Once enrolled, you may delete `NEUBIRD_JOIN_TOKEN` from the Secret: the
relay knows the key. **Without a join token**, install without `--wait`,
then send NeuBird the fingerprint (`kubectl -n neubird exec
deploy/neubird-proxy -- /neubird-proxy fingerprint
/etc/neubird-proxy/tunnel/tunnel.key`); the pods turn Ready once NeuBird
records it.

## Values

| Value | Required | |
|---|---|---|
| `image.repository`, `image.digest` (or `image.tag`) | yes | Where you loaded the image |
| `tunnel.relays`, `tunnel.tenant`, `tunnel.proxy` | yes | From NeuBird; `proxy` is your name for this deployment |
| `relayCA.cert` or `relayCA.existingConfigMap` | yes | The relay CA NeuBird sent (key `relay-ca.crt`) |
| `env.existingSecret` | yes | Your Secret: `NEUBIRD_PROXY_TOKEN`, `REDACTION_HMAC_KEY`, connection credentials |
| `config` | yes | Connections, redaction, limits: see `config.example.yaml` in the neubird-proxy repository. `${VAR}` comes from `env` |
| `tunnel.joinTokenEnv` | default `NEUBIRD_JOIN_TOKEN` | Env var with NeuBird's join token; empty or missing means send the fingerprint instead |
| `tunnelKey.generate` | default `true` | Key generated in a Secret at install, kept on upgrade and uninstall |
| `tunnelKey.existingSecret` | | Bring your own key (`neubird-proxy keygen`), key `tunnel.key` |
| `networkPolicy.enabled` | default `false` | No inbound; outbound only DNS, `relayCIDRs`:443, `upstreams` |
| `replicaCount` | default `2` | NeuBird monitors `replicaCount × tunnel.connectionsPerRelay` tunnels |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `priorityClassName`, `podAnnotations`, `podLabels`, `imagePullSecrets` | | As usual |

With `helm template` (GitOps), the generated key would land in your rendered
YAML: use `tunnelKey.existingSecret` with a key made by `neubird-proxy keygen`.

## Security properties

- Runs as non-root (65532), read-only root filesystem, no capabilities,
  `RuntimeDefault` seccomp: fits Pod Security `restricted`.
- No service-account token, no RBAC, no CRDs, no cluster-scoped objects.
- Only outbound connections; the admin port (9090: health, metrics) isn't exposed.
- Rollouts wait for a tunnel on each new replica, so a bad key or CA stops
  the rollout instead of taking the proxy down.

## Operate

- **Cut NeuBird off**: change `NEUBIRD_PROXY_TOKEN` (requests fail at once),
  or scale to 0 (tunnels close).
- **Rotate the key**: create a new key Secret, send NeuBird its fingerprint,
  switch `tunnelKey.existingSecret` once NeuBird confirms.
- **Upgrade**: load the new image, set `image.digest`, `helm upgrade`. The key is kept.
