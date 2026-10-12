# neubird-proxy Helm chart

NeuBird's proxy, run in **your** cluster. It opens outbound mTLS tunnels to
your dedicated NeuBird relay (port 443) and forwards NeuBird's requests to
the internal systems you allow, by host, redacting sensitive values before
anything leaves. Nothing connects in to it.

```
NeuBird ── relay ⇄ (tunnel, opened from your side, :443) ⇄ neubird-proxy ──▶ your systems (Splunk, ...)
```

You set once which hosts NeuBird may reach (`neubird_destinations`). Systems
are then added, changed and removed in NeuBird, each as a connection with
its own URL and credentials, without changing the proxy.

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
tunnel key stays with you.

Your systems' credentials and URLs are entered in NeuBird's connections:
NeuBird holds them and sends them with each request, and the proxy forwards
them only to the hosts you allow ([configuration.md](docs/configuration.md),
Credentials).

## Install

1. Create the environment Secret (or sync it from your secret store):
   ```sh
   kubectl create namespace neubird
   kubectl label namespace neubird pod-security.kubernetes.io/enforce=restricted
   printf 'NeuBird join token: '; read -rs JOIN; echo
   kubectl -n neubird create secret generic neubird-proxy-env \
     --from-literal=NEUBIRD_PROXY_TOKEN=$(openssl rand -hex 32) \
     --from-literal=REDACTION_HMAC_KEY=$(openssl rand -hex 32) \
     --from-literal=NEUBIRD_JOIN_TOKEN="$JOIN"
   unset JOIN
   ```
   `NEUBIRD_JOIN_TOKEN` is the token NeuBird gave you.
2. Write your values (start from `examples/values.yaml`) and install:
   ```sh
   helm install neubird-proxy ./neubird-proxy -n neubird -f my-values.yaml \
     --set-file relayCA.cert=relay-ca.crt
   ```
   The proxy enrolls its key with the join token and the pods turn Ready
   within seconds (their log says `enrolled with the join token`).
3. In NeuBird, add each system as a connection with its URL and
   credentials, access through the NeuBird proxy, the relay URL NeuBird
   gives you, and `NEUBIRD_PROXY_TOKEN` from step 1 as the proxy token.

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
| `env.existingSecret` | yes | Your Secret: `NEUBIRD_PROXY_TOKEN`, `REDACTION_HMAC_KEY`, `NEUBIRD_JOIN_TOKEN` |
| `config` | yes | `neubird_destinations` (the hosts NeuBird may reach), redaction, limits: see [configuration.md](docs/configuration.md). `${VAR}` comes from `env` |
| `tunnel.joinTokenEnv` | default `NEUBIRD_JOIN_TOKEN` | Env var with NeuBird's join token; empty or missing means send the fingerprint instead |
| `tunnelKey.generate` | default `true` | Key generated in a Secret at install, kept on upgrade and uninstall |
| `tunnelKey.existingSecret` | | Bring your own key (`neubird-proxy keygen`), key `tunnel.key` |
| `networkPolicy.enabled` | default `false` | No inbound; outbound only DNS, `relayCIDRs`:443, and your systems' ranges (`upstreams`) |
| `replicaCount` | default `2` | NeuBird monitors `replicaCount × tunnel.connectionsPerRelay` tunnels |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `priorityClassName`, `podAnnotations`, `podLabels`, `imagePullSecrets` | | As usual |

With `helm template` or a GitOps tool that renders with it (Argo CD), the
chart can't see the existing Secret, so it would generate a new key on every
render and replace the one in use, dropping every tunnel; the key would also
land in your rendered YAML. Use `tunnelKey.existingSecret` with a key made by
`neubird-proxy keygen`. With `helm install`, the generated key is also stored
in Helm's release record (`helm get manifest` shows it), so whoever can read
Secrets in the namespace can read it either way.

## Security properties

- Runs as non-root (65532), read-only root filesystem, no capabilities,
  `RuntimeDefault` seccomp: fits Pod Security `restricted`.
- No service-account token, no RBAC, no CRDs, no cluster-scoped objects.
- Only outbound connections. The admin port (9090: health, metrics) has no
  Service; with `networkPolicy.enabled` only `metricsFrom` reaches it.
- Rollouts wait for a tunnel on each new replica, so a bad key or CA stops
  the rollout instead of taking the proxy down.

## Operate

- **Cut NeuBird off**: scale to 0 (tunnels close at once), or change
  `NEUBIRD_PROXY_TOKEN` and `kubectl rollout restart` the Deployment: the
  token is read at startup, so running pods accept the old one until they
  restart.
- **Rotate the key**: create a new key Secret, send NeuBird its fingerprint,
  switch `tunnelKey.existingSecret` once NeuBird confirms.
- **Upgrade**: load the new image, set `image.digest`, `helm upgrade`. The key is kept.
