# Getting started

This guide takes you from nothing to a working proxy in front of your
systems: write a config, check exactly what NeuBird will receive, install
the proxy with this Helm chart, connect it to NeuBird, and check that it
reaches each system. It takes about an hour.

The proxy runs in your cluster and opens outbound tunnels (TLS, port 443) to
your dedicated NeuBird relay; NeuBird's requests come back through them.
Nothing connects in to your cluster.

You set once which hosts NeuBird may reach. Your systems are then added,
changed and removed in NeuBird, as connections with their own URL and
credentials, without touching the proxy. The example allows two systems:
Splunk (through its MCP server) and ServiceNow. Swap in your own as you go.
[configuration.md](configuration.md) is the reference for every setting, and
the chart's [README](../README.md) for its values.

## Before you start

You need:

- `kubectl` access to the cluster, with rights to create a namespace, and
  Helm 3.
- The proxy image, which NeuBird ships to you separately. Load it into your
  registry and note its digest (`sha256:...`).
- From NeuBird: your relay's address (e.g. `acme.tunnel.neubird.ai:443`)
  and its IP addresses for your firewall, your tenant name,
  `relay-ca.crt`, the relay's CA certificate, and a **join token**
  (`nbjt_...`, secret, works once) for the proxy name you'll use.
- Docker on your machine, to run the proxy's tools before anything is
  deployed. Every tool is a subcommand of the same image, so the version you
  check with is the version you deploy.
- The hostnames of the systems NeuBird should reach. Their credentials go
  into NeuBird, not into the proxy (step 7).
- Outbound access from the cluster to the relay on port 443, and from the
  cluster to those systems.

Set a shortcut for running the tools:

```bash
IMAGE=<your registry>/neubird-proxy@sha256:<digest>
np() { docker run --rm -i -v "$PWD":/work -w /work "$IMAGE" "$@"; }
np help
```

Run the commands from a directory under your home directory: Docker
Desktop and Colima only share that with containers. On an Apple Silicon
Mac, add `--platform linux/amd64` after `docker run`: the image is built
for amd64 only.

## 1. Write the config

To follow along without your own systems' data, use the files in
[`docs/examples`](examples/): the config below, and the sample responses
used in step 3. Run the commands from that directory.

Create `config.yaml` (or start from `docs/examples/config.yaml`):

```yaml
# listen, admin_listen and tunnel are set by the Helm chart: requests arrive
# through the tunnel, nothing listens for them.

# The token NeuBird sends. Secrets never go in this file: the proxy reads
# them from environment variables, which come from a Kubernetes Secret.
client_token_env: NEUBIRD_PROXY_TOKEN

# NeuBird names the system each request is for (the endpoint URL of its
# connection, such as https://splunk.example.com) and sends that system's
# credentials. The proxy only forwards to hosts that match these patterns.
neubird_destinations:
  hosts:
    - splunk.example.com
    - yourinstance.service-now.com
  methods: [GET, HEAD, POST, DELETE]   # Splunk MCP uses POST, and DELETE to end a session
  # SPL commands that write, send, delete or reach other systems.
  request_deny_patterns:
    - "(?i)\\|\\s*(sendemail|sendalert|outputlookup|outputcsv|outputtext|collect|mcollect|meventcollect|tscollect|delete|script|run|runshellscript|map|rest|dbxoutput|dbxquery|sendresults)\\b"

redaction:
  # All built-in rules are on by default: emails, SSNs, phones, cards, IP
  # addresses, dates of birth, and secrets such as JWTs and API keys.
  # Add your own identifier formats:
  custom:
    - name: member_id
      regex: "\\bMET[0-9]{9}\\b"
```

A few things to know:

- **`hosts`** is the list of systems NeuBird may reach: exact names, or a
  domain such as `*.corp.example.com`. It's optional; without it NeuBird may
  reach any host name the pod can. Either way, IP addresses are reached only
  when listed exactly, and loopback, link-local and cloud metadata addresses
  never.
- **`methods`** defaults to GET and HEAD (read-only). List more only if a
  system needs them, as Splunk's MCP server does.
- **`request_deny_patterns`** refuse a request whose query or body matches,
  whichever system it's for.

## 2. Validate it

```bash
np validate -offline -config config.yaml
```

`-offline` checks the config without its secrets: missing variables get
placeholders, and are listed at the end. A good config prints `VALID`, a
summary, and any warnings:

```
VALID config.yaml

CONNECTION            UPSTREAM                                         AUTH    METHODS               PATHS  MCP TOOLS  FIELDS  MODE
neubird_destinations  splunk.example.com,yourinstance.service-now.com  bearer  GET,HEAD,POST,DELETE  any    -          all     NeuBird credentials

redaction: mask=label, rules: private_key, jwt, aws_access_key, ..., member_id, ...

warnings:
  - tls is not set: the proxy listener is plain HTTP and relies on the load balancer for TLS
  - neubird_destinations: NeuBird chooses the destination host within splunk.example.com, yourinstance.service-now.com and supplies the credentials

not checked (offline, placeholders used): NEUBIRD_PROXY_TOKEN
```

Both warnings are expected:
- **TLS**: ignore it. It's about the request listener, which the chart turns
  off; the chart adds the tunnel part of the config in step 5.
- **neubird_destinations** says what NeuBird may do, so it's visible in
  every pod's log.

A broken config lists every problem in one go, each with the setting it's
in. Fix them and run it again.

## 3. See what NeuBird would receive

You can check the masking before anything is deployed. Save a typical
response from one of your systems as `sample.json`, or use the synthetic
ServiceNow incident in `docs/examples/sample.json`, then:

```bash
np preview -config config.yaml sample.json
```

It shows each changed line, with the original above and what NeuBird
receives below:

```
redactions: email 1, member_id 1, phone_us 1
legend:     - returned by the system   + received by NeuBird

  ...
    7         "priority": "2",
    8 -       "short_description": "Member portal login fails for MET220019384",
      +       "short_description": "Member portal login fails for [REDACTED:MEMBER_ID]",
    9 -       "description": "Caller Dana Whitfield (dana.whitfield@example.org, 646-555-0192) reports a login loop since 09:10.",
      +       "description": "Caller Dana Whitfield ([REDACTED:EMAIL], [REDACTED:PHONE_US]) reports a login loop since 09:10.",
   10         "assignment_group": {
  ...
```

For a security review, write it as a side-by-side HTML report:

```bash
np preview -config config.yaml -html - sample.json > report.html
```

The preview and the report contain the original data, so handle them as
sensitive.

Notice that "Dana Whitfield" got through. Names, addresses and other free
text have no pattern to match. Add a custom rule for formats you know, or a
field allowlist, `response_fields`, under `neubird_destinations`: every
field not listed is masked whole. The allowlist applies to every system's
responses, so it suits a proxy whose systems all return the fields you list;
check each system's samples with `preview`.

Repeat until the output is what you're comfortable sending to NeuBird.

### Optional: keep masked values linkable (HMAC)

By default every masked value becomes the same label: every email is
`[REDACTED:EMAIL]`. That hides who's involved, but also whether two events
involve the *same* person, host or account, which often matters for finding
a root cause. "The same user hit this error five times" and "five users hit
it once" call for different fixes.

HMAC masking keeps that link without revealing the value. Each value is
replaced by a code derived from the value and a secret key that stays in
your cluster:
- **The same value always gets the same code,** in every response, on
  every pod, and across restarts, as long as the key doesn't change.
- **Different values get different codes.**
- **Encoded forms of a value get its code too.** An email inside a
  URL-encoded log line gets the same code as the plain address.

Turn it on in `redaction`:

```yaml
redaction:
  mask: hmac
  hmac_key_env: REDACTION_HMAC_KEY
```

To preview with the real codes, put the key in an env file. Without it,
`preview` uses a placeholder key and says so:

```bash
printf 'REDACTION_HMAC_KEY=%s\n' "$(np token)" > hmac.env   # keep this file safe; step 4 stores the key
np preview -config config.yaml -env-file hmac.env incidents.json
```

With three incidents, two of them from the same caller
(`docs/examples/incidents.json`):

```
redactions: email 4
legend:     - returned by the system   + received by NeuBird
    5 -       "short_description": "Login loop for dana.whitfield@example.org",
      +       "short_description": "Login loop for [REDACTED:EMAIL:6dea5e828f9f227f]",
    6 -       "caller_email": "dana.whitfield@example.org"
      +       "caller_email": "[REDACTED:EMAIL:6dea5e828f9f227f]"
  ...
   11 -       "caller_email": "bob.lee@example.org"
      +       "caller_email": "[REDACTED:EMAIL:6e6200bcd74a1314]"
  ...
   16 -       "caller_email": "dana.whitfield@example.org"
      +       "caller_email": "[REDACTED:EMAIL:6dea5e828f9f227f]"
```

The agent can see that INC0010042 and INC0010051 come from the same
person, and that INC0010043 is someone else, without learning who either
is.

Before choosing it, know its limits:

| Limit | What it means |
|---|---|
| **The key is as sensitive as the data** | Anyone with the key and the codes can test guesses. For values with few possibilities, such as a 9-digit SSN or a phone number, that means recovering them by trying every one. Keep the key in your secret store, never send it to NeuBird, and restrict who can read the Secret |
| **It's pseudonymization, not anonymization** | Under many privacy policies, HMAC-masked data still counts as personal data. Check with your privacy team |
| **Changing the key changes every code** | Codes from before and after a rotation don't match, so the agent loses the link across that point. Rotate deliberately |
| **Codes are 16 hex characters (64 bits)** | Two different values sharing a code is vanishingly unlikely at any realistic data volume |

If the agent doesn't need to tell values apart, keep the default,
`mask: label`.

## 4. Create the secrets

Create the namespace (set your own name), then one Secret holding the proxy
token and the join token. Your systems' credentials don't go here: they're
entered in NeuBird (step 7).

```bash
NS=neubird
kubectl create namespace $NS
kubectl label namespace $NS pod-security.kubernetes.io/enforce=restricted

printf 'NeuBird join token: '; read -rs JOIN; echo
kubectl -n $NS create secret generic neubird-proxy \
  --from-literal=NEUBIRD_PROXY_TOKEN="$(np token)" \
  --from-literal=NEUBIRD_JOIN_TOKEN="$JOIN"
unset JOIN
```

If you chose HMAC masking, add the key from `hmac.env` too, then delete
the file:

```bash
kubectl -n $NS patch secret neubird-proxy --type merge \
  -p "{\"stringData\":{\"REDACTION_HMAC_KEY\":\"$(sed -n 's/^REDACTION_HMAC_KEY=//p' hmac.env)\"}}"
rm hmac.env
```

The proxy refuses to start with `mask: hmac` and no key, so a missing key
shows up immediately rather than as wrong codes.

`np token` generates the proxy token, so nobody types it. `read -rs` keeps
the join token off the screen and out of your shell history.

## 5. Install with Helm

Write `values.yaml` with what NeuBird gave you:

```yaml
image:
  repository: <your registry>/neubird-proxy
  digest: sha256:<digest>
tunnel:
  relays: ["acme.tunnel.neubird.ai:443"]   # your relay, from NeuBird
  tenant: acme                             # your tenant, from NeuBird
  proxy: aks-prod                          # the proxy name the join token is for
env:
  existingSecret: neubird-proxy            # the Secret from step 4
```

Your `config.yaml` becomes the chart's `config` value. Wrap it, then install
(add `--set-file upstreamCA.cert=...` if a system uses an internal CA):

```bash
{ echo 'config:'; sed 's/^/  /' config.yaml; } > config-values.yaml
helm install neubird-proxy ./neubird-proxy-<version>.tgz -n $NS \
  -f values.yaml -f config-values.yaml --set-file relayCA.cert=relay-ca.crt
```

The chart generates the proxy's tunnel key in a Secret; it never leaves the
cluster. On its first connect the proxy presents the join token, the relay
records the key, and the tunnels open, all within seconds. Nothing to send
NeuBird:

```bash
kubectl -n $NS rollout status deploy/neubird-proxy
kubectl -n $NS logs deploy/neubird-proxy | grep -E '"(starting|enrolled with the join token|tunnel connected)"'
```

Once enrolled, you can delete `NEUBIRD_JOIN_TOKEN` from the Secret. If the
log says `enrollment: relay refused: join token expired` (or `already
used`), ask NeuBird for a new one. Without a join token, send NeuBird the
key's fingerprint instead (`kubectl -n $NS exec deploy/neubird-proxy --
/neubird-proxy fingerprint /etc/neubird-proxy/tunnel/tunnel.key`); the pods
turn ready once it's recorded.

The `starting` line shows the hash of the config the pod runs. Any `risky
configuration` lines are settings worth a second look.

## 6. Test the tunnel and each system

Run the test inside a proxy pod, so it uses the pod's real network:

```bash
kubectl -n $NS exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml
```

Without arguments it checks the tunnel to each relay:

```
tunnel -> acme.tunnel.neubird.ai:443
  ok    identity   tenant acme, proxy aks-prod; key sha256:0f9f…
  ok    dns        acme.tunnel.neubird.ai -> 20.1.2.3
  ok    relay      acme.tunnel.neubird.ai:443: mutual TLS and neubird-tunnel/1 in 41ms; relay certificate "acme.tunnel.neubird.ai" expires in 364 days
```

Pass a system's URL to check that the proxy may and can reach it:

```bash
kubectl -n $NS exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml \
  https://splunk.example.com https://yourinstance.service-now.com
```

```
https://splunk.example.com -> neubird_destinations
  ok    hosts      allowed by neubird_destinations.hosts
  ok    dns        splunk.example.com -> 10.20.30.40
  ok    tcp        splunk.example.com:443 connected in 18ms
  ok    tls        TLS 1.3, certificate "splunk.example.com" from "Example CA", expires in 106 days
```

No request is sent: the credentials are NeuBird's. Each failure says where
it broke:

| Failure | Usually means |
|---|---|
| `FAIL hosts` | The host isn't in `neubird_destinations.hosts` |
| `FAIL dns` | The name doesn't resolve from inside the cluster |
| `FAIL tcp` | A firewall, or your NetworkPolicy, doesn't allow the system |
| `FAIL tls`, "set upstream_ca_file" | The system uses an internal CA: pass its bundle with the chart's `upstreamCA` |

To change the config later, edit `config.yaml` and upgrade; a config change
rolls the pods:

```bash
{ echo 'config:'; sed 's/^/  /' config.yaml; } > config-values.yaml
helm upgrade neubird-proxy ./neubird-proxy-<version>.tgz -n $NS \
  -f values.yaml -f config-values.yaml --set-file relayCA.cert=relay-ca.crt
```

## 7. Connect NeuBird

The tunnels are already up (step 5). In NeuBird, add each system as a
connection, as you would without the proxy: its URL (for example
`https://splunk.example.com/services/mcp`) and its credentials. Then choose
access through the NeuBird proxy and enter:

- the **relay URL** NeuBird gives you;
- the **proxy token**. Print it with:

```bash
kubectl -n $NS get secret neubird-proxy -o jsonpath='{.data.NEUBIRD_PROXY_TOKEN}' | base64 -d
```

NeuBird sends each request through the relay and the tunnel, naming the
system's host, and the proxy forwards it only if the host is in `hosts`.
Adding, changing or removing a system later happens in NeuBird; the proxy
needs a change only when a new system's host isn't covered by `hosts`.

To cut NeuBird off at any time: change the token in the Secret and restart
the pods, or scale the Deployment to 0.

## 8. Watch it work

Every request gets one audit line: that it came through the tunnel
(`"via":"tunnel"`), the system it went to (`destination`), the path, the
status, the time, and how many values each rule masked. Credentials,
matched values and query values are never logged.

```bash
kubectl -n $NS logs -l app=neubird-proxy -f
```

For totals across both pods:

```bash
for p in $(kubectl -n $NS get pods -l app=neubird-proxy -o name); do
  kubectl get --raw /api/v1/namespaces/$NS/${p/pod\//pods/}:9090/proxy/metrics
done | np metrics -
```

## Next steps

- **Keep `hosts` narrow.** List the systems, or the narrowest domains that
  cover them, rather than `*`.
- **Lock down egress at the network**, so the pod can reach only your
  systems and the relay, whatever `hosts` says (configuration.md, Egress).
- **Tighten the request rules.** The audit lines show every method, path
  and query parameter name; add `request_deny_patterns` for anything
  NeuBird shouldn't send, and drop methods no system needs.
- **Correlate without revealing values:** if you skipped it in step 3,
  see the HMAC section there.
- **Rotate the token** without downtime: add the new token to the Secret,
  keep the old one under another name set as `client_token_previous_env`,
  restart, update NeuBird, then remove the old one and restart again.
