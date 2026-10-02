# Getting started

This guide takes you from nothing to a working proxy in front of your
systems: write a config, deploy it to Kubernetes, check that it reaches
each system, and see exactly what NeuBird will receive. It takes about an
hour.

The example has two connections: Splunk through its MCP server, and the
ServiceNow REST API. Swap in your own systems as you go. The
[README](../README.md) is the full reference for every setting.

## Before you start

You need:

- `kubectl` access to the cluster, with rights to create a namespace.
- The proxy image, `<registry>/neubird-proxy:<version>`. NeuBird gives you
  the image, or you build it from this repository with `make image` and push
  it to your registry.
- Docker on your machine, to run the proxy's tools before anything is
  deployed. Every tool is a subcommand of the same image, so the version you
  check with is the version you deploy.
- For each system, its URL and a credential for the proxy to use. The proxy
  holds these; NeuBird never sees them.

Set a shortcut for running the tools:

```bash
IMAGE=<registry>/neubird-proxy:<version>
np() { docker run --rm -i -v "$PWD":/work -w /work "$IMAGE" "$@"; }
np help
```

Run the commands from a directory under your home directory: Docker
Desktop and Colima only share that with containers. On an Apple Silicon
Mac, add `--platform linux/amd64` after `docker run` if the image is built
for amd64 only.

## 1. Write the config

To follow along without your own systems' data, use the files in
[`docs/examples`](examples/): the config below, and the sample responses
used in step 3. Run the commands from that directory.

Create `config.yaml` (or start from `docs/examples/config.yaml`):

```yaml
listen: ":8443"          # the port NeuBird reaches, behind your load balancer
admin_listen: ":9090"    # health and metrics, cluster-internal only

# The token NeuBird sends. Secrets never go in this file: the proxy reads
# them from environment variables, which come from a Kubernetes Secret.
client_token_env: NEUBIRD_PROXY_TOKEN

connections:
  # NeuBird calls https://<proxy>/splunk/services/mcp
  - name: splunk
    upstream: https://splunk.example.com
    client_auth: bearer
    methods: [POST, DELETE]            # MCP uses POST for every call
    paths: [/services/mcp]             # nothing else on this host is reachable
    headers:
      Authorization: Bearer ${SPLUNK_MCP_TOKEN}   # sent to Splunk, never to NeuBird

  # NeuBird calls https://<proxy>/servicenow/api/now/table/incident...
  - name: servicenow
    upstream: https://yourinstance.service-now.com
    client_auth: basic                 # NeuBird sends its token as a Basic password
    paths:                             # GET and HEAD only, by default
      - /api/now/table/(incident|problem|change_request)(/[0-9a-f]{32})?
    upstream_basic_auth:
      username_env: SN_USER
      password_env: SN_PASSWORD

redaction:
  # All built-in rules are on by default: emails, SSNs, phones, cards, IP
  # addresses, dates of birth, and secrets such as JWTs and API keys.
  # Add your own identifier formats:
  custom:
    - name: member_id
      regex: "\\bMET[0-9]{9}\\b"
```

A few things to know:

- **`name`** becomes the path prefix NeuBird uses, so `splunk` means
  `https://<proxy>/splunk/...`.
- **`paths`** patterns must match the whole path after the prefix. Leave a
  connection's `paths` out and every URL under its upstream is reachable;
  the proxy allows that, but warns at every start.
- **`methods`** defaults to GET and HEAD (read-only). List more only where
  you need them.

## 2. Validate it

```bash
np validate -offline -config config.yaml
```

`-offline` checks the config without its secrets: missing variables get
placeholders, and are listed at the end. A good config prints `VALID`, a
summary of each connection, and any warnings:

```
VALID config.yaml

CONNECTION  UPSTREAM                              AUTH    METHODS      PATHS  MCP TOOLS  FIELDS  MODE
splunk      https://splunk.example.com            bearer  POST,DELETE  1      -          all     redact
servicenow  https://yourinstance.service-now.com  basic   GET,HEAD     1      -          all     redact

redaction: mask=label, rules: private_key, jwt, aws_access_key, ..., member_id, ...

warnings:
  - tls is not set: the proxy listener is plain HTTP and relies on the load balancer for TLS
  - connection splunk: allows POST, DELETE with no request_deny_patterns or mcp_tools

not checked (offline, placeholders used): NEUBIRD_PROXY_TOKEN, SN_PASSWORD, SN_USER, SPLUNK_MCP_TOKEN
```

Both warnings are expected at this point:
- **TLS** is handled by your load balancer in this setup.
- **The Splunk warning** goes away in step 6, when you list the MCP tools
  the agent may call.

A broken config lists every problem in one go, each with the setting it's
in. Fix them and run it again.

## 3. See what NeuBird would receive

You can check the masking before anything is deployed. Save a typical
response from one of your systems as `sample.json`, or use the synthetic
ServiceNow incident in `docs/examples/sample.json`, then:

```bash
np preview -config config.yaml -connection servicenow sample.json
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
np preview -config config.yaml -connection servicenow -html - sample.json > report.html
```

The preview and the report contain the original data, so handle them as
sensitive.

Notice that "Dana Whitfield" got through. Names, addresses and other free
text have no pattern to match. For fields the agent doesn't need, add a
field allowlist to the connection, and every other field is masked:

```yaml
    response_fields:
      - result.sys_id
      - result.number
      - result.state
      - result.priority
      - result.short_description
      - result.assignment_group.display_value
```

Run `preview` again. The description is now masked whole, while the fields
you listed still get every rule:

```
redactions: field_not_allowed 1, member_id 1
            (field_not_allowed: a field not in response_fields, masked whole as [REDACTED:FIELD] before any other rule)
legend:     - returned by the system   + received by NeuBird
    8 -       "short_description": "Member portal login fails for MET220019384",
      +       "short_description": "Member portal login fails for [REDACTED:MEMBER_ID]",
    9 -       "description": "Caller Dana Whitfield (dana.whitfield@example.org, 646-555-0192) reports a login loop since 09:10.",
      +       "description": "[REDACTED:FIELD]",
```

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
np preview -config config.yaml -env-file hmac.env -connection servicenow incidents.json
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
token and the systems' credentials:

```bash
NS=neubird
kubectl create namespace $NS   # the manifest in step 5 adds its security labels

printf 'Splunk MCP token: '; read -rs SPLUNK; echo
printf 'ServiceNow password: '; read -rs SNPW; echo
kubectl -n $NS create secret generic neubird-proxy \
  --from-literal=NEUBIRD_PROXY_TOKEN="$(np token)" \
  --from-literal=SPLUNK_MCP_TOKEN="$SPLUNK" \
  --from-literal=SN_USER=neubird-integration \
  --from-literal=SN_PASSWORD="$SNPW"
unset SPLUNK SNPW
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
the credentials off the screen and out of your shell history.

## 5. Deploy

```bash
kubectl -n $NS create configmap neubird-proxy --from-file=config.yaml
```

Copy `deploy/kubernetes.yaml` from this repository and edit the lines marked
`CHANGE ME`:

| Setting | Set it to |
|---|---|
| `namespace:` (every object) and the Namespace's `name:` | `$NS` |
| `image:` | your image, ideally by digest: `<registry>/neubird-proxy@sha256:...` |
| Ingress `ipBlock` | the range your load balancer or ingress controller connects from |
| Egress `ipBlock` | the range your systems (or your API gateway) are in |
| Monitoring namespace | where your Prometheus runs, if anything scrapes `/metrics` |

The egress range matters. The manifest denies all other traffic, so if it
doesn't cover your systems, the proxy can't reach them; step 6 shows that
as a `tcp` failure. To restrict egress to exactly the configured hostnames
instead of a range, see `np netpol` in the README (Kubernetes hardening).

Apply it and wait for the two pods:

```bash
kubectl apply -f kubernetes.yaml
kubectl -n $NS rollout status deploy/neubird-proxy
kubectl -n $NS logs deploy/neubird-proxy | head -5
```

The first log line, `starting`, lists the connections and the hash of the
config they run. Any `risky configuration` lines are settings worth a second
look.

## 6. Test each connection

Run the test inside a proxy pod, so it uses the pod's real secrets and
network and nobody copies credentials anywhere:

```bash
kubectl -n $NS exec deploy/neubird-proxy -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml
```

For each connection, it checks DNS, TCP and TLS, then sends a real request
through the proxy as NeuBird would. Here's an example for an MCP
connection:

```
splunk -> https://splunk.example.com
  ok    dns        splunk.example.com -> 10.20.30.40
  ok    tcp        splunk.example.com:443 connected in 18ms
  ok    tls        TLS 1.3, certificate "splunk.example.com" from "Example CA", expires in 106 days
  ok    initialize HTTP 200, application/json, 154 bytes, 172ms; redactions: none
  info  server     Splunk_MCP_Server 1.2.1, protocol 2025-06-18
  ok    tools/list HTTP 200, application/json, 7228 bytes, 325ms; redactions: none
  warn  tools      10 tools, all allowed (no mcp_tools): splunk_get_info, splunk_run_query, ...
```

Each failure says where it broke:

| Failure | Usually means |
|---|---|
| `FAIL dns` | The name doesn't resolve from inside the cluster |
| `FAIL tcp` | A firewall, or the manifest's egress range doesn't cover the system |
| `FAIL tls`, "set upstream_ca_file" | The system uses an internal CA; add its bundle as `upstream_ca_file` |
| "rejected the credentials" | The system refused the credential in the Secret |
| "refused by the proxy: path_not_allowed" | The test probe's path isn't in `paths`; pass `-path` with one that is |

For an MCP connection, the last lines list the server's tools. Copy the
ones the agent should use into the connection's `mcp_tools`, and every
other tool is refused. Then update the ConfigMap and restart:

```bash
kubectl -n $NS create configmap neubird-proxy --from-file=config.yaml --dry-run=client -o yaml | kubectl apply -f -
kubectl -n $NS rollout restart deploy/neubird-proxy
```

The proxy has no hot reload, so config changes take effect on restart.

## 7. Check the masking on live data

Capture a real response through a connection and compare it with what
NeuBird would receive:

```bash
kubectl -n $NS exec deploy/neubird-proxy -- /neubird-proxy preview -config /etc/neubird-proxy/config.yaml \
  -connection servicenow -live -path /api/now/table/incident
```

For MCP, pass the tool call:

```bash
kubectl -n $NS exec deploy/neubird-proxy -- /neubird-proxy preview -config /etc/neubird-proxy/config.yaml \
  -connection splunk -live -method POST -path /services/mcp \
  -data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"splunk_run_query","arguments":{"query":"search index=main | head 20"}}}'
```

Add `-html - > report.html` to either for the side-by-side report.

## 8. Connect NeuBird

Expose the Service (port 443) through your load balancer or ingress with
TLS, limited to NeuBird's egress IPs if you can. Then check it from outside
the cluster:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://<proxy-host>/splunk/services/mcp -X POST
# 401: reachable, and refusing requests without the token
```

Send NeuBird the connection URLs and the proxy token through your usual
secure channel:

- Splunk MCP: `https://<proxy-host>/splunk/services/mcp`, bearer token.
- ServiceNow: `https://<proxy-host>/servicenow`, Basic auth with any user
  name and the token as the password.

Print the token with:

```bash
kubectl -n $NS get secret neubird-proxy -o jsonpath='{.data.NEUBIRD_PROXY_TOKEN}' | base64 -d
```

## 9. Watch it work

Every request gets one audit line: who called (`forwarded_for`, as reported
by your load balancer), which connection and path, the status, the time,
and how many values each rule masked. Matched values and query values are
never logged.

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

- **Tighten each connection.** List `paths` and `mcp_tools` from what
  NeuBird's connectors actually call; the audit lines show every method,
  path and query parameter name. Add `response_fields` where free text
  doesn't need to leave.
- **Lock down egress by hostname** with `np netpol` (README, Kubernetes
  hardening).
- **Correlate without revealing values:** if you skipped it in step 3,
  see the HMAC section there.
- **Rotate the token** without downtime: set `client_token_previous_env` to
  the old token's variable while NeuBird switches over (README, Deploy).
