# Admin UI: design

**Status: deferred.** Not in scope for the MetLife pilot, which runs on YAML
config managed through MetLife's own change control. This records the design
so it can be picked up later. Oct 1, 2026.

## Summary

An optional admin service, deployed next to the proxy, that lets the
customer's own administrators configure connections and redaction rules,
test connections, preview redaction, see metrics, and issue the NeuBird
token, without kubectl or hand-written YAML.

The proxy stays as small as it is today. The admin service is a separate
image that customers can choose not to deploy. Customers who manage config
through GitOps lose nothing.

## Goals

- Onboard a new customer in about an hour instead of days of YAML and kubectl.
- Let a customer's security team see exactly what NeuBird would receive (the
  redaction preview), before any data flows.
- Keep the customer fully in control: their identity provider, their secret
  store, their change process, their audit trail.
- Add nothing to what the proxy itself does or exposes to NeuBird.

## Non-goals

- **NeuBird-hosted management.** No control plane run by NeuBird and no
  remote config push. Everything runs in the customer's cluster.
- **Replacing GitOps.** The UI can feed a Git workflow; it does not have to
  own the config.
- **Human vendor access.** NeuBird staff do not get logins by default (see
  NeuBird visibility below).
- **Editing secrets' values in place**, or showing them. The UI only writes
  them or references them.

## Architecture

```
                    customer network                                │ NeuBird
                                                                    │
 admins ──SSO──▶ admin service ──(k8s API)──▶ ConfigMap / Secrets   │
                 (internal only)                  │                 │
                      │ admin port                ▼ mounted         │
                      └────────────────────▶ proxy pods ◀──token────┼── NeuBird platform
                        status, test, reload    │                   │   (proxy port, plus
                                                ▼                   │    read-only status API)
                                         APIM / backends            │
```

- **Proxy (data plane).** Unchanged in what it does, plus the additions under
  Proxy changes. It is the only component that holds backend credentials and
  talks to backends.
- **Admin service (management plane).** A separate Go binary with the
  front-end embedded. It serves only on an internal port and is never behind
  the NeuBird-facing load balancer; customers can also reach it only through
  `kubectl port-forward`. It holds no backend credentials. It reads and
  writes the proxy's ConfigMap and Secrets through the Kubernetes API, and
  calls the proxy's admin port for status, tests and previews.

Splitting the two keeps the reviewed data path small. The admin service can
be reviewed, deployed and upgraded on its own, or not at all.

## Proxy changes

These are useful even without a UI, so they are the first phase.

1. **Config reload.** Watch the mounted config file. On change: parse,
   validate (the same checks as `-check`), build the redaction engine, then
   swap atomically. A config that fails validation is never applied: the
   proxy keeps running the last good one, logs why, and reports it in
   `/status`. In-flight requests finish on the config they started with.
2. **Config identity.** Expose the running config's SHA-256 and load time,
   so the admin service can tell whether a change has reached every pod.
3. **Admin endpoints on the admin port** (cluster-internal, called only by
   the admin service, authenticated with a service token from a Secret):
   - `GET /status`: connections, per-connection health, the config hash, the
     startup warnings, recent block reasons.
   - `POST /test/{connection}`: run that connection's configured probe
     against its backend and return the status, latency and redaction counts.
     Never the body.
   - `POST /preview/{connection}`: redact a sample body supplied by the
     admin with that connection's effective rules, and return the redacted
     output and per-rule counts.
4. **Read-only status API on the proxy port**, authenticated with the
   NeuBird token: connection names, health, and configured MCP tools. Nothing
   from config values or traffic. This is what NeuBird's platform uses
   instead of a human login.

## Features and roles

Roles come from groups in the customer's identity provider.

| Feature | Owner | Editor | Viewer | Auditor |
|---|---|---|---|---|
| View connections and rules | yes | yes | yes | yes |
| View metrics and status | yes | yes | yes | yes |
| Test a connection | yes | yes | yes | no |
| Redaction preview | yes | yes | no | no |
| Add, edit or delete a connection or rule | yes | yes (normal changes) | no | no |
| Approve a weakening change (see below) | yes | no | no | no |
| Issue or rotate the NeuBird token | yes | no | no | no |
| Set or replace a backend credential | yes | yes | no | no |
| Manage SSO settings and role mapping | yes | no | no | no |
| View the admin audit log | yes | no | no | yes |

**Connections and rules.** A form per connection: upstream, client auth,
methods, paths, MCP tools, deny patterns, field allowlist, rate limit. A
rules page for builtins, custom rules, key patterns and allowed values. Every
edit is validated on the server with the proxy's own validation code before
it can be saved. Each change shows a diff of the resulting YAML, and those
diffs make up the version history.

**Test connection.** Calls the proxy's `/test`, so the test uses the real
credentials and the real network path, and the admin service never touches
backends. The probe is read-only and set per connection type (Splunk server
info, ServiceNow `sys_properties?sysparm_limit=1`, MCP `initialize` +
`tools/list`).

**Redaction preview.** The admin pastes a sample, or captures one live
response from a test call, and sees the original next to the redacted
version, with the matching rules highlighted. Samples are kept in memory for
that request only, never stored or logged.

**Metrics.** Requests, latency, redactions by rule, and blocks by reason,
per connection, read from the proxy pods' `/metrics` and summed. The admin
service has no long-term store; it links to the customer's Prometheus or
Grafana for history.

## Config modes

The customer picks one at install time.

- **GitOps mode.** The UI never changes the cluster. Saving produces
  validated YAML to download, or opens a pull request against the customer's
  config repo (GitHub, GitLab or Azure DevOps, with a token the customer
  provides). Their pipeline applies it, and the UI shows when the new config
  hash appears on the pods.
- **Direct mode.** Saving writes the ConfigMap, the pods reload, and the UI
  waits until every pod reports the new hash and passes health checks. If
  they don't, it restores the previous version. Every saved version is kept
  (as ConfigMap history in an annotation or a separate ConfigMap), with
  one-click rollback.

## Weakening changes

Some changes reduce protection. The UI marks them, requires a typed
confirmation, records them in the audit log, and in direct mode can require
an Owner's approval (a two-person rule, a per-install setting):

- turning on `passthrough`
- removing or disabling a builtin rule, custom rule or key pattern
- adding an `allowed_values` pattern
- removing a field from `response_fields`, or clearing the list
- allowing a write method, or removing `paths`, `mcp_tools` or deny patterns
- raising `max_body_bytes` (or setting it above a configured ceiling)
- turning on `allow_http_upstreams`

The list is the proxy's startup warnings plus anything that changes what
leaves the network, and should come from one shared definition in code.

## Secrets

- The UI never shows a secret's value after it is saved.
- Two ways to supply one: write-only fields that write the Kubernetes Secret
  directly, or references to existing secrets (a Kubernetes Secret key, or
  an External Secrets / Key Vault entry the customer manages).
- **NeuBird token.** Generated by the admin service (32 random bytes) and
  shown once, at creation, with a copy button. To get it again, rotate it.
  Rotation uses the proxy's previous-token slot, so the old token keeps
  working until NeuBird has switched over, after which the Owner confirms
  and the old token is removed.

## Authentication and session security

- **OIDC or SAML sign-on** through the customer's identity provider. MFA and
  joiner/leaver handling are theirs. Groups map to the roles above.
- **One bootstrap admin**, created by a one-time token printed in the admin
  pod's log at first start, for setting up SSO. It is disabled once SSO
  works, and can only be re-enabled by recreating its Secret with kubectl.
- **Sessions:** secure, HttpOnly, SameSite=Strict cookies; short idle
  timeout (for example 15 minutes); CSRF tokens on every state change.
- **Hardening:** a strict Content-Security-Policy (no inline scripts, no
  third-party origins), no external fonts or CDNs at runtime, login rate
  limits, and every action authorized on the server (never only hidden in
  the UI).

## NeuBird visibility

The original idea was a NeuBird user with limited permissions: view
metrics, get the token, see connection status, read-only config. A vendor
login into the customer's environment is the part a security team is most
likely to refuse, so the default is no human NeuBird account:

- **Status:** NeuBird's platform calls the proxy's read-only status API with
  its token. That gives connection health and configured tools for display
  in NeuBird's own UI, with nothing new reachable from outside.
- **Token:** the customer's Owner issues it and sends it to NeuBird through
  their usual secure channel.
- **Config visibility:** if a customer wants NeuBird to see the config,
  their Owner exports a read-only, secret-free copy and shares it.

An optional *NeuBird viewer* role (Viewer minus tests) can exist for
customers who want it. It is off by default and given to an identity in
their own identity provider.

## Audit log

Every sign-in, view of a sensitive page, test, preview, config change (with
diff), approval, token action and secret write is logged with the user,
role, time, source IP and outcome. Logs go to stdout as JSON for the
customer's SIEM, in the same format as the proxy's audit lines. The admin
service keeps no long-term copy.

## Build, packaging and supply chain

- **One static Go binary** with the front-end built at compile time and
  embedded (`go:embed`). No Node.js at runtime. Distroless, non-root image,
  pinned by digest, with an SBOM, built by the same CI as the proxy.
- **Front-end dependencies** kept minimal and reviewed: React, Tailwind, a
  charting library. Each one is MIT or Apache 2.0, the same rule as the
  product UI. No analytics, telemetry or remote fonts.
- **Look:** shares the product UI's design layer only (Tailwind config,
  colors, typography, component styling), copied in, not imported. No code
  or packages from NeuBird's product.
- **Kubernetes RBAC** for the admin service, scoped to its namespace: `get`,
  `update` and `patch` on the one ConfigMap and the named Secrets, `list` on
  the proxy pods, nothing cluster-wide. In GitOps mode, read-only.
- Shipped as a Helm chart or Kustomize overlay with the admin service
  *disabled* by default.

## Phases

| Phase | Scope | Useful on its own because |
|---|---|---|
| 0 | Proxy: config reload with last-known-good, config hash, `/status`, `/test`, `/preview`, NeuBird status API | Safe config changes and connection tests through `curl` and GitOps, for every customer |
| 1 | Admin service, read-only: SSO, roles, connections and rules view, status, metrics, test connection, redaction preview, audit log | Covers most of onboarding and the security review; changes nothing |
| 2 | Editing in GitOps mode: forms, validation, diffs, YAML download or pull request, token issue and rotation | Customers with change control can use it fully |
| 3 | Direct mode: ConfigMap writes, staged rollout, automatic rollback, version history, two-person approval | Customers without a config repo |

## Open questions

- Which repo is the design reference: `hawkeye-ui`, or a separate
  `neubirdai-ui`? And is its design layer separable from product code?
- Should the redaction preview be allowed to capture a live response
  (convenient, but shows real data in the browser), or only pasted samples?
- Is the read-only status API acceptable to a security team in its own
  right, or does it need its own token separate from the data-path token?
- Helm, Kustomize or both? What do target customers already use?
- Is there a customer other than MetLife who wants this soon, so the design
  can be checked with a real security team before phase 1?
