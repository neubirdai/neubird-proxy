# Security plan: closing the MetLife review gaps

First written Sep 30, 2026, after an adversarial review of the proxy from the
point of view of a MetLife security architect (5 blockers, 5 major issues, 5
governance gaps). Updated Oct 18, 2026 for the tunnel model and the reviews
since. This document records what the code now handles and plans the rest.
The rest needs a decision, data, access or credentials that engineering alone
does not have.

Effort figures are estimates, not sized by the owning team.

## What changed since Sep 30: the tunnel model

The Sep 30 review assumed NeuBird reached the proxy through MetLife's APIM
with a proxy token. MetLife now runs the proxy in **mode `tunnel`**:

```
NeuBird ─▶ relay ⇄ tunnel (outbound :443, mutual TLS) ⇄ neubird-proxy (AKS) ─▶ Splunk, ServiceNow, ...
```

- **Nothing connects in.** The proxy opens outbound tunnels to a relay
  dedicated to MetLife; NeuBird's requests come back down them. No Service,
  load balancer, inbound firewall rule or APIM in the path.
- **No proxy token** (`client_auth: none`): a request is accepted because it
  arrived over a tunnel this proxy opened. Only MetLife's NeuBird deployment
  can reach MetLife's relay.
- **The proxy's identity is a key that never leaves the cluster.** It is a
  P-256 key in a Kubernetes Secret. The proxy enrolls it once with a
  single-use, expiring join token; NeuBird's relay records only its
  fingerprint.
- **Both ends are pinned.** The proxy trusts only the relay's private CA
  (shipped as `relay-ca.crt`), not the public web PKI; the relay accepts only
  enrolled, unrevoked keys.
- **NeuBird can cut a proxy off at the relay.** Revoking a key takes effect
  within about a minute and closes its open tunnels; reconnects are refused
  (`key … is revoked`). Verified on the metlifemirror relay, Oct 18. MetLife
  can also cut NeuBird off by scaling the proxy to 0.

Findings 6 and 7 and items 9 and 10 below were about the APIM path and are
closed or replaced by this. Mode `inbound` (behind a customer's gateway, with
a proxy token) still exists for other customers; the token controls from
finding 6 apply there.

## Where each finding stands

| # | Finding | Status | How |
|---|---|---|---|
| 1 | PII in encoded or unformatted forms, and free-text PHI | **Partly fixed** | Normalization (percent, HTML entities, full-width, zero-width, BOM, more invisibles and non-ASCII digits) and keyword rules for unformatted SSN, phone and DOB are done. Free text is handled by `response_fields` for fields that don't need to pass; fields that must pass as free text (Splunk `_raw`, MCP tool text) depend on the rules. Open: items 2, 3 |
| 2 | Secrets not detected | **Fixed** | 8 secret rules: private keys, JWT, AWS, Azure, vendor tokens, URL credentials, bearer values, `password=`-style assignments, with matching key rules; also matched in their encoded forms (%-escapes, entities) |
| 3 | Compressed or binary data labeled as text leaks | **Fixed** | Non-UTF-8 or NUL-containing bodies and SSE events are refused (`not_text`) |
| 4 | Backend session cookies forwarded | **Fixed** | `Set-Cookie` is stripped on every connection, including passthrough |
| 5 | Gateway with write access | **Fixed in code; config open** | GET/HEAD by default, plus `methods`, `paths`, `request_deny_patterns` (Splunk SPL, including `\| rest`) and `mcp_tools`. MetLife's values allow every method and rely on read-only roles for each credential plus the SPL deny patterns. Open: item 1 |
| 6 | One static token opens everything | **Replaced (tunnel)** | Mode `tunnel` has no proxy token: see above. Mode `inbound` keeps per-connection tokens, a previous token for rotation, a 32-character minimum and optional mTLS |
| 7 | Arbitrary client headers forwarded (APIM trace) | **Fixed** | Request header allowlist; trace, debug, credential, framing, range, encoding and `X-Forwarded-*` headers can't be allowlisted; trailers aren't forwarded. APIM is no longer in the path |
| 8 | Internal topology leaks (hostnames, paths) | **Open (config)** | Needs MetLife's domain and path patterns as custom rules, or `response_fields`. Item 16 |
| 9 | No rate limits, concurrency limits or performance evidence | **Fixed; follow-ups open** | Per-connection rate limits, a global concurrency cap, a buffered-body cap, memory budgets for streamed JSON and SSE, benchmarks and a measured peak heap. MetLife's values: 20 MiB `max_body_bytes`, 768 Mi memory limit. Throughput is 11–16 MB/s, and Splunk exports stream, so the first result leaves in about 1 ms. Open: items 9, 11, 18 |
| 10 | Audit can't attribute or reconstruct access | **Fixed in code; shipping open** | Request ID (echoed upstream and to the client), remote and forwarded address, query parameter names, config SHA-256 at startup; the relay logs every request with tenant, proxy and status, and every tunnel with its key. Open: item 7 |
| 11 | ConfigMap edit can turn on passthrough | **Mitigated; process open** | Startup warnings, `-check` warnings, and the config hash in logs. Open: item 8 |
| 12 | Unpinned build inputs, no signing | **Fixed; keyless open** | Base image digests, the Go toolchain, CI actions, and the helm, syft and Trivy images are pinned. CI builds linux/amd64 and arm64, attaches SBOM and provenance attestations, scans each pushed platform with Trivy, and signs the index digest with cosign. Packages pin the image by digest and ship `cosign.pub` and the SBOM. Open: item 5 |
| 13 | Thin assurance | **Partly fixed** | Three internal review rounds since (below), a regression test per finding, fuzzing on 5 redaction targets, `go test -race`, govulncheck, Trivy and chart checks in CI. Coverage (Oct 18): proxy 93%, redaction 91%, tunnel 84%, config 80%, CLI 72%. Open: items 2, 4 |
| 14 | HMAC is pseudonymization | **Documented; decision open** | MetLife packages use `mask: hmac`; the key is generated in MetLife's cluster, must be 32+ characters, and is never sent to NeuBird. Item 13 |
| 15 | No patch ownership | **Open** | Item 12 |

The first review also turned up one leak its list didn't cover: upstream 1xx
(103 Early Hints) headers were relayed before redaction. It is fixed.

## Reviews since Sep 30

All internal: by the authoring team, AI-assisted. Item 4 is still needed.

| When | Scope | Main fixes |
|---|---|---|
| Oct 11–12 | Security fix rounds 1–8 and the review of main | Path tricks (`..;`), trailers, encodings that could slip past SPL deny patterns, write deadlines, the dial guard (metadata, loopback, link-local and the pod's own addresses), bare JSON numbers redacted, 401s with no extra headers |
| Oct 12 | Security review 2: memory and redaction | Five memory rounds (budgets for streamed JSON and SSE, bounded match memory); redaction misses at chunk boundaries and in JSON held in strings |
| Oct 12 | Security review 3: tunnel, proxy, redaction | Enrollment tracked per key; `test` never spends the join token; 64 KiB header cap; linear-time matching (was quadratic); HMAC key 32+ characters |
| Oct 16–18 | Install review (Antoni) | Chart from an OCI registry instead of a tarball in the package; no relay IPs, tenant or proxy names in values; no Python; `--kube-context` required; Argo CD key handling documented (existing Secrets, no keys in rendered YAML). Open: items 5 and 19 |

The chart also runs as non-root on every container, with a read-only root
filesystem, no capabilities, `RuntimeDefault` seccomp, no service-account
token, no RBAC and no cluster-scoped objects (fits Pod Security
`restricted`).

## Open items

### Before MetLife architecture review or any production data

**1. Connector inventory: fill in the allowlists.** *Owner: NeuBird
engineering. About 2 days.*
For each pilot connector (Splunk, ServiceNow, Maestro MCP), list every
endpoint and method it calls, every response field it reads, and every MCP
tool it uses. That list becomes `methods`, `paths`, `response_fields` and
`mcp_tools`, replacing the placeholders in `deploy/config.example.yaml` and
the `*` methods in MetLife's values.
- *How:* read the connector code, and run each connector against a staging
  proxy fed synthetic data. The audit log records method, path and
  `query_keys` for every call. Never do this discovery against real MetLife
  data, since allowlists are open during it.
- *Also answers:* whether connectors follow absolute URLs in bodies (item
  14), and the largest response body, which sets `max_body_bytes`.
- *Done when:* the allowlists are real, and every connector passes its test
  suite through a proxy using them.

**2. Detection-rate evaluation on MetLife data.** *Owner: MetLife security
runs it; NeuBird engineering supports. About 3 days.*
Nobody has measured what the rules catch on real MetLife data. MetLife runs
`neubird-proxy -config config.yaml -redact sample.json` on representative
samples from each system, inside their own network, and reviews the output.
- *Decide first:* the sample (for example, 1,000 Splunk events per major
  index, 500 ServiceNow incidents, 100 MCP tool results) and the acceptance
  bar, for example no missed formatted SSN, card or email, and a named list of
  accepted misses.
- *Loop:* every miss becomes a custom rule, a builtin fix, or a
  `response_fields` change, plus a golden-file test on synthetic data of the
  same shape.
- *Done when:* MetLife security signs off on the result against the
  agreed bar.

**3. Decide how to handle free-text fields that must pass.** *Owner: MetLife
security (decision); NeuBird engineering (build). Decision first, then 1–3
weeks depending on the option.*
`response_fields` keeps unapproved free text inside MetLife. But the agent
needs some free text: Splunk `_raw` log lines and MCP tool output. Names,
addresses and health conditions in those fields get through today. The
options, not mutually exclusive:
- (a) Accept regex plus allowlisting for those fields, with item 2's
  measured miss rate as the evidence.
- (b) Add NER (Presidio or similar) for the named free-text fields only, as a
  sidecar the proxy calls. That costs latency and a larger image to review.
  NeuBird would need to measure accuracy and the throughput impact.
- (c) Mask upstream: Cribl for Splunk (already procured), so `_raw` is clean
  before it reaches the proxy.

*Recommendation:* (a) plus (c) for the pilot. Use (b) only if item 2 shows
misses MetLife won't accept.

**4. Independent security review.** *Owner: NeuBird security to commission,
or MetLife red team. 1–2 weeks elapsed.*
The code is new and was substantially AI-assisted, and every review so far
was internal. A reviewer outside the authoring team should do a source
review and a penetration test of a deployed instance. Scope: the attack
classes from the reviews (routing and path confusion, header smuggling,
encoding evasion, fail-open paths) plus the tunnel: enrollment and join
tokens, key revocation, the relay's tenant isolation, and what a compromised
relay could make the proxy do.
- *Done when:* the report has no open high findings, and its tests are added
  to CI.

**5. Image provenance: keyless signing and admission.** *Owner: NeuBird
engineering (CI); MetLife platform (admission). About 1 day each.*
Images are signed today with a NeuBird-held cosign key, and packages ship the
public key. Remaining:
- Keyless signing (cosign with GitHub OIDC), so there's no long-lived
  signing key to protect or ship, and the signature names the workflow that
  built the image. Raised again in the install review.
- MetLife verifies the signature (and optionally the provenance) at
  admission, or mirrors only verified digests into their registry.
- Alternatively MetLife builds the image from reviewed source in their own
  pipeline, which removes NeuBird from the trust chain.

**6. Tunnel identity: operating procedures.** *Owner: NeuBird engineering,
with MetLife security. About 1 day.*
The controls exist (single-use, expiring join tokens; per-key enrollment;
revocation at the relay). Write down and agree:
- how join tokens reach MetLife (a package sent over a secure channel, never
  email or chat) and their lifetime (72 hours by default)
- key rotation: a new key Secret, enrolled with a new token, then revoke the
  old fingerprint (chart README, Operate)
- who at NeuBird may revoke a key or issue a token, and how MetLife asks
- that NeuBird's relay records are kept in Git and match the live relay
- *Done when:* MetLife security accepts the procedure.

### Pilot hardening

**7. Ship audit logs to MetLife's SIEM.** *Owner: MetLife platform. About 1
day.* Forward the pod's stdout to MetLife's log pipeline, with their standard
retention. That gives tamper evidence, since pod logs are ephemeral. Alert
on:
- any `risky configuration` warning (expected today: `client_auth: none` and
  `*` hosts, until item 1)
- a `config_sha256` change outside a change window
- spikes in `neubird_proxy_blocked_total`, especially `request_denied`,
  `path_not_allowed` and `destination_not_allowed`
- the proxy losing all tunnels (pods not Ready)

NeuBird can share the relay's logs for MetLife's tenant on request.

**8. Change control for the configuration.** *Owner: MetLife platform. About
1 day.* Manage the Helm values through GitOps with required review, and
restrict namespace edit rights. `passthrough: true` should need security
approval. With Argo CD, create the tunnel key and env Secrets outside the
chart and set `tunnelKey.existingSecret` and `env.existingSecret` (chart
README), so no key is generated on render or lands in Git.

**9. A global rate limit.** *Owner: NeuBird engineering. Decision, then
about 1 day.* The proxy's `rate_limit` is per connection and per pod, so the
effective limit is that times the replica count (MetLife's values: 10/s,
burst 30, across all destinations). APIM used to be the global ceiling; it's
no longer in the path. Decide whether the relay should enforce a per-tenant
ceiling, or whether the per-pod limit with a fixed replica count is enough.

**10. Egress control.** *Owner: MetLife platform. Under a day.* With
`neubird_destinations.hosts: ["*"]`, the network decides what NeuBird can
reach. Turn on the chart's NetworkPolicy (`--allow-cidrs`) on a cluster that
enforces it, with a default-deny policy in the namespace, or route egress
through Azure Firewall or an egress proxy with an allowlist (MetLife README,
Locking down the network). No TLS inspection on the relay host.

**11. Throughput, if bodies are large.** *Owner: NeuBird engineering. 3–5
days. Depends on item 1.*
Splunk exports now stream: the first result leaves in about a millisecond,
and when Splunk is slower than 11–16 MB/s (a running search), the proxy's
cost is hidden. What remains is CPU per response: an 18 MB export that
Splunk already holds takes 1.2–1.7 s to redact on one core. If item 1 shows
this matters, redact documents in parallel across cores and replace the
`encoding/json` tokenizer, targeting 50 MB/s or more. Keep the fuzz and
golden tests as the safety net.

**12. Patching and CVE response.** *Owner: NeuBird engineering (automation);
NeuBird security and legal (SLA). About 1 day.*
- Schedule `govulncheck` and the Trivy scan weekly in CI; today they run
  only on push and pull requests.
- Use Renovate or Dependabot for the Go toolchain, base image digests and
  action SHAs; neither is set up.
- Put a response SLA in the support agreement, for example critical fixes
  shipped within 7 days, and name an owner.

**13. HMAC masking decision.** *Owner: MetLife privacy. Decision only.*
MetLife packages use `mask: hmac`, so NeuBird can correlate a masked value
without seeing it. Is that output still personal data under MetLife's
policies? Where is `REDACTION_HMAC_KEY` kept (it's generated in MetLife's
cluster; MetLife Key Vault for the long term), and is it ever rotated
(rotating changes every code)? If MetLife decides against it, switch to
`mask: label`.

### Later

**14. Rewrite absolute URLs in bodies.** *Owner: NeuBird engineering. Depends
on item 1.* Needed only if a connector follows pagination links or job URIs
from response bodies. `Location` headers are already rewritten.

**15. Hot reload of config.** *Owner: NeuBird engineering. Low priority.*
v1 restarts pods on a config change, which suits change control (item 8).

**16. MetLife-specific rules.** *Owner: MetLife security supplies patterns;
NeuBird engineering adds tests.*
- Internal hostnames and paths, for example `*.corp.metlife.com`.
- Real member, policy and claim number formats (the `member_id` pattern is a
  placeholder).
- Non-US identifier formats, if any pilot data covers international
  members.
- Whether to turn on `windows_account`.

**17. Deployment values.** *Owner: MetLife platform.*
- NeuBird's package presets the image (by digest), relay and relay CA; the
  chart comes from `oci://ghcr.io/neubirdai/charts/neubird-proxy`. MetLife
  sets `neubird_destinations.hosts`, egress (item 10), `--upstream-ca` for
  internal certificates, and `--image-repo` if they mirror the image.
- Confirm Pod Security `restricted` and the read-only root filesystem work in
  their cluster.

**18. Load test in a MetLife-like environment.** *Owner: NeuBird
engineering. About 2 days.* Run realistic payload mixes at expected
concurrency through the tunnel, with the chart's resource limits. Confirm
`max_concurrent_buffered` and the 768 Mi memory limit hold, and record
p50/p99 latency added per request, including the relay hop.

**19. Hide internal names in NeuBird's UI.** *Owner: NeuBird engineering.*
Raised in the install review: NeuBird's UI shows internal DNS names and IPs
of the proxy's destinations. Show only what the user needs.

## Suggested order

For MetLife's architecture review, bring:
- the tunnel model and the findings table above
- the decisions needed on items 3, 5 and 13
- the owners and dates for items 1, 2, 4 and 6

Production data waits for items 1–6. Items 7, 8 and 10 are MetLife
configuration work that can run in parallel with them.
