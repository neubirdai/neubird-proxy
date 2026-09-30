# Security plan: closing the MetLife review gaps

Sep 30, 2026. Follows an adversarial review of the proxy from the point of
view of a MetLife security architect. That review found 5 blockers, 5 major
issues and 5 governance gaps. This document records what the code now
handles and plans the rest. The rest needs a decision, data, access or
credentials that engineering alone does not have.

Effort figures are estimates, not sized by the owning team.

## Where each finding stands

| # | Finding | Status | How |
|---|---|---|---|
| 1 | PII in encoded or unformatted forms, and free-text PHI | **Partly fixed** | Normalization (percent, HTML entities, full-width, zero-width) and keyword rules for unformatted SSN, phone and DOB are done. Free text is handled by `response_fields` for fields that don't need to pass; fields that must pass as free text (Splunk `_raw`, MCP tool text) depend on the rules. Open: items 2, 3 |
| 2 | Secrets not detected | **Fixed** | 8 secret rules: private keys, JWT, AWS, Azure, vendor tokens, URL credentials, bearer values, `password=`-style assignments, with matching key rules |
| 3 | Compressed or binary data labeled as text leaks | **Fixed** | Non-UTF-8 or NUL-containing bodies and SSE events are refused (`not_text`) |
| 4 | Backend session cookies forwarded | **Fixed** | `Set-Cookie` is stripped on every connection, including passthrough |
| 5 | Gateway with write access | **Fixed in code; config open** | GET/HEAD by default, plus `methods`, `paths`, `request_deny_patterns` (Splunk SPL) and `mcp_tools`. The allowlists in the example config are placeholders. Open: item 1 |
| 6 | One static token opens everything | **Fixed in code; rollout open** | Per-connection tokens, a previous token for rotation, a 32-character minimum, optional mTLS. Open: item 6 |
| 7 | Arbitrary client headers forwarded (APIM trace) | **Fixed** | Request header allowlist; trace, debug and credential headers can't be allowlisted. APIM-side hardening: item 10 |
| 8 | Internal topology leaks (hostnames, paths) | **Open (config)** | Needs MetLife's domain and path patterns as custom rules, or `response_fields`. Item 16 |
| 9 | No rate limits, concurrency limits or performance evidence | **Fixed; one follow-up** | Per-connection rate limits, a global concurrency cap, a buffered-body cap, benchmarks and a measured peak heap. Throughput is 11–16 MB/s, and Splunk exports stream, so the first result leaves in about 1 ms. Open: items 9, 11, 18 |
| 10 | Audit can't attribute or reconstruct access | **Fixed in code; shipping open** | Request ID (echoed upstream and to the client), remote and forwarded address, query parameter names, config SHA-256 at startup. Open: item 7 |
| 11 | ConfigMap edit can turn on passthrough | **Mitigated; process open** | Startup warnings, `-check` warnings, and the config hash in logs. Open: item 8 |
| 12 | Unpinned build inputs, no signing | **Partly fixed** | Base image digests, Go toolchain 1.26.8 (govulncheck clean), and CI actions are all pinned. Open: item 5 |
| 13 | Thin assurance | **Partly fixed** | Fuzz tests on 4 targets, govulncheck in CI, a regression test per finding; coverage is 94% (proxy) and 92% (redaction), with config validation tested from the proxy package. Open: items 2, 4 |
| 14 | HMAC is pseudonymization | **Documented; decision open** | Item 13 |
| 15 | No patch ownership | **Open** | Item 12 |

The review also turned up one leak the finding list didn't cover: upstream
1xx (103 Early Hints) headers were relayed before redaction. It is fixed.

## Open items

### Before MetLife architecture review or any production data

**1. Connector inventory: fill in the allowlists.** *Owner: NeuBird
engineering. About 2 days.*
For each pilot connector (Splunk, ServiceNow, Maestro MCP), list every
endpoint and method it calls, every response field it reads, and every MCP
tool it uses. That list becomes `methods`, `paths`, `response_fields` and
`mcp_tools`, replacing the placeholders in `deploy/config.example.yaml`.
- *How:* read the connector code, and run each connector against a staging
  proxy fed synthetic data. The audit log records method, path and
  `query_keys` for every call. Never do this discovery against real MetLife
  data, since allowlists are open during it.
- *Also answers:* whether connectors follow absolute URLs in bodies (item
  14), and the largest response body, which sets `max_body_bytes`.
- *Done when:* the example config's allowlists are real, and every connector
  passes its test suite through a proxy using them.

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
  before it reaches APIM.

*Recommendation:* (a) plus (c) for the pilot. Use (b) only if item 2 shows
misses MetLife won't accept.

**4. Independent security review.** *Owner: NeuBird security to commission,
or MetLife red team. 1–2 weeks elapsed.*
The code is new and was substantially AI-assisted. A reviewer outside the
authoring team should do a source review and a penetration test of a
deployed instance. Scope: the attack classes from the review (routing and
path confusion, header smuggling, encoding evasion, fail-open paths, token
handling) plus anything the reviewer adds.
- *Done when:* the report has no open high findings, and its tests are added
  to CI.

**5. Image provenance.** *Owner: MetLife platform (decision); NeuBird
engineering (CI). About 1 day after the decision.*
Choose one:
- (a) MetLife builds the image from reviewed source in their own pipeline,
  which removes NeuBird from the trust chain.
- (b) NeuBird signs images in CI (cosign, keyless via GitHub OIDC, with SLSA
  provenance), and MetLife verifies the signature at admission.

Either way, publish the SBOM (`make sbom`) with each release. Blocked on a
decision about where images are published, and on MetLife's admission
policy tooling.

**6. Tokens and mTLS rollout.** *Owner: NeuBird engineering, with MetLife
security. About 2 days, plus certificate issuance lead time.*
- Generate one token per connection (`openssl rand -hex 32`). Agree on how
  each token reaches NeuBird's secret store without email or chat, and set
  a rotation schedule (for example every 90 days), using
  `client_token_previous_env` for no-downtime rotation.
- For mTLS: check whether NeuBird's Splunk, ServiceNow and MCP connectors
  can present a client certificate. Agree who issues it (a MetLife CA is
  preferable), then enable `tls.client_ca_file`.
- *Done when:* each connection has its own token and mTLS is on, or MetLife
  accepts the source-IP allowlist plus token as sufficient.

### Pilot hardening

**7. Ship audit logs to MetLife's SIEM.** *Owner: MetLife platform. About 1
day.* Forward the pod's stdout to MetLife's log pipeline, with their standard
retention. That gives tamper evidence, since pod logs are ephemeral. Alert
on:
- any `risky configuration` warning
- a `config_sha256` change outside a change window
- spikes in `neubird_proxy_blocked_total`, especially `request_denied`,
  `path_not_allowed` and `unauthorized`

**8. Change control for the ConfigMap.** *Owner: MetLife platform. About 1
day.* Manage the ConfigMap through GitOps with required review, and restrict
namespace edit rights. `passthrough: true` should need security approval.

**9. Global rate limits in APIM.** *Owner: MetLife APIM team. Under a day.*
The proxy's `rate_limit` is per pod, so the effective limit is that times
the replica count. Set a `rate-limit-by-key` or `quota-by-key` policy on
the proxy's subscription as the global ceiling.

**10. Harden the APIM side.** *Owner: MetLife APIM team. Under a day.*
- Scope the proxy's subscription to a product that contains only the pilot
  APIs, and only their read operations where APIM defines them.
- Turn off request tracing for that subscription.
- Confirm the Key Vault named values it relies on are readable only by the
  gateway.

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
- Schedule `govulncheck` weekly in CI, not only on push.
- Use Renovate or Dependabot for the Go toolchain, base image digests and
  action SHAs.
- Put a response SLA in the support agreement, for example critical fixes
  shipped within 7 days, and name an owner.

**13. HMAC masking decision.** *Owner: MetLife privacy. Decision only.*
If `mask: hmac` is used, is the output still personal data under MetLife's
policies? Where is `REDACTION_HMAC_KEY` kept (MetLife Key Vault), and how is
it rotated? Until decided, keep `mask: label`, the default.

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
- Fill in the `CHANGE ME` values in `deploy/kubernetes.yaml`: image,
  namespace, load balancer and APIM CIDRs, monitoring namespace.
- Confirm Pod Security admission and the read-only root filesystem work in
  their cluster.

**18. Load test in a MetLife-like environment.** *Owner: NeuBird
engineering. About 2 days.* Run realistic payload mixes at expected
concurrency against the Kubernetes manifest's resource limits. Confirm
`max_concurrent_buffered` and the 512 MiB memory limit hold, and record
p50/p99 latency added per connection.

## Suggested order

For the Oct 5 architecture review, bring:
- the fixed-findings table above
- the decisions needed on items 3, 5 and 13
- the owners and dates for items 1, 2, 4 and 6

Production data waits for items 1–6. Items 7–10 are MetLife configuration
work that can run in parallel with them.
