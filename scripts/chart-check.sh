#!/usr/bin/env bash
# Checks the Helm chart: lint, render with the CI values, then have this
# build of neubird-proxy validate the rendered config with the key the
# chart generated, and confirm each required value fails clearly.
set -euo pipefail
cd "$(dirname "$0")/.."
CHART=deploy/helm/neubird-proxy
HELM_IMAGE=${HELM_IMAGE:-alpine/helm:3.16.4@sha256:9b25e60ae264940b276e32866d37e3088e70c4e2d1784b964dc3f90346281a74}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
helm() { docker run --rm -v "$PWD/$CHART:/chart:ro" -v "$W:/w" "$HELM_IMAGE" "$@"; }
fail() { echo "FAIL: $*"; exit 1; }

go build -o "$W/neubird-proxy" ./cmd/neubird-proxy
# A throwaway relay CA, as NeuBird would send one.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=chart-check relay CA" -keyout "$W/ca.key" -out "$W/ca.crt" 2>/dev/null
# The same throwaway CA also stands in for an upstream CA bundle (upstreamCA).
args=(-f /chart/ci/tunnel-values.yaml --set-file relayCA.cert=/w/ca.crt --set-file upstreamCA.cert=/w/ca.crt)

helm lint /chart "${args[@]}" >/dev/null || fail "helm lint"
helm template p /chart "${args[@]}" > "$W/out.yaml" || fail "helm template"
python3 - "$W" <<'PY'
# Standard library only (CI runners may lack PyYAML): pull the config.yaml
# block and the tunnel.key value out of the rendered manifests.
import base64, sys
w = sys.argv[1]
config, key, inblock = [], None, False
for line in open(w + "/out.yaml").read().splitlines():
    if inblock:
        if line.startswith("    ") or not line.strip():
            config.append(line[4:])
            continue
        inblock = False
    if line == "  config.yaml: |":
        inblock = True
    elif line.startswith("  tunnel.key: "):
        key = line.split(": ", 1)[1]
if not config or not key:
    sys.exit("config.yaml or tunnel.key not found in the rendered chart")
open(w + "/config.yaml", "w").write("\n".join(config).strip() + "\n")
open(w + "/tunnel.key", "wb").write(base64.b64decode(key))
PY
"$W/neubird-proxy" fingerprint "$W/tunnel.key" >/dev/null || fail "the chart's generated key isn't usable"
sed -e "s|/etc/neubird-proxy/tunnel/tunnel.key|$W/tunnel.key|" -e "s|/etc/neubird-proxy/ca/relay-ca.crt|$W/ca.crt|" \
  -e "s|/etc/neubird-proxy/upstream-ca/ca.crt|$W/ca.crt|" \
  "$W/config.yaml" > "$W/local.yaml"
T=check-only-0123456789abcdef012345
NEUBIRD_PROXY_TOKEN=$T REDACTION_HMAC_KEY=$T SPLUNK_TOKEN=x \
  "$W/neubird-proxy" validate -config "$W/local.yaml" > "$W/validate.txt" || { cat "$W/validate.txt"; fail "rendered config invalid"; }
grep -q 'identity: tenant acme, proxy aks-prod' "$W/validate.txt" || fail "tunnel identity not generated"
grep -q "join token: NEUBIRD_JOIN_TOKEN is empty" "$W/validate.txt" || fail "join_token_env not generated"
grep -q 'upstream_ca_file:' "$W/config.yaml" || fail "upstreamCA did not set upstream_ca_file"
grep -q 'name: HTTPS_PROXY' "$W/out.yaml" || fail "extraEnv not rendered into the Deployment"
grep -A3 'ipBlock: {cidr: 203.0.113.10/32}' "$W/out.yaml" | grep -q 'port: 443' || fail "relay port not in the NetworkPolicy"
echo "ok    chart renders a config this build accepts"

for set in config.upstream_ca_file=/x image.repository= env.existingSecret= tunnelKey.generate=false networkPolicy.relayCIDRs=null tunnel.tenant=Bad_Name; do
  if helm template p /chart "${args[@]}" --set "$set" >/dev/null 2>&1; then fail "rendered with --set $set"; fi
done
echo "ok    missing or invalid required values are refused"

# Mode inbound: a listener with TLS and client certificates, no tunnel.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=neubird-proxy" -keyout "$W/tls.key" -out "$W/tls.crt" 2>/dev/null
iargs=(-f /chart/ci/inbound-values.yaml --set-file inbound.clientCA.cert=/w/ca.crt)
helm lint /chart "${iargs[@]}" >/dev/null || fail "helm lint (inbound)"
helm template p /chart "${iargs[@]}" > "$W/in.yaml" || fail "helm template (inbound)"
python3 - "$W" <<'PY2'
import sys
w = sys.argv[1]
config, inblock = [], False
for line in open(w + "/in.yaml").read().splitlines():
    if inblock:
        if line.startswith("    ") or not line.strip():
            config.append(line[4:])
            continue
        inblock = False
    if line == "  config.yaml: |":
        inblock = True
if not config:
    sys.exit("config.yaml not found in the rendered inbound chart")
open(w + "/in-config.yaml", "w").write("\n".join(config).strip() + "\n")
PY2
sed -e "s|/etc/neubird-proxy/tls/|$W/|" -e "s|/etc/neubird-proxy/client-ca/ca.crt|$W/ca.crt|" \
  "$W/in-config.yaml" > "$W/in-local.yaml"
NEUBIRD_PROXY_TOKEN=$T REDACTION_HMAC_KEY=$T \
  "$W/neubird-proxy" validate -config "$W/in-local.yaml" > "$W/in-validate.txt" || { cat "$W/in-validate.txt"; fail "rendered inbound config invalid"; }
grep -q '^listen: :8443' "$W/in-config.yaml" || fail "inbound listen not set"
grep -q 'client_ca_file:' "$W/in-config.yaml" || fail "inbound.clientCA did not set tls.client_ca_file"
if grep -qE '^    tunnel:|tunnel\.key|relay-ca\.crt' "$W/in.yaml"; then fail "mode inbound rendered tunnel parts"; fi
grep -q '^kind: Service$' "$W/in.yaml" || fail "mode inbound rendered no Service"
grep -q 'port: 8443' "$W/in.yaml" || fail "NetworkPolicy does not open 8443"
if grep -q '^kind: Service$' "$W/out.yaml"; then fail "mode tunnel rendered a Service"; fi
echo "ok    mode inbound renders a config this build accepts, with no tunnel"

for set in mode=bogus inbound.tls.existingSecret= networkPolicy.inboundFrom=null 'tunnel.relays={r.example.com:443}' config.listen=:9443; do
  if helm template p /chart "${iargs[@]}" --set "$set" >/dev/null 2>&1; then fail "inbound rendered with --set $set"; fi
done
helm template p /chart -f /chart/ci/inbound-values.yaml --set inbound.tls.existingSecret= --set inbound.allowPlainHTTP=true >/dev/null \
  || fail "inbound with allowPlainHTTP did not render"
if helm template p /chart "${iargs[@]}" --set inbound.tls.existingSecret= --set inbound.allowPlainHTTP=true >/dev/null 2>&1; then
  fail "inbound rendered a client CA without TLS"
fi
echo "ok    mode inbound refuses missing or conflicting values"

# Admission policies such as OPA Gatekeeper's check each container's own
# securityContext, not the pod's: a non-root runAsUser and no privilege
# escalation, in every container of both modes.
python3 - "$W/out.yaml" "$W/in.yaml" <<'PY3' || fail "a container's securityContext fails per-container admission"
import re, sys
def indent(s): return len(s) - len(s.lstrip())
def block(lines, i):
    """The lines nested under lines[i]."""
    out = []
    for s in lines[i + 1:]:
        if s.strip() and indent(s) <= indent(lines[i]):
            break
        out.append(s)
    return out
checked = 0
for path in sys.argv[1:]:
    lines = open(path).read().splitlines()
    for i, line in enumerate(lines):
        if not re.fullmatch(r" *(initContainers|containers):", line):
            continue
        body = [s for s in block(lines, i) if s.strip()]
        dash, items = indent(body[0]), []
        for s in body:
            if indent(s) == dash and s.lstrip().startswith("- "):
                items.append([" " * (dash + 2) + s.lstrip()[2:]])
            else:
                items[-1].append(s)
        for item in items:
            name = re.search(r"name: (\S+)", "\n".join(item)).group(1)
            sc = [k for k, s in enumerate(item) if s.strip() == "securityContext:" and indent(s) == dash + 2]
            fields = "\n".join(block(item, sc[0])) if sc else ""
            user = re.search(r"^ *runAsUser: (\d+)$", fields, re.M)
            if not user or user.group(1) == "0":
                sys.exit(f"{path}: container {name}: no non-root runAsUser in its securityContext")
            if not re.search(r"^ *allowPrivilegeEscalation: false$", fields, re.M):
                sys.exit(f"{path}: container {name}: no allowPrivilegeEscalation: false in its securityContext")
            checked += 1
if not checked:
    sys.exit("no containers found in the rendered chart")
PY3
echo "ok    every container sets a non-root runAsUser and allowPrivilegeEscalation: false"

# What ships to customers: the packaged chart must not name NeuBird's
# internal registries, tenants, clusters or repositories.
helm package /chart -d /w >/dev/null || fail "helm package"
mkdir "$W/pkg" && tar xzf "$W"/neubird-proxy-*.tgz -C "$W/pkg"
if leaks=$(grep -rniE 'neubirdai|docker\.io|metlife|swift|dev-aks|raven|splunk-e2e|github\.com|this repository' "$W/pkg"); then
  echo "$leaks"; fail "internal references in the packaged chart"
fi
[ ! -e "$W/pkg/neubird-proxy/ci" ] || fail "ci/ values are packaged"
echo "ok    packaged chart is self-contained (no internal references)"
