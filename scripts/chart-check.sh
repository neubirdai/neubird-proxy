#!/usr/bin/env bash
# Checks the Helm chart: lint, render with the CI values, then have this
# build of neubird-proxy validate the rendered config with the key the
# chart generated, and confirm each required value fails clearly.
set -euo pipefail
cd "$(dirname "$0")/.."
CHART=deploy/helm/neubird-proxy
HELM_IMAGE=${HELM_IMAGE:-alpine/helm:3.16.4}
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
echo "ok    chart renders a config this build accepts"

for set in config.upstream_ca_file=/x image.repository= env.existingSecret= tunnelKey.generate=false networkPolicy.relayCIDRs=null tunnel.tenant=Bad_Name; do
  if helm template p /chart "${args[@]}" --set "$set" >/dev/null 2>&1; then fail "rendered with --set $set"; fi
done
echo "ok    missing or invalid required values are refused"

# What ships to customers: the packaged chart must not name NeuBird's
# internal registries, tenants, clusters or repositories.
helm package /chart -d /w >/dev/null || fail "helm package"
mkdir "$W/pkg" && tar xzf "$W"/neubird-proxy-*.tgz -C "$W/pkg"
if leaks=$(grep -rniE 'neubirdai|docker\.io|metlife|swift|dev-aks|raven|splunk-e2e|github\.com|this repository' "$W/pkg"); then
  echo "$leaks"; fail "internal references in the packaged chart"
fi
[ ! -e "$W/pkg/neubird-proxy/ci" ] || fail "ci/ values are packaged"
echo "ok    packaged chart is self-contained (no internal references)"
