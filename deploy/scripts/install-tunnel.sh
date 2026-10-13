#!/usr/bin/env bash
# Install neubird-proxy in tunnel mode the way a customer does, then check it
# end to end: Secret with the join token, helm install, enrollment and
# tunnels, a test of each system, and removing the spent join token.
#
#   KUBE_CONTEXT=<ctx> VALUES=values.yaml RELAY_CA=relay-ca.crt \
#   JOIN_TOKEN_FILE=join.token deploy/scripts/install-tunnel.sh
#
# Optional: NAMESPACE (neubird), RELEASE (neubird-proxy), CHART (this repo's
# chart, or a packaged .tgz), UPSTREAM_CA (a CA bundle for upstreamCA),
# TIMEOUT (seconds to wait for the tunnels, 300). Nothing secret is printed.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${KUBE_CONTEXT:?}" "${VALUES:?}" "${RELAY_CA:?}"
NAMESPACE=${NAMESPACE:-neubird}
RELEASE=${RELEASE:-neubird-proxy}
CHART=${CHART:-deploy/helm/neubird-proxy}
TIMEOUT=${TIMEOUT:-300}
SECRET=$(python3 -c "import yaml,sys; print((yaml.safe_load(open(sys.argv[1])).get('env') or {}).get('existingSecret') or 'neubird-proxy-env')" "$VALUES")
k() { kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" "$@"; }
step() { printf '\n== %s\n' "$*"; }
ok() { printf 'ok    %s\n' "$*"; }
die() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
args=(-f "$VALUES" --set-file "relayCA.cert=$RELAY_CA")
[ -n "${UPSTREAM_CA:-}" ] && args+=(--set-file "upstreamCA.cert=$UPSTREAM_CA")

step "render"
rendered=$(helm template "$RELEASE" "$CHART" -n "$NAMESPACE" "${args[@]}") || die "the values don't render"
config=$(echo "$rendered" | python3 -c "
import sys,yaml
for d in yaml.safe_load_all(sys.stdin):
    if d and d.get('kind')=='ConfigMap' and 'config.yaml' in (d.get('data') or {}): print(d['data']['config.yaml'])")
grep -q '^listen: "off"' <<<"$config" || die "not a tunnel-only proxy (mode: tunnel)"
ok "tunnel mode; relays $(python3 -c "import sys,yaml; print(', '.join(yaml.safe_load(sys.stdin)['tunnel']['relays']))" <<<"$config")"

step "namespace and Secret $SECRET"
kubectl --context "$KUBE_CONTEXT" get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl --context "$KUBE_CONTEXT" create namespace "$NAMESPACE" >/dev/null
k get secret "$SECRET" >/dev/null 2>&1 || k create secret generic "$SECRET" >/dev/null
put() { # put KEY FILE: add one key, keeping the others
  k patch secret "$SECRET" --type=merge -p "{\"data\":{\"$1\":\"$(base64 < "$2" | tr -d '\n')\"}}" >/dev/null
}
if [ -n "${JOIN_TOKEN_FILE:-}" ]; then
  grep -qE '^nbjt_[A-Za-z0-9_-]{43}$' "$JOIN_TOKEN_FILE" || die "$JOIN_TOKEN_FILE doesn't hold a join token"
  put NEUBIRD_JOIN_TOKEN "$JOIN_TOKEN_FILE"; ok "join token added"
fi
if grep -q 'mask: hmac' <<<"$config"; then
  have=$(k get secret "$SECRET" -o jsonpath='{.data.REDACTION_HMAC_KEY}')
  if [ -z "$have" ]; then
    t=$(mktemp); openssl rand -hex 32 | tr -d '\n' > "$t"; put REDACTION_HMAC_KEY "$t"; rm -f "$t"; ok "REDACTION_HMAC_KEY generated"
  fi
fi

step "helm upgrade --install $RELEASE"
helm --kube-context "$KUBE_CONTEXT" upgrade --install "$RELEASE" "$CHART" -n "$NAMESPACE" "${args[@]}" >/dev/null
ok "installed"

step "enrollment and tunnels (up to ${TIMEOUT}s)"
end=$((SECONDS + TIMEOUT)); enrolled=""; connected=0
while [ $SECONDS -lt $end ]; do
  logs=$(k logs -l "app.kubernetes.io/instance=$RELEASE" --tail=-1 2>/dev/null || true)
  grep -qE '"msg":"(enrolled with the join token|key already enrolled)"' <<<"$logs" && enrolled=1
  if r=$(grep -oE 'relay refused: [^"]+' <<<"$logs" | tail -1) && [ -n "$r" ] && [ -z "$enrolled" ]; then die "$r"; fi
  connected=$(grep -c '"msg":"tunnel connected"' <<<"$logs" || true)
  [ "$connected" -gt 0 ] && k rollout status "deploy/$RELEASE" --timeout=5s >/dev/null 2>&1 && break
  sleep 5
done
[ "$connected" -gt 0 ] || die "no tunnel connected; last errors: $(grep -oE '"msg":"tunnel connect failed"[^}]*' <<<"$logs" | tail -1)"
ok "${enrolled:+key enrolled; }$connected tunnel connection(s); pods ready"

step "test the tunnel and each system"
dep=$(k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o jsonpath='{.items[0].metadata.name}')
k exec "deploy/$dep" -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml 2>&1 | grep -v 'Unknown stream id' || die "tunnel test failed"
urls=$(python3 -c "
import sys,yaml
c=yaml.safe_load(sys.stdin); h=(c.get('neubird_destinations') or {}).get('hosts') or []
print(' '.join('https://'+x for x in h if '*' not in x))" <<<"$config")
if [ -n "$urls" ]; then
  # shellcheck disable=SC2086
  k exec "deploy/$dep" -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml $urls 2>&1 | grep -v 'Unknown stream id' || die "a system failed its test"
fi

if [ -n "$enrolled" ] && [ -n "$(k get secret "$SECRET" -o jsonpath='{.data.NEUBIRD_JOIN_TOKEN}')" ]; then
  step "remove the spent join token"
  k patch secret "$SECRET" --type=json -p '[{"op":"remove","path":"/data/NEUBIRD_JOIN_TOKEN"}]' >/dev/null
  ok "NEUBIRD_JOIN_TOKEN removed from $SECRET"
fi
printf '\nDone. Tell NeuBird the proxy is up; they record the key and set up the connections.\n'
