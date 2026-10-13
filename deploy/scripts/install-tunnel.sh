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
: "${KUBE_CONTEXT:?}" "${VALUES:?}" "${RELAY_CA:?}"
# Paths are the caller's: make them absolute (and check them) up front.
abs() { [ -e "$1" ] || { printf 'FAIL  %s: no such file\n' "$1" >&2; exit 1; }; (CDPATH='' cd -P -- "$(dirname -- "$1")" >/dev/null && printf '%s/%s' "$(pwd -P)" "$(basename -- "$1")"); }
VALUES=$(abs "$VALUES"); RELAY_CA=$(abs "$RELAY_CA")
[ -n "${UPSTREAM_CA:-}" ] && UPSTREAM_CA=$(abs "$UPSTREAM_CA")
[ -n "${JOIN_TOKEN_FILE:-}" ] && JOIN_TOKEN_FILE=$(abs "$JOIN_TOKEN_FILE")
NAMESPACE=${NAMESPACE:-neubird}
RELEASE=${RELEASE:-neubird-proxy}
CHART=${CHART:-$(CDPATH='' cd -P -- "$(dirname -- "$0")/../helm/neubird-proxy" >/dev/null && pwd -P)}
[ -d "$CHART" ] || [ -f "$CHART" ] || CHART=$(abs "$CHART")
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
# The variable the proxy reads its join token from (tunnel.joinTokenEnv).
TOKEN_ENV=$(python3 -c "import sys,yaml; print(yaml.safe_load(sys.stdin)['tunnel'].get('join_token_env') or '')" <<<"$config")
if [ -n "${JOIN_TOKEN_FILE:-}" ] && [ -z "$TOKEN_ENV" ]; then
  die "the values have no tunnel.joinTokenEnv, so the proxy would ignore the join token: set tunnel.joinTokenEnv: NEUBIRD_JOIN_TOKEN"
fi

# The chart names the Deployment <release>-neubird-proxy unless the release
# name already contains neubird-proxy: find it by label, not by name.
find_dep() { k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true; }
existed=$(find_dep)

step "namespace and Secret $SECRET"
kubectl --context "$KUBE_CONTEXT" get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl --context "$KUBE_CONTEXT" create namespace "$NAMESPACE" >/dev/null
k get secret "$SECRET" >/dev/null 2>&1 || k create secret generic "$SECRET" >/dev/null
put() { # put KEY FILE: add one key, keeping the others. The value goes in a
  # private patch file, never on a command line (where ps could see it).
  local p; p=$(mktemp); chmod 600 "$p"
  printf '{"data":{"%s":"%s"}}' "$1" "$(base64 < "$2" | tr -d '\n')" > "$p"
  k patch secret "$SECRET" --type=merge --patch-file "$p" >/dev/null; rm -f "$p"
}
if [ -n "${JOIN_TOKEN_FILE:-}" ]; then
  grep -qE '^nbjt_[A-Za-z0-9_-]{43}$' "$JOIN_TOKEN_FILE" || die "$JOIN_TOKEN_FILE doesn't hold a join token"
  put "$TOKEN_ENV" "$JOIN_TOKEN_FILE"; ok "join token added as $TOKEN_ENV"; token_added=1
fi
if grep -q 'mask: hmac' <<<"$config"; then
  have=$(k get secret "$SECRET" -o jsonpath='{.data.REDACTION_HMAC_KEY}')
  if [ -z "$have" ]; then
    t=$(mktemp); openssl rand -hex 32 | tr -d '\n' > "$t"; put REDACTION_HMAC_KEY "$t"; rm -f "$t"; ok "REDACTION_HMAC_KEY generated"
  fi
fi

step "helm upgrade --install $RELEASE"
# The pod template before the upgrade: if the upgrade leaves it unchanged, no
# pod restarts (a replicaCount change bumps the generation but restarts none).
tmpl_before=""; [ -n "$existed" ] && tmpl_before=$(k get "deploy/$existed" -o jsonpath='{.spec.template}')
helm --kube-context "$KUBE_CONTEXT" upgrade --install "$RELEASE" "$CHART" -n "$NAMESPACE" "${args[@]}" >/dev/null
ok "installed"
dep=$(find_dep); [ -n "$dep" ] || die "no Deployment for release $RELEASE"
# Pods read the Secret only at start, and a Secret change alone doesn't roll
# them. If the upgrade didn't roll them either (same pod template), restart,
# so they read the new join token; never both, which would roll twice.
if [ -n "${token_added:-}" ] && [ -n "$existed" ] && [ "$(k get "deploy/$dep" -o jsonpath='{.spec.template}')" = "$tmpl_before" ]; then
  k rollout restart "deploy/$dep" >/dev/null; ok "restarted deploy/$dep to read the join token"
fi

step "enrollment and tunnels (up to ${TIMEOUT}s)"
# Enrollment refusals (token expired, used, for another proxy) are final:
# stop at once. A refused tunnel can be transient (a relay replica that hasn't
# seen a just-enrolled key yet), so it fails only if no tunnel connects within
# a minute of the first refusal.
end=$((SECONDS + TIMEOUT)); enrolled=""; connected=0; refused_at=""; ready=""
while [ $SECONDS -lt $end ]; do
  logs=$(k logs -l "app.kubernetes.io/instance=$RELEASE" --tail=-1 2>/dev/null || true)
  grep -qE '"msg":"(enrolled with the join token|key already enrolled)"' <<<"$logs" && enrolled=1
  # "relay refused: <reason>" is the relay's answer; "relay refused the
  # enrollment (...)" is a connection error the proxy retries.
  r=$(grep -oE 'enrollment: relay refused: [^"]*' <<<"$logs" | tail -1 || true)
  [ -n "$r" ] && [ -z "$enrolled" ] && die "$r (ask NeuBird for a new join token)"
  connected=$(grep -c '"msg":"tunnel connected"' <<<"$logs" || true)
  # Ready means the rollout finished: in tunnel mode a pod is ready only with
  # a tunnel up, so old pods' log lines can't stand in for it.
  if k rollout status "deploy/$dep" --timeout=5s >/dev/null 2>&1; then ready=1; break; fi
  t=$(grep -oE 'relay refused the tunnel[^"]*' <<<"$logs" | tail -1 || true)
  if [ -n "$t" ] && [ "$connected" -eq 0 ]; then
    refused_at=${refused_at:-$SECONDS}
    [ $((SECONDS - refused_at)) -ge 60 ] && die "$t"
  fi
  sleep 5
done
# The pods may have enrolled while rollout status waited: read the log again.
logs=$(k logs -l "app.kubernetes.io/instance=$RELEASE" --tail=-1 2>/dev/null || true)
grep -qE '"msg":"(enrolled with the join token|key already enrolled)"' <<<"$logs" && enrolled=1
connected=$(grep -c '"msg":"tunnel connected"' <<<"$logs" || true)
[ -n "$ready" ] || die "deploy/$dep not ready after ${TIMEOUT}s; last errors: $(grep -oE '"msg":"tunnel connect failed"[^}]*' <<<"$logs" | tail -1)"
ok "${enrolled:+key enrolled; }$connected tunnel connection(s); pods ready"

step "test the tunnel and each system"
# Judge by the test's exit status; the filter only drops kubectl's websocket noise.
ptest() { local out rc=0; out=$(k exec "deploy/$dep" -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml "$@" 2>&1) || rc=$?
  grep -v 'Unknown stream id' <<<"$out" || true; return $rc; }
ptest || die "tunnel test failed"
urls=$(python3 -c "
import sys,yaml
c=yaml.safe_load(sys.stdin); h=(c.get('neubird_destinations') or {}).get('hosts') or []
print(' '.join('https://'+x for x in h if '*' not in x))" <<<"$config")
if [ -n "$urls" ]; then
  # shellcheck disable=SC2086
  ptest $urls || die "a system failed its test"
fi

if [ -n "$enrolled" ] && [ -n "$TOKEN_ENV" ] && [ -n "$(k get secret "$SECRET" -o jsonpath="{.data.$TOKEN_ENV}")" ]; then
  step "remove the spent join token"
  k patch secret "$SECRET" --type=json -p "[{\"op\":\"remove\",\"path\":\"/data/$TOKEN_ENV\"}]" >/dev/null
  ok "$TOKEN_ENV removed from $SECRET"
fi
printf '\nDone. Tell NeuBird the proxy is up; they record the key and set up the connections.\n'
