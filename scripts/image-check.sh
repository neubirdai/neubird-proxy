#!/usr/bin/env bash
# Smoke-tests a built image the way the chart runs it: no shell in it, runs
# as nonroot, and with MetLife's chart values (relay pointed nowhere) it
# starts on a read-only root filesystem with no capabilities, reports the
# expected version, is live but not ready without a tunnel, and its tools
# (keygen, fingerprint, validate) work. CI runs it after `make image`.
#
#   scripts/image-check.sh <image> [<version>]
#   e.g. scripts/image-check.sh neubird-proxy:$(git rev-parse HEAD) $(git rev-parse HEAD)
#
# Needs docker, openssl, python3 and curl. Everything secret is throwaway.
set -euo pipefail
[ $# -ge 1 ] || { echo "usage: $0 <image> [<version>]" >&2; exit 2; }
img=$1 want_version=${2:-}
cd "$(dirname "$0")/.."
CHART=deploy/helm/neubird-proxy
HELM_IMAGE=${HELM_IMAGE:-alpine/helm:3.16.4@sha256:9b25e60ae264940b276e32866d37e3088e70c4e2d1784b964dc3f90346281a74}
W=$(mktemp -d); name=image-check-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$W"' EXIT
fail() { echo "FAIL  $*"; exit 1; }
ok() { echo "ok    $*"; }
# The pod's restrictions (deployment.yaml's securityContext), minus the
# volumes, which each check mounts itself.
pod=(--read-only --cap-drop ALL --security-opt no-new-privileges --user 65532:65532)

# The image as built: user, entrypoint, no shell.
user=$(docker image inspect -f '{{.Config.User}}' "$img")
case "$user" in nonroot|nonroot:nonroot|65532|65532:65532) ok "runs as $user" ;; *) fail "image user is '$user', not nonroot" ;; esac
[ "$(docker image inspect -f '{{json .Config.Entrypoint}}' "$img")" = '["/neubird-proxy"]' ] || fail "entrypoint isn't /neubird-proxy"
for sh in /bin/sh /bin/bash /busybox/sh; do
  if docker run --rm --entrypoint "$sh" "$img" -c true >/dev/null 2>&1; then fail "$sh runs in the image"; fi
done
ok "no shell"
docker run --rm "${pod[@]}" "$img" help | grep -q '^commands:' || fail "help"

# keygen and fingerprint, writing only to a tmpfs as in the pod.
out=$(docker run --rm "${pod[@]}" --tmpfs /tmp:uid=65532 "$img" keygen -tenant acme -proxy aks-prod -key-out /tmp/tunnel.key) \
  || fail "keygen on a read-only root filesystem"
grep -q '^fingerprint: sha256:' <<<"$out" || fail "keygen printed no fingerprint"
ok "keygen"

# MetLife's values, rendered by the chart with a throwaway relay CA and
# the relay at an address that doesn't resolve.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=image-check relay CA" -keyout "$W/ca.key" -out "$W/ca.crt" 2>/dev/null
docker run --rm -v "$PWD/$CHART:/chart:ro" -v "$PWD/deploy/metlife:/v:ro" -v "$W:/w" "$HELM_IMAGE" \
  template p /chart -f /v/values.yaml --set-file relayCA.cert=/w/ca.crt --set 'tunnel.relays={relay.invalid:443}' > "$W/out.yaml"
python3 - "$W" <<'PY'
# The config.yaml block and the generated tunnel.key, as in chart-check.sh.
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
chmod 644 "$W/tunnel.key" "$W/ca.crt" "$W/config.yaml"   # throwaway; the container's user reads them
# A join token in the right form (nbjt_ and 43 characters) that no relay issued.
token=nbjt_$(openssl rand 32 | openssl base64 -A | tr '+/' '-_' | tr -d '=')
mounts=(-v "$W/config.yaml:/etc/neubird-proxy/config.yaml:ro" -v "$W/tunnel.key:/etc/neubird-proxy/tunnel/tunnel.key:ro"
  -v "$W/ca.crt:/etc/neubird-proxy/ca/relay-ca.crt:ro")

docker run --rm "${pod[@]}" "${mounts[@]}" "$img" fingerprint /etc/neubird-proxy/tunnel/tunnel.key | grep -q 'sha256:' \
  || fail "fingerprint of the chart's key"
docker run --rm "${pod[@]}" "${mounts[@]}" -e NEUBIRD_JOIN_TOKEN="$token" "$img" \
  validate -config /etc/neubird-proxy/config.yaml > "$W/validate.txt" || { cat "$W/validate.txt"; fail "validate MetLife's rendered config"; }
ok "validate MetLife's rendered config"

# Start it as the pod does. Without a relay it must stay up and live but
# never turn ready.
docker run -d --name "$name" "${pod[@]}" "${mounts[@]}" -e NEUBIRD_JOIN_TOKEN="$token" \
  -p 127.0.0.1::9090 "$img" >/dev/null
port=$(docker port "$name" 9090/tcp | head -1 | sed 's/.*://')
for _ in $(seq 1 30); do
  curl -fsS -o /dev/null "http://127.0.0.1:$port/healthz" 2>/dev/null && break
  [ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ] || { docker logs "$name"; fail "the proxy exited"; }
  sleep 1
done
curl -fsS -o /dev/null "http://127.0.0.1:$port/healthz" || { docker logs "$name"; fail "/healthz isn't 200"; }
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/readyz")
[ "$code" != 200 ] || fail "/readyz is 200 with no tunnel"
ok "live; not ready without a tunnel (/readyz $code)"
docker logs "$name" > "$W/logs.txt" 2>&1
start=$(grep -m1 '"msg":"starting"' "$W/logs.txt") || fail "no starting log line"
got=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["version"])' "$start")
[ -z "$want_version" ] || [ "$got" = "$want_version" ] || fail "version $got, want $want_version"
ok "starts on a read-only root filesystem, no capabilities (version $got)"
! grep -qF "$token" "$W/logs.txt" || fail "the join token appears in the logs"
ok "the join token isn't logged"
