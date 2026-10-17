#!/usr/bin/env bash
# Publish the Helm chart: package deploy/helm/neubird-proxy and push it to an
# OCI registry as <destination>/neubird-proxy:<version in Chart.yaml>. Chart
# versions are immutable: a version already there is left alone, so bump
# version in Chart.yaml to publish a change. CI runs it on main.
#
#   scripts/publish-chart.sh <destination>
#   e.g. scripts/publish-chart.sh oci://ghcr.io/neubirdai/charts
#
# Customers then install with
#   helm install neubird-proxy oci://ghcr.io/neubirdai/charts/neubird-proxy --version <version> ...
#
# Optional: REGISTRY_USERNAME and REGISTRY_PASSWORD (the registry login; CI
# uses GITHUB_TOKEN), DRY_RUN=1 (package and check, push nothing),
# PLAIN_HTTP=1 (a local test registry). Helm runs in a container pinned by
# digest, the same one `make chart-package` uses.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 <destination, e.g. oci://ghcr.io/neubirdai/charts>" >&2; exit 2; }
dest=${1%/}
case $dest in oci://*) ;; *) echo "$0: the destination must start with oci://" >&2; exit 2 ;; esac
HELM=${HELM:-alpine/helm:3.16.4@sha256:9b25e60ae264940b276e32866d37e3088e70c4e2d1784b964dc3f90346281a74}
chart=deploy/helm/neubird-proxy
summary() { [ -z "${GITHUB_STEP_SUMMARY:-}" ] || printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"; }

name=$(awk '$1 == "name:" {print $2; exit}' "$chart/Chart.yaml")
version=$(awk '$1 == "version:" {gsub(/"/, "", $2); print $2; exit}' "$chart/Chart.yaml")
[ -n "$name" ] && [ -n "$version" ] || { echo "$0: no name or version in $chart/Chart.yaml" >&2; exit 1; }
ref=$dest/$name
host=${dest#oci://}; host=${host%%/*}
echo "== $ref:$version"

# One container does the login, the check and the push, so the login is
# never written outside it. Exit 3 means the version is already there.
rc=0
out=$(docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -e REGISTRY_USERNAME -e REGISTRY_PASSWORD -e DRY_RUN -e PLAIN_HTTP \
  -e CHART="$chart" -e DEST="$dest" -e REF="$ref" -e VERSION="$version" -e HOST="$host" \
  -v "$PWD:/src:ro" -w /src --entrypoint sh "$HELM" -c '
set -eu
plain=; [ -z "${PLAIN_HTTP:-}" ] || plain=--plain-http
helm package "$CHART" -d /tmp/out >/dev/null
if [ -n "${REGISTRY_USERNAME:-}" ]; then
  printf %s "${REGISTRY_PASSWORD:-}" | helm registry login "$HOST" $plain -u "$REGISTRY_USERNAME" --password-stdin >/dev/null
fi
if helm show chart "$REF" --version "$VERSION" $plain >/dev/null 2>&1; then exit 3; fi
if [ -n "${DRY_RUN:-}" ]; then echo "dry run: packaged, nothing pushed"; exit 0; fi
helm push /tmp/out/*.tgz "$DEST" $plain 2>&1
' 2>&1) || rc=$?
[ -z "$out" ] || printf '%s\n' "$out"

case $rc in
  0) ;;
  3)
    echo "skip  $ref:$version is already published: bump version in $chart/Chart.yaml to publish this chart"
    [ -z "${GITHUB_ACTIONS:-}" ] || echo "::warning::chart $version is already published; bump version in $chart/Chart.yaml to publish the change"
    summary "Chart \`$ref:$version\` is already published: nothing pushed (bump version in Chart.yaml to publish)."
    exit 0 ;;
  *) echo "$0: publishing $ref:$version failed" >&2; exit "$rc" ;;
esac
[ -z "${DRY_RUN:-}" ] || exit 0

digest=$(printf '%s\n' "$out" | awk '$1 == "Digest:" {print $2; exit}')
echo "ok    $ref:$version ($digest)"
summary "### Published chart $ref:$version"
summary ""
summary "- digest: \`$digest\`"
summary "- install: \`helm install neubird-proxy $ref --version $version ...\`"
