#!/usr/bin/env bash
# Rescans published images for known vulnerabilities found since they were
# published: each image, each platform, with Trivy (pinned), failing when
# any has a fixable HIGH or CRITICAL one. The weekly workflow (rescan.yml)
# runs it on the images customers run; the same script is in neubird-relay.
#
#   scripts/rescan.sh <image> [<image>...]
#   e.g. scripts/rescan.sh docker.io/neubirdai/neubird-proxy:latest
#
# Optional: DOCKER_USERNAME and DOCKER_PASSWORD for a private repository,
# PLATFORMS (default linux/amd64,linux/arm64).
set -euo pipefail
[ $# -ge 1 ] || { echo "usage: $0 <image> [<image>...]" >&2; exit 2; }
TRIVY=${TRIVY:-aquasec/trivy:0.69.3@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c}
PLATFORMS=${PLATFORMS:-linux/amd64,linux/arm64}
summary() { [ -z "${GITHUB_STEP_SUMMARY:-}" ] || printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"; }
auth=()
[ -z "${DOCKER_USERNAME:-}" ] || auth=(-e TRIVY_USERNAME="$DOCKER_USERNAME" -e TRIVY_PASSWORD="${DOCKER_PASSWORD:-}")
# One vulnerability database for every scan.
cache=$(mktemp -d); trap 'rm -rf "$cache"' EXIT
chmod 777 "$cache"

summary "| Image | Platform | Fixable HIGH/CRITICAL |"
summary "|---|---|---|"
failed=0
for ref in "$@"; do
  for p in ${PLATFORMS//,/ }; do
    if out=$(docker run --rm ${auth[@]+"${auth[@]}"} -v "$cache:/root/.cache/trivy" "$TRIVY" image --quiet --scanners vuln \
        --severity HIGH,CRITICAL --ignore-unfixed --exit-code 3 --platform "$p" "$ref" 2>&1); then
      echo "ok    $ref $p"; summary "| \`$ref\` | $p | none |"
    else
      # Exit 3 is what --exit-code sets for findings; anything else is an
      # error (a pull refused, no database), which fails the run too.
      rc=$?; what=found; [ $rc = 3 ] || what="scan error ($rc)"
      echo "FAIL  $ref $p: $what"; printf '%s\n' "$out"; summary "| \`$ref\` | $p | **$what (see the log)** |"
      failed=1
    fi
  done
done
exit $failed
