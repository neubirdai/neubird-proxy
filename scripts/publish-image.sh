#!/usr/bin/env bash
# Publish the image: build it, scan it, and only then push it for linux/amd64
# and linux/arm64 with SBOM and provenance attestations, tagged <version> and
# latest; then sign the pushed digest when COSIGN_PRIVATE_KEY is set. CI runs
# it on main after `docker login`; the same script serves neubird-relay.
#
#   scripts/publish-image.sh <repository> <version>
#   e.g. scripts/publish-image.sh docker.io/neubirdai/neubird-proxy 3dc5ea1
#
# Optional: COSIGN_PRIVATE_KEY and COSIGN_PASSWORD (the signing key, as
# `cosign generate-key-pair` makes it), DOCKER_USERNAME and DOCKER_PASSWORD
# (the registry login, passed to the scanner and cosign, whose containers
# can't use the host's credential helpers), DRY_RUN=1 (build and scan, push
# nothing). Scanners and cosign run in containers pinned by digest.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <repository> <version>" >&2; exit 2; }
repo=$1 version=$2
TRIVY=${TRIVY:-aquasec/trivy:0.69.3@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c}
COSIGN=${COSIGN:-gcr.io/projectsigstore/cosign:v2.6.1@sha256:68839b7f13dac5a6744a5d8818e984dd39183374e37855c19e14d623d9bc9037}
PLATFORMS=${PLATFORMS:-linux/amd64,linux/arm64}
# The commit the image is built from, as a label: CI compares the next commit
# with the one in :latest to decide whether to publish.
REVISION=${REVISION:-$(git rev-parse HEAD)}
step() { printf '\n== %s\n' "$*"; }
summary() { [ -z "${GITHUB_STEP_SUMMARY:-}" ] || printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"; }
# trivy <ref>: HIGH or CRITICAL vulnerabilities with a fix fail it. The
# registry login, if given, goes in by variable name only, so the password is
# on no command line.
trivy() {
  local auth=()
  if [ -n "${DOCKER_USERNAME:-}" ]; then
    export TRIVY_USERNAME="$DOCKER_USERNAME" TRIVY_PASSWORD="${DOCKER_PASSWORD:-}"
    auth=(-e TRIVY_USERNAME -e TRIVY_PASSWORD)
  fi
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ${auth[@]+"${auth[@]}"} \
    "$TRIVY" image --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$@"
}

# A builder that can build several platforms and attach attestations.
docker buildx inspect publish >/dev/null 2>&1 || docker buildx create --name publish --driver docker-container >/dev/null

step "build and scan $repo:$version (linux/amd64), before anything is pushed"
docker buildx build --builder publish --platform linux/amd64 --build-arg VERSION="$version" \
  --label org.opencontainers.image.revision="$REVISION" --load -t "$repo:$version-scan" .
trivy "$repo:$version-scan"
echo "ok    no fixable HIGH or CRITICAL vulnerabilities"

if [ -n "${DRY_RUN:-}" ]; then
  echo "dry run: nothing pushed"; exit 0
fi

step "push $repo:$version ($PLATFORMS), with SBOM and provenance"
meta=$(mktemp); trap 'rm -f "$meta"' EXIT
docker buildx build --builder publish --platform "$PLATFORMS" --build-arg VERSION="$version" \
  --label org.opencontainers.image.revision="$REVISION" \
  --provenance=mode=max --sbom=true -t "$repo:$version" --metadata-file "$meta" --push .
digest=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$meta")
ref=$repo@$digest
echo "ok    $ref"

step "scan the pushed image, each platform"
for p in ${PLATFORMS//,/ }; do trivy --platform "$p" "$ref"; echo "ok    $p"; done

# Only now, with every platform scanned, does :latest move to it.
step "tag $repo:latest"
docker buildx imagetools create -t "$repo:latest" "$ref"
echo "ok    $repo:latest -> $digest"

step "sign"
if [ -n "${COSIGN_PRIVATE_KEY:-}" ]; then
  # The signature covers the index digest, so every platform's image.
  : "${DOCKER_USERNAME:?DOCKER_USERNAME and DOCKER_PASSWORD are needed to push the signature}"
  # cosign reads the login from a Docker config: a private one with only
  # this login, so the password is on no command line.
  cfg=$(mktemp -d); chmod 700 "$cfg"; trap 'rm -rf "$cfg" "$meta"' EXIT
  python3 -c 'import base64,json,os,sys
a=base64.b64encode((os.environ["DOCKER_USERNAME"]+":"+os.environ["DOCKER_PASSWORD"]).encode()).decode()
json.dump({"auths":{"https://index.docker.io/v1/":{"auth":a}}}, open(sys.argv[1],"w"))' "$cfg/config.json"
  chmod 600 "$cfg/config.json"
  # As this user, so the container can read the private config.
  docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e COSIGN_PRIVATE_KEY -e COSIGN_PASSWORD \
    -e DOCKER_CONFIG=/docker -v "$cfg:/docker:ro" "$COSIGN" \
    sign --yes --key env://COSIGN_PRIVATE_KEY "$ref"
  echo "ok    signed: cosign verify --key cosign.pub $ref"
  signed=yes
else
  echo "skip  COSIGN_PRIVATE_KEY isn't set: the image is NOT signed"
  signed=no
fi

summary "### Published $repo:$version"
summary ""
summary "- digest: \`$ref\`"
summary "- platforms: $PLATFORMS; SBOM and provenance attached; scanned (no fixable HIGH/CRITICAL)"
summary "- signed: $signed"
