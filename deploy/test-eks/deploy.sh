#!/usr/bin/env bash
# Build, push and deploy the proxy to the eks-htm-prod test namespace.
# Usage: deploy/test-eks/deploy.sh            (build + push + apply)
#        SKIP_BUILD=1 deploy/test-eks/deploy.sh   (re-apply config/manifests only)
set -euo pipefail
cd "$(dirname "$0")/../.."

# Pinned: a profile already set in the shell may point at another account.
export AWS_PROFILE=hclpoc AWS_REGION=us-west-2
ACCOUNT=443370673207
[ "$(aws sts get-caller-identity --query Account --output text)" = "$ACCOUNT" ] ||
  { echo "AWS profile $AWS_PROFILE is not account $ACCOUNT; run: aws sso login --profile $AWS_PROFILE" >&2; exit 1; }
CTX=arn:aws:eks:us-west-2:443370673207:cluster/eks-htm-prod
NS=neubird-proxy-test
REPO=443370673207.dkr.ecr.us-west-2.amazonaws.com/neubird-proxy
V=$(git rev-parse --short HEAD)$(git diff --quiet HEAD -- cmd internal go.mod go.sum Dockerfile || echo -dirty)

if [ -z "${SKIP_BUILD:-}" ]; then
  case "$V" in *-dirty) echo "refusing to push a dirty tree ($V); commit first" >&2; exit 1;; esac
  if aws ecr describe-images --repository-name neubird-proxy --image-ids imageTag="$V" >/dev/null 2>&1; then
    echo "tag $V already in ECR (tags are immutable); using it"
  else
    docker buildx build --platform linux/amd64 --build-arg VERSION="$V" -t "$REPO:$V" --load .
    aws ecr get-login-password | docker login --username AWS --password-stdin "${REPO%%/*}"
    docker push "$REPO:$V"
  fi
fi
DIGEST=$(aws ecr describe-images --repository-name neubird-proxy --image-ids imageTag="${V%-dirty}" \
  --query 'imageDetails[0].imageDigest' --output text)

k() { kubectl --context "$CTX" "$@"; }
k apply -f - <<<"$(sed -n '1,/^---$/p' deploy/test-eks/kubernetes.yaml | sed '$d')"   # namespace
k -n "$NS" create configmap neubird-proxy --from-file=config.yaml=deploy/test-eks/config.yaml \
  --dry-run=client -o yaml | k apply -f -
if ! k -n "$NS" get secret neubird-proxy >/dev/null 2>&1; then
  echo "Secret $NS/neubird-proxy is missing; create it first (see deploy/test-eks/README.md)" >&2
  exit 1
fi
sed "s|image: IMAGE .*|image: $REPO@$DIGEST|" deploy/test-eks/kubernetes.yaml | k apply -f -
# Config changes need a restart (no hot reload).
k -n "$NS" rollout restart deploy/neubird-proxy
k -n "$NS" rollout status deploy/neubird-proxy --timeout=120s
