#!/usr/bin/env bash
# Build the install package NeuBird sends a customer for a tenant: the proxy
# chart, deploy/metlife/install.sh and its guide, <tenant>.env with the relay
# preset, the relay CA, and a fresh join token for <tenant>/<tenant> that is
# recorded on the tenant's relay first. NeuBird-internal; it isn't shipped.
#
#   scripts/make-package.sh -t <tenant>
#
# The relay's details come from neubird-relay's
# deploy/production/customers/<tenant>/ (relay.env and ca/relay-ca.crt, written
# by its scripts/setup-relay.sh); options override them.
#
# Run with --help for the options. The join token is never printed: it goes to
# ~/.neubird-onboard/<tenant>/ (mode 600) and into the package.
set -euo pipefail

repo=$(CDPATH='' cd -P -- "$(dirname -- "$0")/.." >/dev/null && pwd -P)
orig=$(pwd -P)

die() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
bad() { printf '%s: %s\nRun %s --help for usage.\n' "$0" "$*" "$0" >&2; exit 2; }
step() { printf '\n== %s\n' "$*"; }
ok() { printf 'ok    %s\n' "$*"; }

usage() {
  cat <<EOF
Build a customer's neubird-proxy install package for a tenant, with a join
token for <tenant>/<tenant> recorded on the tenant's relay.

Usage:
  $0 -t <tenant> [options]

Required:
  -t, --tenant <tenant>          the tenant; the proxy is <tenant>/<tenant>

The relay's details default to neubird-relay's
deploy/production/customers/<tenant>/: relay.env (context, namespace, host)
and ca/relay-ca.crt, as its scripts/setup-relay.sh wrote them. For a relay
without that directory, give --relay-ca and --relay-context.

Options:
      --relay-ca <file>          the tenant's relay CA certificate (public); it
                                 must verify the live relay's certificate
      --relay-context <context>  kubectl context of the cluster running the
                                 tenant's relay (not needed with --no-record)
      --relay-namespace <ns>     the relay's namespace (default: the tenant)
      --relay <host:port>        default: <tenant>-tunnel.cluster.neubird.ai:443
      --relay-ips <list>         the relay's IP addresses, comma-separated
                                 (default: what the relay's host name resolves to)
      --mask <hmac|label>        the package's masking preset (default: hmac)
      --ttl <duration>           how long the join token is valid (default: 72h)
      --ref <git ref>            the commit of this repo to package
                                 (default: origin/main, fetched first)
      --relay-repo <dir>         a neubird-relay checkout, for its join-token
                                 command and tenants tools (default: ~/git/neubird-relay)
      --out <dir>                where the .tgz goes (default: ~/Downloads)
      --no-record                don't change the relay's records: print the
                                 record to add instead (the package won't work
                                 until it's added)
      --yes                      record on the relay without asking
  -h, --help                     show this help
EOF
}

TENANT= RELAY_CA= RELAY_CONTEXT= RELAY_NS= RELAY= RELAY_IPS= MASK=hmac TTL=72h
REF=origin/main RELAY_REPO=$HOME/git/neubird-relay OUT=$HOME/Downloads NO_RECORD= YES=
while [ $# -gt 0 ]; do
  arg=$1; shift
  case $arg in
    -h|--help) usage; exit 0 ;;
    --no-record) NO_RECORD=1; continue ;;
    --yes) YES=1; continue ;;
    --*=*) set -- "${arg#*=}" "$@"; arg=${arg%%=*} ;;
  esac
  [ $# -gt 0 ] && [ -n "$1" ] || bad "$arg needs a value"
  case $arg in
    -t|--tenant) TENANT=$1 ;;
    --relay-ca) RELAY_CA=$1 ;;
    --relay-context) RELAY_CONTEXT=$1 ;;
    --relay-namespace) RELAY_NS=$1 ;;
    --relay) RELAY=$1 ;;
    --relay-ips) RELAY_IPS=$1 ;;
    --mask) MASK=$1 ;;
    --ttl) TTL=$1 ;;
    --ref) REF=$1 ;;
    --relay-repo) RELAY_REPO=$1 ;;
    --out) OUT=$1 ;;
    *) bad "unknown option: $arg" ;;
  esac
  shift
done
[ -n "$TENANT" ] || bad "--tenant is required"
[[ $TENANT =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || bad "--tenant must be a DNS label (lower case letters, digits, '-')"
# Defaults from the relay's directory in neubird-relay, if it has one.
cust=$RELAY_REPO/deploy/production/customers/$TENANT
envv() { [ -f "$cust/relay.env" ] && sed -n "s/^$1=//p" "$cust/relay.env" | tail -1; }
if [ -f "$cust/relay.env" ]; then
  RELAY_CONTEXT=${RELAY_CONTEXT:-$(envv KUBE_CONTEXT)}
  RELAY_NS=${RELAY_NS:-$(envv NAMESPACE)}
  h=$(envv RELAY_HOST); [ -z "$h" ] || RELAY=${RELAY:-$h:443}
fi
[ -n "$RELAY_CA" ] || [ ! -f "$cust/ca/relay-ca.crt" ] || RELAY_CA=$cust/ca/relay-ca.crt
[ -n "$RELAY_CA" ] || bad "--relay-ca is required ($cust/ca/relay-ca.crt doesn't exist: set the relay up with neubird-relay's scripts/setup-relay.sh)"
[ -n "$NO_RECORD" ] || [ -n "$RELAY_CONTEXT" ] || bad "--relay-context is required (or --no-record): no $cust/relay.env"
case $MASK in hmac|label) ;; *) bad "--mask must be hmac or label" ;; esac
[[ $RELAY_CA == /* ]] || RELAY_CA=$orig/$RELAY_CA
[[ $OUT == /* ]] || OUT=$orig/$OUT
RELAY_NS=${RELAY_NS:-$TENANT}
RELAY=${RELAY:-$TENANT-tunnel.cluster.neubird.ai:443}
[[ $RELAY == *:* ]] || RELAY=$RELAY:443
host=${RELAY%:*} port=${RELAY##*:}
[[ $host =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || bad "relay host $host isn't a host name"
[[ $port =~ ^[0-9]{1,5}$ ]] || bad "relay port $port isn't a number"
PROXY=$TENANT
name=neubird-proxy-$TENANT
pkgfile=$OUT/$name-with-token.tgz
WORK=$HOME/.neubird-onboard/$TENANT

step "checks"
for c in git helm openssl python3 tar docker; do command -v "$c" >/dev/null 2>&1 || die "$c not found"; done
python3 -c 'import yaml' 2>/dev/null || die "python3 can't import yaml: pip3 install PyYAML"
command -v go >/dev/null 2>&1 || die "go not found (the relay's join-token command runs from $RELAY_REPO)"
[ -f "$RELAY_REPO/cmd/neubird-relay/jointoken.go" ] || die "--relay-repo $RELAY_REPO: not a neubird-relay checkout"
[ -f "$RELAY_REPO/scripts/onboard/tenants_edit.py" ] || die "$RELAY_REPO has no scripts/onboard/tenants_edit.py: update it to main"
[ -f "$RELAY_CA" ] || die "--relay-ca $RELAY_CA: no such file"
openssl x509 -in "$RELAY_CA" -noout 2>/dev/null || die "--relay-ca $RELAY_CA: not a PEM certificate"
[ -d "$OUT" ] || die "--out $OUT: no such directory"
[ ! -e "$pkgfile" ] || die "$pkgfile exists: move it away first"
relay() { (cd "$RELAY_REPO" && go run ./cmd/neubird-relay "$@"); }
k() { kubectl --context "$RELAY_CONTEXT" --request-timeout=30s -n "$RELAY_NS" "$@"; }
if [ -z "$NO_RECORD" ]; then
  command -v kubectl >/dev/null 2>&1 || die "kubectl not found"
  k get configmap neubird-relay-tenants -o name >/dev/null || die "no relay records (ConfigMap neubird-relay-tenants) in namespace $RELAY_NS of $RELAY_CONTEXT"
fi
ok "tools; tenant $TENANT, proxy $TENANT/$PROXY, relay $RELAY"

# The relay CA must be the one the live relay's certificate chains to: the
# proxy pins it and trusts nothing else.
out=$(openssl s_client -connect "$host:$port" -servername "$host" -CAfile "$RELAY_CA" -verify_return_error </dev/null 2>&1 || true)
grep -q 'Verify return code: 0 (ok)' <<<"$out" \
  || die "$RELAY_CA doesn't verify $RELAY's certificate: $(grep -m1 -E 'verify error|Verify return code|connect' <<<"$out" || echo "no TLS answer")"
ok "relay CA verifies $RELAY's certificate"
if [ -z "$RELAY_IPS" ]; then
  RELAY_IPS=$(python3 -c 'import socket,sys; print(",".join(sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1], 443, socket.AF_INET, socket.SOCK_STREAM)})))' "$host" 2>/dev/null || true)
  [ -n "$RELAY_IPS" ] || die "$host doesn't resolve: give --relay-ips"
fi
# One comma-separated list of IPv4 addresses, without spaces: it goes in the
# package's .env, which install.sh loads as shell.
RELAY_IPS=$(tr -d ' \t' <<<"$RELAY_IPS")
for ip in ${RELAY_IPS//,/ }; do
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "relay IP $ip isn't an IPv4 address (--relay-ips takes a comma-separated list)"
done
ok "relay IPs $RELAY_IPS"

step "package source ($REF)"
case $REF in origin/*) git -C "$repo" fetch -q origin ;; esac
sha=$(git -C "$repo" rev-parse --short "$REF^{commit}") || die "--ref $REF: no such commit"
ok "$(git -C "$repo" log -1 --format='%h %s' "$sha")"

step "the proxy image"
image=$(git -C "$repo" show "$sha:deploy/metlife/values.yaml" | python3 -c 'import sys,yaml; i=yaml.safe_load(sys.stdin)["image"]; print(i["repository"]+"@"+i["digest"])')
[[ $image == *@sha256:* ]] || die "deploy/metlife/values.yaml at $sha doesn't pin the image by digest: $image"
SYFT=anchore/syft:v1.52.0@sha256:500e2d872ac019436926e8322b4fc1f39441d94d21f6f4046c6ff29b30e8cb02
COSIGN=gcr.io/projectsigstore/cosign:v2.6.1@sha256:68839b7f13dac5a6744a5d8818e984dd39183374e37855c19e14d623d9bc9037
ok "$image"
# The signing key's public half, if this commit has one (cosign.pub at the
# repo root); images published by CI are signed with it.
cosign_pub=$(git -C "$repo" show "$sha:cosign.pub" 2>/dev/null || true)
signed=
if [ -n "$cosign_pub" ]; then
  kd=$(mktemp -d); printf '%s\n' "$cosign_pub" > "$kd/cosign.pub"; chmod 755 "$kd"; chmod 644 "$kd/cosign.pub"
  if docker run --rm -v "$kd:/k:ro" "$COSIGN" verify --key /k/cosign.pub "$image" >/dev/null 2>&1; then
    signed=1; ok "signed with cosign.pub"
  else
    printf 'warn  %s has no valid signature from cosign.pub (images from before signing are unsigned)\n' "$image"
  fi
  rm -rf "$kd"
else
  printf -- '--    no cosign.pub at %s: signatures not checked\n' "$sha"
fi

step "join token for $TENANT/$PROXY"
mkdir -p "$WORK" && chmod 700 "$WORK"
umask 077
stamp=$(date -u +%Y%m%dT%H%M%SZ)
for f in join.token record; do [ ! -e "$WORK/$f" ] || mv "$WORK/$f" "$WORK/$f.$stamp"; done
out=$(relay join-token -tenant "$TENANT" -proxy "$PROXY" -ttl "$TTL") || die "join-token: $out"
printf '%s' "$(grep -oE 'nbjt_[A-Za-z0-9_-]{43}' <<<"$out" | head -1)" > "$WORK/join.token"
grep -qE '^nbjt_[A-Za-z0-9_-]{43}$' "$WORK/join.token" || die "no join token in join-token's output"
rec=$(grep -oE 'hash: sha256:[0-9a-f]{64}, expires: [0-9TZ:-]+' <<<"$out" | head -1)
[ -n "$rec" ] || die "no hash in join-token's output"
printf '%s\n' "$rec" > "$WORK/record"
hash=$(sed -E 's/hash: ([^,]+),.*/\1/' <<<"$rec"); expires=$(sed -E 's/.*expires: //' <<<"$rec")
[ "$hash" = "sha256:$(tr -d '\n' < "$WORK/join.token" | openssl dgst -sha256 -r | cut -d' ' -f1)" ] || die "the recorded hash isn't the token's"
ok "made; expires $expires; in $WORK/join.token (never printed)"

step "build the package"
umask 022   # the package's files readable as usual; join.token stays 600
B=$(mktemp -d); trap 'rm -rf "$B"' EXIT
P=$B/$name; mkdir -p "$P"
git -C "$repo" archive "$sha" deploy/helm deploy/metlife deploy/scripts | tar -x -C "$P"
(cd "$P" && helm package deploy/helm/neubird-proxy >/dev/null)
chart_tgz=$(cd "$P" && ls neubird-proxy-*.tgz)
cp "$RELAY_CA" "$P/relay-ca.crt"; chmod 644 "$P/relay-ca.crt"
install -m 600 "$WORK/join.token" "$P/join.token"
# The image's SBOM (SPDX), for the customer's security review.
docker run --rm "$SYFT" "$image" -q -o spdx-json > "$P/neubird-proxy-image.spdx.json" \
  || die "couldn't make the image's SBOM (syft $image)"
[ -z "$cosign_pub" ] || printf '%s\n' "$cosign_pub" > "$P/cosign.pub"
until=$(python3 -c 'import sys,datetime; print(datetime.datetime.strptime(sys.argv[1], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M UTC"))' "$expires")
cat > "$P/$TENANT.env" <<EOF
# Loaded by deploy/metlife/install.sh; you don't need to source it.

# Preset by NeuBird for the $TENANT relay: don't change.
export TENANT='$TENANT'
export RELAY='$RELAY'
export RELAY_IPS='$RELAY_IPS'
export RELAY_CA=relay-ca.crt
# The proxy is $TENANT/$PROXY (named after the tenant); the join token is for it.

# The join token, included in this package (secret, single use).
export JOIN_TOKEN_FILE=join.token

EOF
if [ "$MASK" = hmac ]; then
  cat >> "$P/$TENANT.env" <<'EOF'
# Masking: each sensitive value becomes a keyed code (HMAC), so NeuBird can
# correlate values without seeing them. install.sh generates the key
# (REDACTION_HMAC_KEY in the Secret) on first install; keep it, never send it.
# --mask label overrides this.
export MASK=hmac
EOF
else
  cat >> "$P/$TENANT.env" <<'EOF'
# Masking: each sensitive value becomes a label, e.g. <email>. --mask hmac
# overrides this.
export MASK=label
EOF
fi
printf '\n# Everything else is an option of deploy/metlife/install.sh (see --help).\n' >> "$P/$TENANT.env"

# <tenant>-values.yaml, for a plain helm install: the values install.sh would
# build with the defaults (from a dry run of this package), with the relay CA
# inline and the chart's own env Secret (join token and hmac key) instead of
# one install.sh creates.
G=$B/gen; mkdir -p "$G"; cp -Rp "$P" "$G/"
out=$(cd "$G" && env -u KUBE_CONTEXT -u NAMESPACE -u MASK -u TENANT -u RELAY -u RELAY_IPS -u RELAY_CA -u JOIN_TOKEN_FILE -u HOSTS \
  "$G/$name/deploy/metlife/install.sh" -c values -n values --dry-run 2>&1) || die "couldn't build $TENANT-values.yaml (install.sh --dry-run): $out"
python3 - "$G/neubird-proxy-values.yaml" "$P/relay-ca.crt" "$P/$TENANT-values.yaml" "$TENANT" "$chart_tgz" "$sha" <<'PY'
import sys, yaml
src, ca, out, tenant, chart, sha = sys.argv[1:]
v = yaml.safe_load(open(src))
v.pop("env", None)                       # the chart's own Secret
v["relayCA"] = {"cert": open(ca).read()}
class D(yaml.SafeDumper): pass
D.add_representer(str, lambda d, s: d.represent_scalar("tag:yaml.org,2002:str", s, style="|" if "\n" in s else None))
head = f"""# neubird-proxy for {tenant}, from NeuBird (package {sha[:7]}). Install:
#
#   helm install neubird-proxy {chart} -n neubird --create-namespace \\
#     -f {tenant}-values.yaml --set-file joinToken=join.token --wait
#   helm test neubird-proxy -n neubird
#
# Preset by NeuBird, don't change: image, tunnel (relay, tenant, proxy) and
# relayCA. Yours to set: config.neubird_destinations.hosts (the systems
# NeuBird may reach; "*" is any host name), extraEnv (an outbound HTTP
# proxy: HTTPS_PROXY, NO_PROXY), networkPolicy, resources, replicaCount.
"""
open(out, "w").write(head + yaml.dump(v, Dumper=D, sort_keys=False, default_flow_style=False))
PY
chmod 644 "$P/$TENANT-values.yaml"
ips_text=$(sed 's/,/ and /g' <<<"$RELAY_IPS")
mask_text=label; [ "$MASK" = label ] || mask_text=HMAC
cat > "$P/README.md" <<EOF
# neubird-proxy for $TENANT

The proxy in tunnel mode for tenant \`$TENANT\`: it dials out to the
$TENANT relay (\`$RELAY\`,
$ips_text) and calls any host name it can reach, or only
the ones you list in \`HOSTS\`. No proxy token.

| File | What |
|---|---|
| \`$chart_tgz\` | The Helm chart, packaged (also unpacked under \`deploy/helm/\`) |
| \`$TENANT-values.yaml\` | The chart's values for $TENANT: relay, tenant, CA and image preset; hosts and egress yours to set |
| \`$TENANT.env\` | The relay, tenant and IPs, and $mask_text masking (preset); loaded by install.sh |
| \`join.token\` | The join token (secret, single use) |
| \`relay-ca.crt\` | The $TENANT relay CA (public) |
| \`neubird-proxy-image.spdx.json\` | The proxy image's SBOM (SPDX JSON): \`$image\` |$( [ -z "$cosign_pub" ] || printf '\n| `cosign.pub` | NeuBird'"'"'s image signing key (public), for the check below |')
| \`deploy/metlife/install.sh\` | The installer: builds the values, installs and confirms (\`--help\`) |
| \`deploy/scripts/install-tunnel.sh\` | Called by install.sh: Secret, install, enrollment, tests |
| \`deploy/scripts/values.sh\`, \`values-helper/\` | Used by both: YAML through helm (a chart that's never installed) |

**This package includes a secret:** \`join.token\`, a single-use join token for
\`$TENANT/$PROXY\`, valid until $until.
\`$TENANT.env\` points \`JOIN_TOKEN_FILE\` at it. Don't share this package.

## Install with helm

\`\`\`sh
tar xzf $name-with-token.tgz && cd $name
helm install neubird-proxy $chart_tgz -n neubird --create-namespace \\
  -f $TENANT-values.yaml --set-file joinToken=join.token --wait
helm test neubird-proxy -n neubird
\`\`\`

First edit \`config.neubird_destinations.hosts\` in \`$TENANT-values.yaml\` if
NeuBird should reach only some systems (default \`*\`: any host name). \`--wait\`
returns once the proxy has enrolled its key and its tunnels are up (a pod is
ready only with a tunnel up); \`helm test\` checks the tunnel and each listed host
from inside the cluster (if it says "not in the tenant records" within a minute
of NeuBird making this package, the relay hasn't loaded the token yet: run it
again). The join token is spent after that: your next
\`helm upgrade ... -f $TENANT-values.yaml\` (without \`--set-file joinToken\`) drops it.
\`helm uninstall\` keeps the proxy's key and HMAC key (two Secrets), so a
reinstall needs no new token.

## Or the guided installer

\`\`\`sh
$name/deploy/metlife/install.sh
\`\`\`

It installs in your current kubectl context (it shows the context and asks
first) and namespace \`neubird\`. To choose: \`--kube-context <context>\` and
\`--namespace <namespace>\` (a script must give \`--kube-context\`).

Common options (all of them: \`install.sh --help\`):

| Option | What |
|---|---|
| \`--hosts <host[:port]>,...\` | Limit what the proxy may call (default \`*\`, any host name) |
| \`--egress-proxy <url>\` | Outbound HTTP proxy for the tunnel |
| \`--dry-run\` | Build and render the values, install nothing |
| \`--confirm-only\` | Re-check an existing install |
| \`--uninstall\` | Remove the proxy; keeps its key and HMAC key, so a reinstall needs no new token |
| \`--uninstall --purge\` | Also delete both keys (asks first) and print the key's fingerprint for NeuBird to revoke |

The script waits for enrollment and the tunnels, tests the tunnel and each listed host,
removes the spent join token from the Secret, then confirms the running proxy and
prints its key fingerprint.

Requires kubectl and helm 3 or later; nothing else (no Python).
EOF
if [ -n "$signed" ]; then
  cat >> "$P/README.md" <<EOF

## Checking the image (optional)

The image is signed by NeuBird. To check it, or a copy in your registry:

\`\`\`sh
cosign verify --key $name/cosign.pub $image
\`\`\`
EOF
fi
ok "assembled from $sha"

# Checked before the token is recorded: a package that doesn't work leaves
# the relay unchanged.
step "check the package"
T=$B/check; mkdir -p "$T"
cp -Rp "$P" "$T/"
out=$(cd "$T" && env -u KUBE_CONTEXT -u NAMESPACE -u MASK -u TENANT -u RELAY -u RELAY_IPS -u RELAY_CA -u JOIN_TOKEN_FILE \
  "$T/$name/deploy/metlife/install.sh" -c check -n check --dry-run 2>&1) || die "the package's dry run failed: $out"
grep -q "values for tenant $TENANT, proxy $PROXY, relay $RELAY" <<<"$out" || die "the package's dry run didn't pick up its presets: $out"
grep -q "mask: $MASK" <<<"$out" || die "the package's dry run has the wrong mask: $out"
ok "a dry run from the package builds $TENANT's values (mask: $MASK)"
out=$(helm template neubird-proxy "$T/$name/$chart_tgz" -n neubird -f "$T/$name/$TENANT-values.yaml" --set-file joinToken="$T/$name/join.token" 2>&1) \
  || die "the package's helm install wouldn't render: $out"
grep -q 'name: neubird-proxy-env' <<<"$out" && grep -q "NEUBIRD_JOIN_TOKEN:" <<<"$out" \
  || die "the helm install's env Secret has no join token"
ok "helm install from the package renders, with the join token in the chart's Secret"

step "record it on the relay"
umask 077
if [ -n "$NO_RECORD" ]; then
  printf 'skip  --no-record. Add to %s'"'"'s records, under proxies:, before the customer installs:\n\n' "$TENANT"
  printf '      - name: %s\n        expected_tunnels: 0\n        keys: []\n        join_tokens:\n          - {hash: %s, expires: %s}\n' "$PROXY" "$hash" "$expires"
else
  k get configmap neubird-relay-tenants -o yaml > "$WORK/tenants-cm.backup.$stamp.yaml"
  k get configmap neubird-relay-tenants -o jsonpath='{.data.tenants\.yaml}' > "$WORK/tenants.yaml.orig"
  cp "$WORK/tenants.yaml.orig" "$WORK/tenants.yaml"
  python3 "$RELAY_REPO/scripts/onboard/tenants_edit.py" "$WORK/tenants.yaml" "$PROXY" add-proxy
  python3 "$RELAY_REPO/scripts/onboard/tenants_edit.py" "$WORK/tenants.yaml" "$PROXY" add-join-token "$hash" "$expires"
  out=$(relay tenants check -f "$WORK/tenants.yaml" -tenant "$TENANT" 2>&1) || die "the new records don't check: $out"
  # The new proxy record must be under this tenant, with this token.
  python3 - "$WORK/tenants.yaml" "$TENANT" "$PROXY" "$hash" <<'PY' || die "the edit didn't record the token under $TENANT/$PROXY"
import sys, yaml
f, tenant, proxy, h = sys.argv[1:]
t = [t for t in yaml.safe_load(open(f))["tenants"] if t["name"] == tenant]
p = [p for p in (t[0].get("proxies") or []) if p["name"] == proxy] if t else []
sys.exit(0 if p and any(j["hash"].lower() == h for j in p[0].get("join_tokens") or []) else 1)
PY
  printf 'The change to %s'"'"'s records (namespace %s, %s):\n' "$TENANT" "$RELAY_NS" "$RELAY_CONTEXT"
  diff "$WORK/tenants.yaml.orig" "$WORK/tenants.yaml" | sed 's/^/      /' || true
  if [ -z "$YES" ]; then
    [ -t 0 ] || die "not recording without a terminal: add --yes, or --no-record"
    printf 'Record it on the live relay? Type the tenant to confirm: '
    read -r answer || answer=
    [ "$answer" = "$TENANT" ] || die "not confirmed: the relay is unchanged; the token in $WORK/join.token isn't recorded"
  fi
  # Nobody else changed the records since they were read.
  diff -q <(k get configmap neubird-relay-tenants -o jsonpath='{.data.tenants\.yaml}') "$WORK/tenants.yaml.orig" >/dev/null \
    || die "the relay's records changed while this ran: run it again"
  python3 -c 'import json,sys; json.dump({"data":{"tenants.yaml":open(sys.argv[1]).read()}}, open(sys.argv[2],"w"))' "$WORK/tenants.yaml" "$WORK/patch.json"
  k patch configmap neubird-relay-tenants --type merge --patch-file "$WORK/patch.json" >/dev/null
  diff -q <(k get configmap neubird-relay-tenants -o jsonpath='{.data.tenants\.yaml}') "$WORK/tenants.yaml" >/dev/null \
    || die "the relay's records don't read back as written"
  ok "recorded (the relay loads it within about a minute); backup $WORK/tenants-cm.backup.$stamp.yaml"
  # Keep the relay's directory in git in step with the live records, so
  # applying it (setup-relay.sh) doesn't drop this token.
  if [ -f "$cust/tenants.yaml" ]; then
    if [ "$(cat "$cust/tenants.yaml")" != "$(cat "$WORK/tenants.yaml.orig")" ]; then
      printf 'note  %s differed from the live records before this token (not committed, or the relay was\n      changed directly); it now holds the live records: check its diff before committing\n' "${cust#"$RELAY_REPO"/}/tenants.yaml"
    fi
    cp "$WORK/tenants.yaml" "$cust/tenants.yaml"
    ok "updated ${cust#"$RELAY_REPO"/}/tenants.yaml in $RELAY_REPO: commit it"
  fi
fi

step "write the package"
# No macOS metadata files (._*) in the package.
tarflags=(); tar --version 2>/dev/null | grep -q bsdtar && tarflags=(--no-mac-metadata)
(cd "$B" && COPYFILE_DISABLE=1 tar ${tarflags[@]+"${tarflags[@]}"} -czf "$pkgfile" "$name")
chmod 600 "$pkgfile"
cmp -s <(tar -xzOf "$pkgfile" "$name/join.token") "$WORK/join.token" || die "$pkgfile doesn't hold the token"
ok "$pkgfile ($(tar -tzf "$pkgfile" | wc -l | tr -d ' ') entries, from $sha)"

printf '\nDone: %s\n' "$pkgfile"
printf 'It holds the join token (single use, until %s): send it to whoever installs, over a secure channel.\n' "$until"
[ -z "$NO_RECORD" ] || printf 'The token is NOT recorded on the relay yet (--no-record): add the record above first.\n'
