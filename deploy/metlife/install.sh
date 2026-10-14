#!/usr/bin/env bash
# neubird-proxy installer. Builds the Helm values from values.yaml (next to
# this script), installs the chart with deploy/scripts/install-tunnel.sh
# (Secret, chart, enrollment, tunnels, tests, removing the spent join token),
# then re-checks the running proxy and prints its key fingerprint for NeuBird.
# Run it with --help for the options. The join token is read from its file and
# never printed or put on a command line.
set -euo pipefail

here=$(CDPATH='' cd -P -- "$(dirname -- "$0")" >/dev/null && pwd -P)
pkg=$(dirname -- "$(dirname -- "$here")")
orig=$(pwd -P)
chart=$here/../helm/neubird-proxy

# A package from NeuBird presets the relay, tenant, CA and join token in
# <tenant>.env next to deploy/; it's loaded below, so nothing is sourced by hand.
die() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
# Only a file whose name is the tenant it presets counts, so a stray local.env
# (say, in a checkout of the repo) is never loaded; two packages' files are an
# error rather than a silent pick, and a skipped file is named.
# A variable as the file sets it: sourced in a clean shell, so quoting works
# as it does when the file is loaded.
envvar() { env -i "$BASH" --noprofile --norc -c 'source "$1" >/dev/null 2>&1; printf "%s" "${!2:-}"' _ "$1" "$2"; }
envfile=
for f in "$pkg"/*.env; do
  [ -f "$f" ] || continue
  if [ "$(envvar "$f" TENANT)" != "$(basename -- "$f" .env)" ]; then
    printf 'warn  ignoring %s: it doesn'"'"'t preset TENANT=%s\n' "$f" "$(basename -- "$f" .env)" >&2
    continue
  fi
  [ -z "$envfile" ] || die "two package files next to deploy/: $envfile and $f (keep one)"
  envfile=$f
done
preset() { [ -n "$envfile" ] && envvar "$envfile" "$1"; }
bad() { printf '%s: %s\nRun %s --help for usage.\n' "$0" "$*" "$0" >&2; exit 2; }

usage() {
  cat <<EOF
Install NeuBird's proxy (neubird-proxy) in a Kubernetes cluster and confirm it
works. The proxy dials out to NeuBird's relay; nothing connects in.

Usage:
  $0 --kube-context <context> --namespace <namespace> [options]

Required:
  -c, --kube-context <context>   kubectl context of the cluster to install in
  -n, --namespace <namespace>    namespace to install in (created if missing)

Options:
      --hosts <list>             systems NeuBird may reach, comma-separated:
                                 host[:port], *.domain[:port] or an IP address;
                                 port 443 if omitted. Default: '*' (any host name
                                 the proxy can reach, never IP literals).
                                 ServiceNow hosts stay read-only (GET, HEAD)
      --egress-proxy <url>       outbound HTTP proxy for the tunnel and internet
                                 systems, e.g. http://proxy.metlife.com:3128
                                 (no TLS inspection)
      --egress-no-proxy <list>   hosts reached directly, not through
                                 --egress-proxy, e.g. splunk.metlife.com,.metlife.com
      --allow-cidrs <list>       turn on the NetworkPolicy: the ranges the proxy
                                 may reach besides DNS and the relay, as
                                 cidr:port,... e.g. 10.20.0.0/16:8089
      --egress-proxy-cidr <cidr> the egress proxy's address, e.g. 10.1.2.3/32
                                 (needed with --allow-cidrs and --egress-proxy)
      --upstream-ca <file>       CA bundle for systems with internal-CA certificates
      --image-repo <repo>        your registry's copy of the image (same digest)
      --mask <label|hmac>        how redacted values are masked (default: label,
                                 or the package's preset)
      --timeout <seconds>        how long to wait for the tunnels (default: 300)
      --join-token-file <file>   NeuBird's join token, for the first install
                                 (a package from NeuBird presets it)
      --relay-ca <file>          NeuBird's relay CA (default: relay-ca.crt;
                                 a package from NeuBird presets it)

Modes:
      --dry-run                  build and render the values, write them to
                                 ./neubird-proxy-values.yaml; install nothing
      --confirm-only             only re-check an existing install
      --uninstall                remove the proxy; its key and HMAC key are kept,
                                 so reinstalling needs no new join token
      --purge                    with --uninstall: also delete the key and HMAC
                                 key and print the key's fingerprint for NeuBird
                                 to revoke (asks first; --yes skips the question)
  -h, --help                     show this help
      --version                  show the chart version and this package's relay

Each option can also be set as an environment variable (--kube-context as
KUBE_CONTEXT, --dry-run as DRY_RUN=1, and so on); a command-line option wins.
A package's presets (its .env file) win over the environment. --uninstall,
--purge and --yes are taken only from the command line.

Examples:
  $0 -c prod-aks -n neubird --join-token-file join.token
  $0 -c prod-aks -n neubird --hosts splunk.metlife.com:8089,metlife.service-now.com
  $0 -c prod-aks -n neubird --dry-run
  $0 -c prod-aks -n neubird --uninstall

Requires kubectl, helm 3 or later and python3 with PyYAML.
EOF
  if [ -n "$envfile" ]; then
    printf '\nThis package: tenant %s, relay %s, mask %s\n' "$(preset TENANT)" "$(preset RELAY)" "$(preset MASK)"
  fi
}

version() {
  printf 'neubird-proxy chart %s (app %s)\n' \
    "$(sed -nE 's/^version: *//p' "$chart/Chart.yaml")" \
    "$(sed -nE 's/^appVersion: *"?([^"]*)"?.*/\1/p' "$chart/Chart.yaml")"
  if [ -n "$envfile" ]; then
    printf 'package: tenant %s, relay %s\n' "$(preset TENANT)" "$(preset RELAY)"
  fi
}

# Options: --name value or --name=value; each maps to its environment variable
# (--kube-context is KUBE_CONTEXT). Collected first and applied after the
# package's .env, so they override its presets.
# --uninstall, --purge and --yes only from the command line: a variable left
# in the shell must never turn an install into an uninstall or a purge.
unset UNINSTALL PURGE YES
takes_value=" KUBE_CONTEXT NAMESPACE HOSTS EGRESS_PROXY EGRESS_NO_PROXY ALLOW_CIDRS EGRESS_PROXY_CIDR UPSTREAM_CA IMAGE_REPO MASK TIMEOUT JOIN_TOKEN_FILE RELAY_CA "
switches=" DRY_RUN CONFIRM_ONLY UNINSTALL PURGE YES "
opts=()
from_env=
[ -z "${KUBE_CONTEXT:-}" ] || from_env+=" KUBE_CONTEXT"
[ -z "${NAMESPACE:-}" ] || from_env+=" NAMESPACE"
while [ $# -gt 0 ]; do
  arg=$1; shift
  case $arg in
    -h|--help) usage; exit 0 ;;
    --version) version; exit 0 ;;
    -c|--context) arg=--kube-context ;;
    --context=*) arg=--kube-context=${arg#--context=} ;;
    -n) arg=--namespace ;;
    --*) ;;
    *) bad "unexpected argument: $arg" ;;
  esac
  name=${arg#--} val= inline=
  case $name in *=*) val=${name#*=} name=${name%%=*} inline=1 ;; esac
  var=$(printf '%s' "$name" | tr 'a-z-' 'A-Z_')
  if [[ $switches == *" $var "* ]]; then
    [ -z "$inline" ] || bad "--$name takes no value"
    opts+=("$var=1")
  elif [[ $takes_value == *" $var "* ]]; then
    if [ -z "$inline" ]; then
      [ $# -gt 0 ] && [[ $1 != -* ]] || bad "--$name needs a value"
      val=$1; shift
    fi
    [ -n "$val" ] || bad "--$name needs a value"
    opts+=("$var=$val")
    from_env=${from_env// $var/}
  else
    bad "unknown option: --$name"
  fi
done
apply() {
  local kv
  for kv in ${opts[@]+"${opts[@]}"}; do printf -v "${kv%%=*}" '%s' "${kv#*=}"; export "${kv%%=*}"; done
}
apply
[ -n "${KUBE_CONTEXT:-}" ] || bad "--kube-context is required"
[ -n "${NAMESPACE:-}" ] || bad "--namespace is required"
[ -z "${DRY_RUN:-}" ] || [ -z "${CONFIRM_ONLY:-}" ] || bad "--dry-run and --confirm-only don't go together"
[ -z "${PURGE:-}" ] || [ -n "${UNINSTALL:-}" ] || bad "--purge goes with --uninstall"
[ -z "${YES:-}" ] || [ -n "${PURGE:-}" ] || bad "--yes goes with --uninstall --purge"
if [ -n "${UNINSTALL:-}" ]; then
  [ -z "${DRY_RUN:-}${CONFIRM_ONLY:-}" ] || bad "--uninstall doesn't go with --dry-run or --confirm-only"
  for kv in ${opts[@]+"${opts[@]}"}; do
    case ${kv%%=*} in
      KUBE_CONTEXT|NAMESPACE|UNINSTALL|PURGE|YES) ;;
      *) bad "--$(printf '%s' "${kv%%=*}" | tr 'A-Z_' 'a-z-') doesn't apply to --uninstall" ;;
    esac
  done
fi
case ${MASK:-label} in label|hmac) ;; *) bad "--mask must be label or hmac" ;; esac
case ${TIMEOUT:-300} in ''|*[!0-9]*) bad "--timeout must be a number of seconds" ;; esac
export KUBE_CONTEXT NAMESPACE
origin() { [[ $from_env == *" $1"* ]] && printf ' (from $%s in your environment)' "$1"; return 0; }
printf '== context %s%s, namespace %s%s\n' "$KUBE_CONTEXT" "$(origin KUBE_CONTEXT)" "$NAMESPACE" "$(origin NAMESPACE)"

# Files given by the caller are relative to where they ran this; the script
# works from the package directory, so make them absolute first.
for v in UPSTREAM_CA JOIN_TOKEN_FILE RELAY_CA; do
  p=${!v:-}
  if [ -n "$p" ] && [[ $p != /* ]]; then printf -v "$v" '%s' "$orig/$p"; fi
done
for i in ${opts[@]+"${!opts[@]}"}; do
  kv=${opts[$i]}
  case ${kv%%=*} in UPSTREAM_CA|JOIN_TOKEN_FILE|RELAY_CA) [[ ${kv#*=} == /* ]] || opts[$i]="${kv%%=*}=$orig/${kv#*=}" ;; esac
done

if [ -n "$envfile" ]; then
  # The package's presets replace the environment's values (an option still
  # wins): say so, rather than silently ignoring what the caller set.
  for v in $(sed -nE 's/^export ([A-Z_]+)=.*/\1/p' "$envfile"); do
    [ -n "${!v:-}" ] || continue
    printf '%s\n' ${opts[@]+"${opts[@]}"} | grep -q "^$v=" && continue
    pv=$(preset "$v")
    [ "${!v}" = "$pv" ] && continue
    # Paths: the environment's is already absolute (from where this was run),
    # the package's is relative to the package; the same file is no change.
    case $v in UPSTREAM_CA|JOIN_TOKEN_FILE|RELAY_CA)
      [[ $pv == /* ]] || pv=$pkg/$pv
      { [ "${!v}" = "$pv" ] || [ "${!v}" -ef "$pv" ]; } && continue ;;
    esac
    o=$(printf '%s' "$v" | tr 'A-Z_' 'a-z-')
    if [[ $takes_value == *" $v "* ]]; then
      printf 'note  $%s in your environment is replaced by the package'"'"'s %s (use --%s to change it)\n' "$v" "$(preset "$v")" "$o"
    else
      printf 'note  $%s in your environment is replaced by the package'"'"'s %s\n' "$v" "$(preset "$v")"
    fi
  done
  cd "$pkg"
  # shellcheck disable=SC1090
  source "$envfile"
  apply
fi

# What it needs, checked before anything is changed.
if [ -z "${CONFIRM_ONLY:-}${UNINSTALL:-}" ]; then
  [ -z "${UPSTREAM_CA:-}" ] || [ -f "$UPSTREAM_CA" ] || die "--upstream-ca $UPSTREAM_CA: no such file"
  [ -z "${JOIN_TOKEN_FILE:-}" ] || [ -f "$JOIN_TOKEN_FILE" ] || die "--join-token-file $JOIN_TOKEN_FILE: no such file"
fi
if [ -z "${UNINSTALL:-}" ]; then
  command -v python3 >/dev/null 2>&1 || die "python3 not found"
  python3 -c 'import yaml' 2>/dev/null || die "python3 can't import yaml: pip3 install PyYAML"
fi
[ -z "${PURGE:-}" ] || command -v openssl >/dev/null 2>&1 || die "openssl not found (--purge needs it for the key's fingerprint)"
command -v helm >/dev/null 2>&1 || die "helm not found: https://helm.sh/docs/intro/install/"
helm_v=$(helm version --short 2>/dev/null || true)
helm_major=${helm_v#v}; helm_major=${helm_major%%.*}
[[ $helm_major =~ ^[0-9]+$ ]] && [ "$helm_major" -ge 3 ] || die "helm 3 or later is required (found: ${helm_v:-unknown})"
if [ -z "${DRY_RUN:-}" ]; then
  command -v kubectl >/dev/null 2>&1 || die "kubectl not found"
  contexts=$(kubectl config get-contexts -o name 2>&1) || die "kubectl can't list its contexts: $contexts"
  if ! grep -qxF -- "$KUBE_CONTEXT" <<<"$contexts"; then
    printf 'FAIL  no kubectl context named %s%s\n      kubectl (KUBECONFIG=%s) has:\n' "$KUBE_CONTEXT" "$(origin KUBE_CONTEXT)" "${KUBECONFIG:-~/.kube/config}" >&2
    sed 's/^/        /' <<<"${contexts:-(none)}" >&2
    exit 1
  fi
fi

# Set by NeuBird before sending this script.
TENANT=${TENANT:-metlife}
RELAY=${RELAY:-metlife-tunnel.neubird.ai:443}
RELAY_IPS=${RELAY_IPS:-52.206.84.184,23.23.64.142}
# The proxy is named after the tenant (<tenant>/<tenant>); NeuBird issues the
# join token for that name.
PROXY_NAME=$TENANT

# --uninstall removes the Helm release. The chart keeps the key Secret (the
# proxy's identity at the relay; helm.sh/resource-policy: keep) and Helm never
# owned the env Secret (HMAC key, join token), so both stay unless --purge: a
# reinstall then needs no new join token and keeps the masking codes.
RELEASE=neubird-proxy
KEY_SECRET=$RELEASE-tunnel-key
ENV_SECRET=neubird-proxy-env
uninstall() {
  k() { kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" "$@"; }
  h() { helm --kube-context "$KUBE_CONTEXT" -n "$NAMESPACE" "$@"; }
  # Look everything up first. "Not found" is an answer; any other error (the
  # cluster unreachable, no permission) stops the script before anything is
  # changed, rather than being taken for "nothing installed".
  has_secret() {
    local out
    out=$(k get secret "$1" -o name 2>&1) && return 0
    grep -q 'NotFound' <<<"$out" && return 1
    die "can't look up Secret $1 in namespace $NAMESPACE: $out"
  }
  local out release= key= env= fp= b64 s answer w
  if out=$(h status "$RELEASE" 2>&1); then
    release=1
  elif ! grep -q 'release: not found' <<<"$out"; then
    die "can't look up release $RELEASE in namespace $NAMESPACE: $out"
  fi
  has_secret "$KEY_SECRET" && key=1
  has_secret "$ENV_SECRET" && env=1

  if [ -n "${PURGE:-}" ] && [ -n "$key" ]; then
    # The fingerprint NeuBird revokes: sha256 of the public key (DER
    # SubjectPublicKeyInfo), as the proxy prints it. The private key goes
    # from the Secret through a pipe, never to disk. Without the right
    # fingerprint the key can't be revoked, so a failure stops here, before
    # anything is deleted.
    # stderr is left out of $b64 (a warning from kubectl or an auth plugin
    # would corrupt the base64); it goes to the terminal instead.
    b64=$(k get secret "$KEY_SECRET" -o jsonpath='{.data.tunnel\.key}') \
      || die "can't read Secret $KEY_SECRET (kubectl's error above); nothing changed"
    [ -n "$b64" ] || die "Secret $KEY_SECRET has no tunnel.key; nothing changed"
    fp=$(printf '%s' "$b64" | base64 -d | openssl pkey -pubout -outform DER | openssl dgst -sha256 -r) \
      || die "can't work out the key's fingerprint from Secret $KEY_SECRET; nothing changed"
    fp=${fp%% *}
    # sha256 of nothing: openssl read no key.
    [[ $fp =~ ^[0-9a-f]{64}$ ]] && [ "$fp" != e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ] \
      || die "can't work out the key's fingerprint from Secret $KEY_SECRET; nothing changed"
    fp=sha256:$fp
  fi

  if [ -n "${PURGE:-}" ] && [ -z "${YES:-}" ] && [ -n "$release$key$env" ]; then
    [ -t 0 ] || die "--purge deletes the proxy's key: add --yes to confirm when not running interactively"
    printf '\n--purge deletes, for good, from namespace %s:\n' "$NAMESPACE"
    [ -z "$release" ] || printf '  the release %s\n' "$RELEASE"
    [ -z "$key" ] || printf '  the key of proxy %s/%s (%s)\n' "$TENANT" "$PROXY_NAME" "$fp"
    [ -z "$env" ] || printf '  Secret %s (the HMAC key)\n' "$ENV_SECRET"
    printf 'A reinstall then needs a new join token from NeuBird.\nType the namespace to confirm: '
    read -r answer || { echo; answer=; }
    [ "$answer" = "$NAMESPACE" ] || die "not confirmed; nothing changed"
  fi

  printf '\n== uninstall (namespace %s)\n' "$NAMESPACE"
  # Shown before anything is deleted, so a failure part way (or --yes, which
  # skips the prompt) never loses it: once the key Secret is gone, so is the key.
  # It is only a record here; revoking is asked for once the purge is done.
  [ -z "$fp" ] || printf 'key   %s/%s %s (still in place; revoke only after "Purged." below)\n' "$TENANT" "$PROXY_NAME" "$fp"
  # Until the key Secret is deleted, a failure leaves the key usable for a
  # reinstall: say so, so it isn't revoked by mistake.
  local kept=
  [ -z "${PURGE:-}" ] || [ -z "$key" ] || kept="; the key Secret $KEY_SECRET is untouched: don't revoke it, fix the error and rerun"
  if [ -n "$release" ]; then
    # --wait came in Helm 3.7; without it, helm returns while the pods stop.
    w=(); h uninstall --help 2>/dev/null | grep -- '--wait' >/dev/null && w=(--wait)
    out=$(h uninstall "$RELEASE" ${w[@]+"${w[@]}"} 2>&1) || die "helm uninstall $RELEASE: $out$kept"
    printf 'ok    release %s removed\n' "$RELEASE"
  else
    printf -- '--    no release %s in namespace %s\n' "$RELEASE" "$NAMESPACE"
  fi

  if [ -z "${PURGE:-}" ]; then
    [ -z "$env" ] || printf 'kept  Secret %s (the HMAC key)\n' "$ENV_SECRET"
    if [ -n "$key" ]; then
      printf 'kept  Secret %s (the proxy key)\n' "$KEY_SECRET"
      printf '\nThe key is kept: reinstalling (without --join-token-file) needs no new join token.\n'
      printf 'To remove the key and HMAC key too: %s -c %s -n %s --uninstall --purge\n' "$0" "$KUBE_CONTEXT" "$NAMESPACE"
    else
      printf 'warn  no Secret %s: there is no proxy key to keep, so a reinstall\n      makes a new key and needs a new join token from NeuBird\n' "$KEY_SECRET"
    fi
    return 0
  fi

  # The key Secret last: if a delete fails, the key is still there to retry with.
  for s in ${env:+"$ENV_SECRET"} ${key:+"$KEY_SECRET"}; do
    [ "$s" != "$KEY_SECRET" ] || kept="; Secret $KEY_SECRET may still exist: check it, then rerun before asking NeuBird to revoke"
    out=$(k delete secret "$s" 2>&1) || die "can't delete Secret $s: $out$kept"
    printf 'ok    Secret %s deleted\n' "$s"
  done
  if [ -n "$fp" ]; then
    printf '\nPurged. Ask NeuBird to revoke the key of %s/%s: %s\n' "$TENANT" "$PROXY_NAME" "$fp"
  else
    printf '\nPurged. There was no Secret %s, so the key'"'"'s fingerprint is unknown: ask\nNeuBird to revoke whatever key is enrolled for %s/%s.\n' "$KEY_SECRET" "$TENANT" "$PROXY_NAME"
  fi
  printf 'A reinstall needs a new join token. The namespace %s is left in place.\n' "$NAMESPACE"
}
if [ -n "${UNINSTALL:-}" ]; then uninstall; exit; fi

HOSTS=${HOSTS:-*}
RELAY_CA=${RELAY_CA:-relay-ca.crt}
[ -n "${CONFIRM_ONLY:-}" ] || [ -f "$RELAY_CA" ] || { echo "FAIL  $RELAY_CA: no such file (NeuBird's relay CA certificate)" >&2; exit 1; }
if [ -n "${EGRESS_PROXY:-}" ] && [ -n "${ALLOW_CIDRS:-}" ] && [ -z "${EGRESS_PROXY_CIDR:-}" ]; then
  echo "FAIL  with ALLOW_CIDRS (NetworkPolicy on) and EGRESS_PROXY, set EGRESS_PROXY_CIDR too" >&2; exit 1
fi

# confirm: re-check the installed proxy from what's actually running (its
# config, pods, tunnel and Secret) and print what to send NeuBird.
confirm() {
  k() { kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" "$@"; }
  local dep cfg relay ident want ready out fp tested r err fails=0
  dep=$(k get deploy -l app.kubernetes.io/instance=neubird-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  [ -n "$dep" ] || { echo "FAIL  no neubird-proxy Deployment in namespace $NAMESPACE" >&2; return 1; }
  # Every lookup below may come back empty on a broken install: none may stop
  # the script (set -e), so each failure is reported as a FAIL line instead.
  cfg=$(k get configmap -l app.kubernetes.io/instance=neubird-proxy -o jsonpath='{range .items[*]}{.data.config\.yaml}{end}' 2>/dev/null || true)
  read -r relay ident tested < <(python3 -c '
import sys,yaml
try:
    c=yaml.safe_load(sys.stdin) or {}; t=c["tunnel"]; h=(c.get("neubird_destinations") or {}).get("hosts") or []
    print(",".join(t["relays"]), t["tenant"]+"/"+t["proxy"], ",".join(x for x in h if "*" not in x) or "-")
except Exception:
    print("unknown unknown -")' <<<"$cfg") || true
  check() { if [ "$1" = ok ]; then printf '  ok    %s\n' "$2"; else printf '  FAIL  %s\n' "$2"; fails=$((fails + 1)); fi; }
  printf '\n== confirm (namespace %s)\n' "$NAMESPACE"
  want=$(k get "deploy/$dep" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)
  ready=$(k get "deploy/$dep" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)
  [ "${ready:-0}" -ge 1 ] 2>/dev/null && [ "${ready:-0}" = "$want" ] && r=ok || r=fail
  check "$r" "pods ready: ${ready:-0}/$want (a pod is ready only with a tunnel up)"
  out=$(k exec "deploy/$dep" -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml 2>&1 | grep -v 'Unknown stream id' || true)
  grep -qE '^[[:space:]]*ok[[:space:]]+relay' <<<"$out" && r=ok || r=fail
  check "$r" "tunnel to $relay: mutual TLS accepted by the relay"
  fp=$(grep -oE 'key sha256:[0-9a-f]{64}' <<<"$out" | head -1 | cut -d' ' -f2 || true)
  [ -n "$fp" ] && r=ok || r=fail
  check "$r" "identity $ident, key ${fp:-unknown}"
  if [ "$tested" != "-" ]; then
    # shellcheck disable=SC2046
    if k exec "deploy/$dep" -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml $(tr ',' '\n' <<<"$tested" | sed 's#^#https://#') >/dev/null 2>&1; then r=ok; else r=fail; fi
    check "$r" "systems reachable (DNS, TCP, TLS): $tested"
  else
    printf '  --    systems: only wildcard hosts, nothing to test; check one with\n        kubectl -n %s exec deploy/%s -- /neubird-proxy test -config /etc/neubird-proxy/config.yaml https://<host>\n' "$NAMESPACE" "$dep"
  fi
  # kubectl's stderr kept apart: a warning on a good lookup isn't a token.
  err=$(mktemp)
  if out=$(k get secret neubird-proxy-env -o jsonpath='{.data.NEUBIRD_JOIN_TOKEN}' 2>"$err"); then
    [ -z "$out" ] && r=ok || r=fail
    check "$r" "join token removed from the Secret"
  else
    check fail "join token removed from the Secret: can't read Secret neubird-proxy-env: $(tr '\n' ' ' < "$err")"
  fi
  rm -f "$err"
  if [ "$fails" -gt 0 ]; then
    printf '\n%d check(s) failed: kubectl -n %s logs -l app.kubernetes.io/instance=neubird-proxy --tail=50 --prefix\n' "$fails" "$NAMESPACE"
    return 1
  fi
  printf '\nConfirmed. Send NeuBird the key fingerprint above (it is not secret) so they can check it\nmatches the key their relay enrolled; then they set up the connections.\n'
}
if [ -n "${CONFIRM_ONLY:-}" ]; then confirm; exit; fi

values=$(mktemp "${TMPDIR:-/tmp}/neubird-proxy-values.XXXXXX")
trap 'rm -f "$values"' EXIT
TENANT=$TENANT RELAY=$RELAY RELAY_IPS=$RELAY_IPS HOSTS=$HOSTS \
EGRESS_PROXY=${EGRESS_PROXY:-} NO_PROXY_HOSTS=${EGRESS_NO_PROXY:-} \
EGRESS_PROXY_CIDR=${EGRESS_PROXY_CIDR:-} IMAGE_REPO=${IMAGE_REPO:-} \
PROXY_NAME=$PROXY_NAME MASK=${MASK:-label} ALLOW_CIDRS=${ALLOW_CIDRS:-} \
python3 - "$here/values.yaml" "$values" <<'PY'
import os, sys, yaml
src, out = sys.argv[1], sys.argv[2]
e = os.environ
def fail(msg): sys.exit("FAIL  " + msg)
v = yaml.safe_load(open(src))
if e["IMAGE_REPO"]:
    v["image"]["repository"] = e["IMAGE_REPO"]
v["tunnel"].update(relays=[e["RELAY"]], tenant=e["TENANT"], proxy=e["PROXY_NAME"])
d = v["config"]["neubird_destinations"]
hosts = [h.strip().lower() for h in e["HOSTS"].split(",") if h.strip()]
if not hosts:
    fail("HOSTS is empty")
d["hosts"] = hosts
# ServiceNow read-only: keep values.yaml's host_methods rule if a ServiceNow
# host (or '*', which includes them) is listed.
if not any(h.split(":")[0] == "*" or h.split(":")[0].endswith("service-now.com") for h in hosts):
    d.pop("host_methods", None)
if e["MASK"] not in ("label", "hmac"):
    fail("MASK must be label or hmac")
v["config"]["redaction"]["mask"] = e["MASK"]
if e["MASK"] == "hmac":
    v["config"]["redaction"]["hmac_key_env"] = "REDACTION_HMAC_KEY"
env = []
if e["EGRESS_PROXY"]:
    env.append({"name": "HTTPS_PROXY", "value": e["EGRESS_PROXY"]})
    if e["NO_PROXY_HOSTS"]:
        env.append({"name": "NO_PROXY", "value": e["NO_PROXY_HOSTS"]})
elif e["NO_PROXY_HOSTS"]:
    fail("EGRESS_NO_PROXY is only used with EGRESS_PROXY")
v["extraEnv"] = env
np = v.setdefault("networkPolicy", {})
np["relayCIDRs"] = [ip.strip() + "/32" for ip in e["RELAY_IPS"].split(",") if ip.strip()]
if e["ALLOW_CIDRS"]:
    np["enabled"] = True
    up = []
    for item in e["ALLOW_CIDRS"].split(","):
        item = item.strip()
        if not item:
            continue
        cidr, sep, port = item.rpartition(":")
        if not sep or "/" not in cidr or not port.isdigit():
            fail(f"ALLOW_CIDRS entry {item!r}: expected cidr:port, e.g. 10.20.0.0/16:8089")
        up.append({"cidr": cidr, "ports": [int(port)]})
    if e["EGRESS_PROXY"]:
        from urllib.parse import urlsplit
        up.append({"cidr": e["EGRESS_PROXY_CIDR"], "ports": [urlsplit(e["EGRESS_PROXY"]).port or 3128]})
    elif any(h.startswith("*") for h in hosts):
        print("warn  wildcard HOSTS with the NetworkPolicy on and no EGRESS_PROXY: only names resolving into ALLOW_CIDRS are reachable", file=sys.stderr)
    np["upstreams"] = up
else:
    np["enabled"] = False
yaml.safe_dump(v, open(out, "w"), sort_keys=False)
PY

printf '== values for tenant %s, proxy %s, relay %s\n' "$TENANT" "$PROXY_NAME" "$RELAY"
python3 -c "
import sys,yaml; v=yaml.safe_load(open(sys.argv[1])); d=v['config']['neubird_destinations']
print('   hosts:', ', '.join(d['hosts']))
print('   egress proxy:', next((x['value'] for x in v['extraEnv'] if x['name']=='HTTPS_PROXY'), 'none'))
print('   network policy:', 'on' if v['networkPolicy']['enabled'] else 'off', '| mask:', v['config']['redaction']['mask'])" "$values"

if [ -n "${DRY_RUN:-}" ]; then
  args=(-f "$values" --set-file "relayCA.cert=$RELAY_CA")
  [ -n "${UPSTREAM_CA:-}" ] && args+=(--set-file "upstreamCA.cert=$UPSTREAM_CA")
  helm template neubird-proxy "$chart" -n "$NAMESPACE" "${args[@]}" >/dev/null
  cp "$values" "$orig/neubird-proxy-values.yaml"
  echo "ok    renders; values written to $orig/neubird-proxy-values.yaml (dry run: nothing installed)"
  exit 0
fi

KUBE_CONTEXT=$KUBE_CONTEXT VALUES=$values RELAY_CA=$RELAY_CA \
  "$here/../scripts/install-tunnel.sh"
confirm
