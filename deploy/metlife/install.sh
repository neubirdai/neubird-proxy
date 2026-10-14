#!/usr/bin/env bash
# Install neubird-proxy at MetLife from a few parameters and confirm it: builds
# the Helm values from values.yaml (next to this script), runs
# deploy/scripts/install-tunnel.sh (Secret, chart, enrollment, tunnels, tests,
# removing the spent join token), then re-checks the running proxy and prints
# its key fingerprint for NeuBird.
#
#   KUBE_CONTEXT=<ctx> NAMESPACE=neubird \
#   HOSTS='splunk.metlife.com:8089,metlife.service-now.com' \
#   JOIN_TOKEN_FILE=join.token deploy/metlife/install.sh
#
# MetLife sets:
#   KUBE_CONTEXT         kubectl context of the AKS cluster (required)
#   NAMESPACE            namespace to install in (required)
#   HOSTS                the systems NeuBird may reach, comma-separated:
#                        host[:port], *.domain[:port] (any name under it) or
#                        an IP address; port 443 if omitted. Default: '*'
#                        (any host name the proxy can reach; never IP
#                        literals). ServiceNow hosts stay read-only (GET, HEAD)
#   JOIN_TOKEN_FILE      file holding NeuBird's join token (first install only)
#   RELAY_CA             NeuBird's relay CA certificate (default: relay-ca.crt)
#   UPSTREAM_CA          CA bundle for systems with internal-CA certificates
#   EGRESS_PROXY         forwarding proxy for the tunnel and internet systems
#                        (set in the pod as HTTPS_PROXY),
#                        e.g. http://proxy.metlife.com:3128 (no TLS inspection)
#   EGRESS_NO_PROXY      hosts reached directly, not through EGRESS_PROXY (set
#                        in the pod as NO_PROXY; your shell's NO_PROXY is ignored),
#                        e.g. splunk.metlife.com,.metlife.com
#   ALLOW_CIDRS          turns on the NetworkPolicy: the ranges the proxy may
#                        reach besides DNS and the relay, as cidr:port,...
#                        e.g. 10.20.0.0/16:8089 (with EGRESS_PROXY, also
#                        set EGRESS_PROXY_CIDR)
#   EGRESS_PROXY_CIDR    the egress proxy's address, e.g. 10.1.2.3/32
#   IMAGE_REPO           your registry's copy of the image (same digest)
#   MASK                 label or hmac (default: label)
#   DRY_RUN=1            write the values and render them; install nothing
#   CONFIRM_ONLY=1       only re-run the confirmation on an existing install
#
# The token is read from its file and never printed or put on a command line.
set -euo pipefail

# Set by NeuBird before sending this script.
TENANT=${TENANT:-metlife}
RELAY=${RELAY:-metlife-tunnel.neubird.ai:443}
RELAY_IPS=${RELAY_IPS:-52.206.84.184,23.23.64.142}
# The proxy is named after the tenant (<tenant>/<tenant>); NeuBird issues the
# join token for that name.
PROXY_NAME=$TENANT

: "${KUBE_CONTEXT:?set KUBE_CONTEXT}" "${NAMESPACE:?set NAMESPACE}"
HOSTS=${HOSTS:-*}
here=$(CDPATH='' cd -P -- "$(dirname -- "$0")" >/dev/null && pwd -P)
RELAY_CA=${RELAY_CA:-relay-ca.crt}
[ -n "${CONFIRM_ONLY:-}" ] || [ -f "$RELAY_CA" ] || { echo "FAIL  $RELAY_CA: no such file (NeuBird's relay CA certificate)" >&2; exit 1; }
if [ -n "${EGRESS_PROXY:-}" ] && [ -n "${ALLOW_CIDRS:-}" ] && [ -z "${EGRESS_PROXY_CIDR:-}" ]; then
  echo "FAIL  with ALLOW_CIDRS (NetworkPolicy on) and EGRESS_PROXY, set EGRESS_PROXY_CIDR too" >&2; exit 1
fi

# confirm: re-check the installed proxy from what's actually running (its
# config, pods, tunnel and Secret) and print what to send NeuBird.
confirm() {
  k() { kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" "$@"; }
  local dep cfg relay ident want ready out fp tested r fails=0
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
  [ -z "$(k get secret neubird-proxy-env -o jsonpath='{.data.NEUBIRD_JOIN_TOKEN}' 2>/dev/null || true)" ] && r=ok || r=fail
  check "$r" "join token removed from the Secret"
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
  helm template neubird-proxy "$here/../helm/neubird-proxy" -n "$NAMESPACE" "${args[@]}" >/dev/null
  cp "$values" ./neubird-proxy-values.yaml
  echo "ok    renders; values written to ./neubird-proxy-values.yaml (DRY_RUN: nothing installed)"
  exit 0
fi

KUBE_CONTEXT=$KUBE_CONTEXT VALUES=$values RELAY_CA=$RELAY_CA \
  "$here/../scripts/install-tunnel.sh"
confirm
