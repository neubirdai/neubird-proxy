#!/usr/bin/env bash
# Install neubird-proxy at MetLife from a few parameters: builds the Helm
# values from values.yaml (next to this script), then runs
# deploy/scripts/install-tunnel.sh, which creates the Secret, installs the
# chart, waits for enrollment and the tunnels, tests each system and removes
# the spent join token.
#
#   KUBE_CONTEXT=<ctx> NAMESPACE=neubird PROXY_NAME=aks-prod \
#   SPLUNK_HOST=splunk.metlife.com SERVICENOW_INSTANCE=metlife \
#   JOIN_TOKEN_FILE=join.token deploy/metlife/install.sh
#
# MetLife sets:
#   KUBE_CONTEXT         kubectl context of the AKS cluster (required)
#   NAMESPACE            namespace to install in (required)
#   PROXY_NAME           the name the join token is for (required)
#   SPLUNK_HOST          Splunk's host[:port], port 8089 if omitted (required)
#   JOIN_TOKEN_FILE      file holding NeuBird's join token (first install only)
#   SERVICENOW_INSTANCE  <instance> of <instance>.service-now.com (optional)
#   RELAY_CA             NeuBird's relay CA certificate (default: relay-ca.crt)
#   UPSTREAM_CA          CA bundle if Splunk's certificate is from an internal CA
#   EGRESS_PROXY         forwarding proxy for the tunnel and ServiceNow,
#                        e.g. http://proxy.metlife.com:3128 (no TLS inspection)
#   IMAGE_REPO           your registry's copy of the image (same digest)
#   MASK                 label or hmac (default: label)
#   SPLUNK_CIDR          Splunk's range: turns on the NetworkPolicy (with
#                        ServiceNow it needs EGRESS_PROXY; with EGRESS_PROXY,
#                        EGRESS_PROXY_CIDR)
#   EGRESS_PROXY_CIDR    the egress proxy's address, e.g. 10.1.2.3/32
#   DRY_RUN=1            write the values and render them; install nothing
#
# The token is read from its file and never printed or put on a command line.
set -euo pipefail

# Set by NeuBird before sending this script.
TENANT=${TENANT:-metlife}
RELAY=${RELAY:-metlife-tunnel.neubird.ai:443}
RELAY_IPS=${RELAY_IPS:-52.206.84.184,23.23.64.142}

: "${KUBE_CONTEXT:?set KUBE_CONTEXT}" "${NAMESPACE:?set NAMESPACE}" "${PROXY_NAME:?set PROXY_NAME}" "${SPLUNK_HOST:?set SPLUNK_HOST}"
here=$(CDPATH='' cd -P -- "$(dirname -- "$0")" >/dev/null && pwd -P)
RELAY_CA=${RELAY_CA:-relay-ca.crt}
[ -f "$RELAY_CA" ] || { echo "FAIL  $RELAY_CA: no such file (NeuBird's relay CA certificate)" >&2; exit 1; }
case "$SPLUNK_HOST" in *:*) ;; *) SPLUNK_HOST="$SPLUNK_HOST:8089" ;; esac
if [ -n "${EGRESS_PROXY:-}" ] && [ -n "${SPLUNK_CIDR:-}" ] && [ -z "${EGRESS_PROXY_CIDR:-}" ]; then
  echo "FAIL  with SPLUNK_CIDR (NetworkPolicy on) and EGRESS_PROXY, set EGRESS_PROXY_CIDR too" >&2; exit 1
fi
# ServiceNow is SaaS without fixed addresses, so the NetworkPolicy can allow it
# only through an egress proxy.
if [ -n "${SERVICENOW_INSTANCE:-}" ] && [ -n "${SPLUNK_CIDR:-}" ] && [ -z "${EGRESS_PROXY:-}" ]; then
  echo "FAIL  with SPLUNK_CIDR (NetworkPolicy on) and SERVICENOW_INSTANCE, set EGRESS_PROXY and EGRESS_PROXY_CIDR: the policy can't allow ServiceNow by address" >&2; exit 1
fi

values=$(mktemp "${TMPDIR:-/tmp}/neubird-proxy-values.XXXXXX")
trap 'rm -f "$values"' EXIT
TENANT=$TENANT RELAY=$RELAY RELAY_IPS=$RELAY_IPS SPLUNK_HOST=$SPLUNK_HOST \
SERVICENOW_INSTANCE=${SERVICENOW_INSTANCE:-} EGRESS_PROXY=${EGRESS_PROXY:-} \
EGRESS_PROXY_CIDR=${EGRESS_PROXY_CIDR:-} IMAGE_REPO=${IMAGE_REPO:-} \
PROXY_NAME=$PROXY_NAME MASK=${MASK:-label} SPLUNK_CIDR=${SPLUNK_CIDR:-} \
python3 - "$here/values.yaml" "$values" <<'PY'
import os, sys, yaml
src, out = sys.argv[1], sys.argv[2]
e = os.environ
v = yaml.safe_load(open(src))
if e["IMAGE_REPO"]:
    v["image"]["repository"] = e["IMAGE_REPO"]
v["tunnel"].update(relays=[e["RELAY"]], tenant=e["TENANT"], proxy=e["PROXY_NAME"])
d = v["config"]["neubird_destinations"]
splunk = e["SPLUNK_HOST"]
d["hosts"] = [splunk]
if e["SERVICENOW_INSTANCE"]:
    d["hosts"].append(e["SERVICENOW_INSTANCE"] + ".service-now.com")
else:
    d.pop("host_methods", None)
if e["MASK"] not in ("label", "hmac"):
    sys.exit("FAIL  MASK must be label or hmac")
v["config"]["redaction"]["mask"] = e["MASK"]
if e["MASK"] == "hmac":
    v["config"]["redaction"]["hmac_key_env"] = "REDACTION_HMAC_KEY"
env = []
if e["EGRESS_PROXY"]:
    # The tunnel and ServiceNow go through the egress proxy; Splunk stays direct.
    env = [{"name": "HTTPS_PROXY", "value": e["EGRESS_PROXY"]},
           {"name": "NO_PROXY", "value": splunk.rsplit(":", 1)[0]}]
v["extraEnv"] = env
np = v.setdefault("networkPolicy", {})
np["relayCIDRs"] = [ip.strip() + "/32" for ip in e["RELAY_IPS"].split(",") if ip.strip()]
if e["SPLUNK_CIDR"]:
    np["enabled"] = True
    up = [{"cidr": e["SPLUNK_CIDR"], "ports": [int(splunk.rsplit(":", 1)[1])]}]
    if e["EGRESS_PROXY"]:
        from urllib.parse import urlsplit
        up.append({"cidr": e["EGRESS_PROXY_CIDR"], "ports": [urlsplit(e["EGRESS_PROXY"]).port or 3128]})
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
