# shellcheck shell=bash
# Sourced by install.sh and install-tunnel.sh: YAML through helm (the
# values-helper chart next to this file), so the installer needs only bash,
# kubectl and helm.
values_helper=$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/values-helper" >/dev/null && pwd -P)

# merge_values OUT FILE...: the values files merged in order, as Helm merges
# them (later wins; maps merge, lists are replaced), written to OUT. A key a
# later file sets to null is removed (for example hmac_key_env with label
# masking), as it would be from the chart's own defaults.
merge_values() {
  local out=$1 f args=(); shift
  for f in "$@"; do args+=(-f "$f"); done
  helm template values "$values_helper" "${args[@]}" --show-only templates/merged.yaml \
    | sed -E -e '1{/^---$/d;}' -e '/^# Source: /d' -e '/^[[:space:]]*[A-Za-z0-9_.-]+: null$/d' > "$out"
}

# Every field either template prints, empty until read_facts sets it (so
# set -u never trips on one).
# shellcheck disable=SC2034  # read by the scripts that source this
fact_mode='' fact_secret='' fact_relays='' fact_token_env='' fact_mask='' fact_hosts=''
# shellcheck disable=SC2034
fact_egress_proxy='' fact_network_policy='' fact_config_relays='' fact_config_identity='' fact_config_hosts=''

# read_facts TEMPLATE FILE...: sets fact_<field> for each field the template
# prints (values-facts: chart values; config-facts: a proxy's config.yaml).
read_facts() {
  local t=$1 f out line args=(); shift
  for f in "$@"; do args+=(-f "$f"); done
  out=$(helm template values "$values_helper" "${args[@]}" --show-only "templates/$t.yaml") || return 1
  while IFS= read -r line; do
    [[ $line =~ ^([a-z_]+):\ \"([A-Za-z0-9+/=]*)\"$ ]] || continue
    printf -v "fact_${BASH_REMATCH[1]}" '%s' "$(printf '%s' "${BASH_REMATCH[2]}" | base64 --decode)"
  done <<<"$out"
}

# json_str VALUE / json_list VALUE...: JSON (which Helm reads as YAML) for
# a values file written by hand.
json_str() {
  local s=$1
  case $s in *[[:cntrl:]]*) printf 'FAIL  a value has a control character: %q\n' "$s" >&2; exit 1 ;; esac
  s=${s//\\/\\\\}; s=${s//\"/\\\"}
  printf '"%s"' "$s"
}
json_list() {
  local x out=
  for x in "$@"; do out+=${out:+,}$(json_str "$x"); done
  printf '[%s]' "$out"
}
