# shellcheck shell=bash
# Sourced by install.sh and install-tunnel.sh: YAML through helm (the
# values-helper chart next to this file), so the installer needs only bash,
# kubectl and helm.
values_helper=$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/values-helper" >/dev/null && pwd -P)

# merge_values OUT FILE...: the values files merged in order, as Helm merges
# them (later wins; maps merge, lists are replaced), written to OUT. A later
# file's null stays null; the caller removes the keys it meant to drop.
merge_values() {
  local out=$1 f args=(); shift
  for f in "$@"; do args+=(-f "$f"); done
  helm template values "$values_helper" "${args[@]}" --show-only templates/merged.yaml > "$out.tmp" || { rm -f "$out.tmp"; return 1; }
  sed -e '1{/^---$/d;}' -e '/^# Source: /d' "$out.tmp" > "$out"; rm -f "$out.tmp"
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
  local n=0 field val
  out=$(helm template values "$values_helper" "${args[@]}" --show-only "templates/$t.yaml") || return 1
  while IFS= read -r line; do
    [[ $line =~ ^([a-z_]+):\ \"([A-Za-z0-9+/=]*)\"$ ]] || continue
    field=${BASH_REMATCH[1]} val=${BASH_REMATCH[2]}
    # base64 -d: GNU, BusyBox and macOS all take it (--decode isn't BusyBox's).
    if [ -n "$val" ]; then val=$(printf '%s' "$val" | base64 -d) || { printf 'FAIL  base64 -d failed on field %s\n' "$field" >&2; return 1; }; fi
    printf -v "fact_$field" '%s' "$val"; n=$((n + 1))
  done <<<"$out"
  # Every template prints at least three fields: none read means the
  # helper's output wasn't understood, which mustn't pass as empty values.
  [ "$n" -ge 3 ] || { printf 'FAIL  read %d field(s) from values-helper %s\n' "$n" "$t" >&2; return 1; }
}

# json_str VALUE / json_list VALUE...: JSON (which Helm reads as YAML) for
# a values file written by hand.
# Values must not hold control characters (the caller checks; a check here
# would run in the $(...) subshell and couldn't stop the script).
json_str() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}
  printf '"%s"' "$s"
}
json_list() {
  local x out=
  for x in "$@"; do out+=${out:+,}$(json_str "$x"); done
  printf '[%s]' "$out"
}
