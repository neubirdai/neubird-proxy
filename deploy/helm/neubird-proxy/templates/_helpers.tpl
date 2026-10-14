{{- define "neubird-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "neubird-proxy.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if contains (include "neubird-proxy.name" .) .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "neubird-proxy.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "neubird-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "neubird-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "neubird-proxy.labels" -}}
{{ include "neubird-proxy.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "neubird-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "neubird-proxy.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "neubird-proxy.image" -}}
{{- $i := .Values.image -}}
{{- if not $i.repository -}}{{- fail "image.repository is required: the registry you loaded the neubird-proxy image into" -}}{{- end -}}
{{- if $i.digest -}}
{{- printf "%s@%s" $i.repository $i.digest -}}
{{- else if $i.tag -}}
{{- printf "%s:%s" $i.repository $i.tag -}}
{{- else -}}
{{- fail "image.digest (preferred) or image.tag is required" -}}
{{- end -}}
{{- end -}}

{{- define "neubird-proxy.keySecret" -}}
{{- if .Values.tunnelKey.existingSecret -}}
{{- .Values.tunnelKey.existingSecret -}}
{{- else if .Values.tunnelKey.generate -}}
{{- printf "%s-tunnel-key" (include "neubird-proxy.fullname" .) -}}
{{- else -}}
{{- fail "tunnelKey.existingSecret, or tunnelKey.generate: true, is required" -}}
{{- end -}}
{{- end -}}

{{- define "neubird-proxy.caConfigMap" -}}
{{- if .Values.relayCA.existingConfigMap -}}
{{- .Values.relayCA.existingConfigMap -}}
{{- else if .Values.relayCA.cert -}}
{{- printf "%s-relay-ca" (include "neubird-proxy.fullname" .) -}}
{{- else -}}
{{- fail "relayCA.cert or relayCA.existingConfigMap is required: the relay CA certificate NeuBird sent you" -}}
{{- end -}}
{{- end -}}

{{- define "neubird-proxy.upstreamCAConfigMap" -}}
{{- default (printf "%s-upstream-ca" (include "neubird-proxy.fullname" .)) .Values.upstreamCA.existingConfigMap -}}
{{- end -}}

{{/* "tunnel" or "inbound"; fails on anything else. */}}
{{- define "neubird-proxy.mode" -}}
{{- $m := .Values.mode | default "tunnel" -}}
{{- if not (has $m (list "tunnel" "inbound")) -}}{{- fail (printf "mode: %q is not tunnel or inbound" $m) -}}{{- end -}}
{{- $m -}}
{{- end -}}

{{- define "neubird-proxy.inbound" -}}
{{- if eq (include "neubird-proxy.mode" .) "inbound" -}}true{{- end -}}
{{- end -}}

{{/* "true" when NeuBird's requests take no proxy token
(neubird_destinations.client_auth: none, mode tunnel only). */}}
{{/* "true" when a neubird_destinations map says nothing about a proxy token
(no client_auth, client_token_env or client_auth_header): mode tunnel then
defaults it to client_auth: none. */}}
{{- define "neubird-proxy.tokenUnset" -}}
{{- if and (kindIs "map" .) (not (get . "client_auth")) (not (get . "client_token_env")) (not (get . "client_auth_header")) -}}true{{- end -}}
{{- end -}}

{{- define "neubird-proxy.noToken" -}}
{{- $d := get (.Values.config | default dict) "neubird_destinations" -}}
{{- if kindIs "map" $d -}}
{{- $ca := toString (get $d "client_auth") -}}
{{- if or (eq $ca "none") (and (include "neubird-proxy.tokenUnset" $d) (not (include "neubird-proxy.inbound" .))) -}}true{{- end -}}
{{- end -}}
{{- end -}}

{{- define "neubird-proxy.clientCAConfigMap" -}}
{{- default (printf "%s-client-ca" (include "neubird-proxy.fullname" .)) .Values.inbound.clientCA.existingConfigMap -}}
{{- end -}}

{{- define "neubird-proxy.hasClientCA" -}}
{{- if or .Values.inbound.clientCA.cert .Values.inbound.clientCA.existingConfigMap -}}true{{- end -}}
{{- end -}}

{{/* The proxy's config.yaml: .Values.config plus what the mode sets: the
tunnel section and listen: off, or listen: :8443 and tls. */}}
{{- define "neubird-proxy.config" -}}
{{- $c := .Values.config -}}
{{- if hasKey $c "tunnel" -}}{{- fail "set the tunnel under `tunnel`, not config.tunnel" -}}{{- end -}}
{{- $listen := ternary ":8443" "off" (eq (include "neubird-proxy.mode" .) "inbound") -}}
{{- if and (hasKey $c "listen") (ne (toString $c.listen) $listen) -}}{{- fail (printf "config.listen: leave it out (the chart sets it to %s from `mode`)" $listen) -}}{{- end -}}
{{- if hasKey $c "tls" -}}{{- fail "config.tls: set inbound.tls and inbound.clientCA instead" -}}{{- end -}}
{{- if and (hasKey $c "admin_listen") (ne (toString $c.admin_listen) ":9090") -}}{{- fail "config.admin_listen: leave it out (the chart's probes use :9090)" -}}{{- end -}}
{{- $cfg := merge (dict "admin_listen" ":9090") (deepCopy $c) -}}
{{- /* No proxy token anywhere (client_auth: none, no named connections):
leave out the default client_token_env, which nothing would read. */ -}}
{{- if and (include "neubird-proxy.noToken" .) (not $c.connections) -}}
{{- $_ := unset $cfg "client_token_env" -}}
{{- end -}}
{{- if include "neubird-proxy.inbound" . -}}
{{- $in := .Values.inbound -}}
{{- if .Values.tunnel.relays -}}{{- fail "tunnel.relays: mode inbound has no tunnel; leave tunnel out (or use mode: tunnel)" -}}{{- end -}}
{{- if and (kindIs "map" (get $c "neubird_destinations")) (eq (toString (get (get $c "neubird_destinations") "client_auth")) "none") -}}{{- fail "neubird_destinations.client_auth: none is for mode tunnel only; an inbound listener needs a proxy token" -}}{{- end -}}
{{- $_ := set $cfg "listen" $listen -}}
{{- if $in.tls.existingSecret -}}
{{- $tls := dict "cert_file" "/etc/neubird-proxy/tls/tls.crt" "key_file" "/etc/neubird-proxy/tls/tls.key" -}}
{{- if include "neubird-proxy.hasClientCA" . -}}
{{- $_ := set $tls "client_ca_file" "/etc/neubird-proxy/client-ca/ca.crt" -}}
{{- end -}}
{{- $_ := set $cfg "tls" $tls -}}
{{- else if not $in.allowPlainHTTP -}}
{{- fail "inbound.tls.existingSecret is required with mode inbound: a kubernetes.io/tls Secret (or inbound.allowPlainHTTP: true when TLS ends in front of the pod)" -}}
{{- else if include "neubird-proxy.hasClientCA" . -}}
{{- fail "inbound.clientCA needs inbound.tls.existingSecret: mutual TLS is part of the proxy's TLS" -}}
{{- end -}}
{{- else -}}
{{- $t := .Values.tunnel -}}
{{- if not $t.relays -}}{{- fail "tunnel.relays is required: your relay's address from NeuBird" -}}{{- end -}}
{{- if not (and $t.tenant $t.proxy) -}}{{- fail "tunnel.tenant and tunnel.proxy are required" -}}{{- end -}}
{{- $tunnel := dict
  "relays" $t.relays
  "tenant" $t.tenant
  "proxy" $t.proxy
  "key_file" "/etc/neubird-proxy/tunnel/tunnel.key"
  "ca_file" "/etc/neubird-proxy/ca/relay-ca.crt"
  "connections_per_relay" $t.connectionsPerRelay
  "join_token_env" ($t.joinTokenEnv | default "") -}}
{{- $_ := set $cfg "tunnel" $tunnel -}}
{{- /* Mode tunnel: NeuBird sends no proxy token (the tunnel authenticates
every request), so neubird_destinations defaults to client_auth: none, unless
the section names a token (client_auth, client_token_env or
client_auth_header). */ -}}
{{- if include "neubird-proxy.tokenUnset" (get $cfg "neubird_destinations") -}}
{{- $_ := set $cfg.neubird_destinations "client_auth" "none" -}}
{{- end -}}
{{- $_ := set $cfg "listen" $listen -}}
{{- end -}}
{{- if or .Values.upstreamCA.cert .Values.upstreamCA.existingConfigMap -}}
{{- if hasKey .Values.config "upstream_ca_file" -}}{{- fail "set upstreamCA instead of config.upstream_ca_file" -}}{{- end -}}
{{- $_ := set $cfg "upstream_ca_file" "/etc/neubird-proxy/upstream-ca/ca.crt" -}}
{{- end -}}
{{- toYaml $cfg -}}
{{- end -}}
