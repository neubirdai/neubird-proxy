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

{{/* The proxy's config.yaml: .Values.config plus the generated tunnel section. */}}
{{- define "neubird-proxy.config" -}}
{{- $t := .Values.tunnel -}}
{{- if not $t.relays -}}{{- fail "tunnel.relays is required: your relay's address from NeuBird" -}}{{- end -}}
{{- if not (and $t.tenant $t.proxy) -}}{{- fail "tunnel.tenant and tunnel.proxy are required" -}}{{- end -}}
{{- if hasKey .Values.config "tunnel" -}}{{- fail "set the tunnel under `tunnel`, not config.tunnel" -}}{{- end -}}
{{- $tunnel := dict
  "relays" $t.relays
  "tenant" $t.tenant
  "proxy" $t.proxy
  "key_file" "/etc/neubird-proxy/tunnel/tunnel.key"
  "ca_file" "/etc/neubird-proxy/ca/relay-ca.crt"
  "connections_per_relay" $t.connectionsPerRelay
  "join_token_env" ($t.joinTokenEnv | default "") -}}
{{- $c := .Values.config -}}
{{- if and (hasKey $c "listen") (ne (toString $c.listen) "off") -}}{{- fail "config.listen: this chart is tunnel-only; leave listen out (the chart sets it to off)" -}}{{- end -}}
{{- if and (hasKey $c "admin_listen") (ne (toString $c.admin_listen) ":9090") -}}{{- fail "config.admin_listen: leave it out (the chart's probes use :9090)" -}}{{- end -}}
{{- $cfg := merge (dict "tunnel" $tunnel "listen" "off" "admin_listen" ":9090") (deepCopy $c) -}}
{{- if or .Values.upstreamCA.cert .Values.upstreamCA.existingConfigMap -}}
{{- if hasKey .Values.config "upstream_ca_file" -}}{{- fail "set upstreamCA instead of config.upstream_ca_file" -}}{{- end -}}
{{- $_ := set $cfg "upstream_ca_file" "/etc/neubird-proxy/upstream-ca/ca.crt" -}}
{{- end -}}
{{- toYaml $cfg -}}
{{- end -}}
