{{- define "ozone-oidc-proxy.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ozone-oidc-proxy.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ozone-oidc-proxy.labels" -}}
app.kubernetes.io/name: {{ include "ozone-oidc-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "ozone-oidc-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ozone-oidc-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Proxy pods only, the component label keeps the proxy Service and
     NetworkPolicies from also matching the in-chart valkey pods, which share
     the name/instance labels. */}}
{{- define "ozone-oidc-proxy.proxySelectorLabels" -}}
{{ include "ozone-oidc-proxy.selectorLabels" . }}
app.kubernetes.io/component: proxy
{{- end -}}

{{- define "ozone-oidc-proxy.storeKeySecret" -}}
{{- if .Values.storeKey.existingSecret -}}
{{- .Values.storeKey.existingSecret -}}
{{- else -}}
{{- include "ozone-oidc-proxy.fullname" . -}}-store-key
{{- end -}}
{{- end -}}
