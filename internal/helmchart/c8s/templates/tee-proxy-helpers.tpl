{{/*
Expand the name of the chart.
*/}}
{{- define "tee-proxy.name" -}}
{{- default "tee-proxy" .Values.teeProxy.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "tee-proxy.fullname" -}}
{{- if .Values.teeProxy.fullnameOverride }}
{{- .Values.teeProxy.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default "tee-proxy" .Values.teeProxy.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "tee-proxy.labels" -}}
helm.sh/chart: tee-proxy-0.1.0
{{ include "tee-proxy.selectorLabels" . }}
app.kubernetes.io/version: ""
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: c8s
{{- end }}

{{/*
Selector labels
*/}}
{{- define "tee-proxy.selectorLabels" -}}
app: {{ include "tee-proxy.fullname" . }}
app.kubernetes.io/name: {{ include "tee-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Image reference
*/}}
{{- define "tee-proxy.image" -}}
{{ include "c8s-common.image" .Values.teeProxy.image }}
{{- end }}
