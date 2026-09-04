{{/*
Expand the name of the chart.
*/}}
{{- define "c8s-lib.ratlsMesh.name" -}}
ratls-mesh
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "c8s-lib.ratlsMesh.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "c8s-lib.ratlsMesh.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "c8s-lib.ratlsMesh.labels" -}}
helm.sh/chart: {{ include "c8s-lib.ratlsMesh.name" . }}-0.1.0
{{ include "c8s-lib.ratlsMesh.selectorLabels" . }}
app.kubernetes.io/version: ""
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: c8s
{{- end }}

{{/*
Selector labels
*/}}
{{- define "c8s-lib.ratlsMesh.selectorLabels" -}}
app: {{ include "c8s-lib.ratlsMesh.fullname" . }}
app.kubernetes.io/name: {{ include "c8s-lib.ratlsMesh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Image reference
*/}}
{{- define "c8s-lib.ratlsMesh.image" -}}
{{ include "c8s-lib.common.image" .Values.ratlsMesh.image }}
{{- end }}

{{/*
c8s-lib.ratlsMesh.durationSeconds — parse a Go-style duration into integer seconds.
Supports the single-unit forms (Ns, Nm, Nh) that fit chart-bound arithmetic;
compound forms ("1m30s") are intentionally rejected so the bound math stays
exact instead of silently truncating via sprig's lenient int parsing.
*/}}
{{- define "c8s-lib.ratlsMesh.durationSeconds" -}}
{{- $d := . -}}
{{- $unit := "" -}}
{{- $num := "" -}}
{{- if hasSuffix "h" $d -}}
{{- $unit = "h" -}}
{{- $num = trimSuffix "h" $d -}}
{{- else if hasSuffix "m" $d -}}
{{- $unit = "m" -}}
{{- $num = trimSuffix "m" $d -}}
{{- else if hasSuffix "s" $d -}}
{{- $unit = "s" -}}
{{- $num = trimSuffix "s" $d -}}
{{- else -}}
{{- fail (printf "duration %q must end with h, m, or s (single unit only)" $d) -}}
{{- end -}}
{{- if not (mustRegexMatch "^[0-9]+$" $num) -}}
{{- fail (printf "duration %q must be a positive integer followed by a single unit (h, m, or s)" $d) -}}
{{- end -}}
{{- $n := $num | int -}}
{{- if eq $unit "h" -}}{{- mul 3600 $n -}}
{{- else if eq $unit "m" -}}{{- mul 60 $n -}}
{{- else -}}{{- $n -}}{{- end -}}
{{- end }}
