{{/* Services helpers. See ../helpers/services/README.md. */}}

{{- define "c8s.attestationApiURL" -}}
{{- if .Values.attestationApi.enabled -}}
unix://{{ include "c8s.attestationApiSocket" . }}
{{- else -}}
http://$(HOST_IP):{{ .Values.attestationApi.port }}
{{- end -}}
{{- end -}}

{{- define "c8s.attestationApiSocket" -}}
{{ .Values.nriImagePolicy.hostPaths.runtimeDir }}/attestation-api.sock
{{- end -}}

{{- define "c8s.attestationApiSocketVolume" -}}
{{- if .Values.attestationApi.enabled }}
- name: attestation-api-socket
  hostPath:
    path: {{ .Values.nriImagePolicy.hostPaths.runtimeDir }}
    type: DirectoryOrCreate
{{- end }}
{{- end -}}

{{- define "c8s.attestationApiSocketMount" -}}
{{- if .Values.attestationApi.enabled }}
- name: attestation-api-socket
  mountPath: {{ .Values.nriImagePolicy.hostPaths.runtimeDir }}
  readOnly: true
{{- end }}
{{- end -}}

{{- define "c8s.attestationApiHostIPEnv" -}}
{{- if and (not .Values.attestationApi.enabled) (eq .Values.attestationApi.cvmMode "node") -}}
- name: HOST_IP
  valueFrom:
    fieldRef:
      fieldPath: status.hostIP
{{- end -}}
{{- end -}}

{{- define "c8s.nriCDSURL" -}}
{{- if .Values.nriImagePolicy.cds.url -}}
{{ .Values.nriImagePolicy.cds.url }}
{{- else -}}
{{ printf "https://127.0.0.1:%d" (int .Values.cds.service.nodePort) }}
{{- end -}}
{{- end -}}

{{- define "c8s.cdsURL" -}}
https://{{ include "c8s.cdsName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.cds.port }}
{{- end -}}

{{- define "c8s.trustRootURL" -}}
{{ include "c8s.cdsURL" . }}
{{- end -}}

{{- define "c8s.attestationApiConfig" -}}
{{- $root := .root -}}
[server]
# Pod loopback only: consumers enter through the attest-proxy sidecar's
# node-local Unix socket; nothing routable can reach /attest.
bind = "127.0.0.1:{{ $root.Values.attestationApi.port }}"

[server.tls]
enabled = false

[attestation]
enabled = true
platforms = [{{- range $i, $p := $root.Values.attestationApi.platforms -}}
  {{- if $i }}, {{ end -}}{{- $p | quote -}}
{{- end -}}]

[certs]
cache_max_entries = 1024
{{- end -}}

{{- define "c8s.tlsLb.resolver" -}}
{{- if .Values.tlsLb.nginx.resolver -}}
{{- .Values.tlsLb.nginx.resolver -}}
{{- else if eq .Values.nriImagePolicy.distro "rke2" -}}
rke2-coredns-rke2-coredns.kube-system.svc.cluster.local
{{- else -}}
kube-dns.kube-system.svc.cluster.local
{{- end -}}
{{- end -}}
