{{/* Kata helpers. See ../helpers/kata/README.md. */}}

{{- define "c8s.controlPlaneKataRuntimeClass" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
kata-qemu-tdx
{{- else -}}
kata-qemu-snp
{{- end -}}
{{- end -}}

{{- define "c8s.kataShimName" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
qemu-tdx
{{- else -}}
qemu-snp
{{- end -}}
{{- end -}}

{{- define "c8s.kataGpuRuntimeClass" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
kata-qemu-tdx-nvidia
{{- else -}}
kata-qemu-snp-nvidia
{{- end -}}
{{- end -}}

{{- define "c8s.kataGpuShimName" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
qemu-nvidia-gpu-tdx
{{- else -}}
qemu-nvidia-gpu-snp
{{- end -}}
{{- end -}}

{{- define "c8s.hardwarePlatform" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
tdx
{{- else -}}
sev-snp
{{- end -}}
{{- end -}}

{{- define "c8s.kataConfidentialShims" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
qemu-tdx qemu-nvidia-gpu-tdx
{{- else -}}
qemu-snp qemu-nvidia-gpu-snp
{{- end -}}
{{- end -}}

{{- define "c8s.kataAllowedRuntimeClasses" -}}
{{- if .Values.attestationApi.teeDevices.tdxGuest -}}
'kata-qemu', 'kata-clh', 'kata-qemu-tdx', 'kata-qemu-tdx-nvidia'
{{- else -}}
'kata-qemu', 'kata-clh', 'kata-qemu-snp', 'kata-qemu-snp-nvidia'
{{- end -}}
{{- end -}}

{{- define "c8s.kataContainerdConfigDir" -}}
{{- if .Values.kata.containerdConfigDir -}}
{{ .Values.kata.containerdConfigDir }}
{{- else if eq .Values.kata.distro "rke2" -}}
/var/lib/rancher/rke2/agent/etc/containerd
{{- else if eq .Values.kata.distro "k8s" -}}
/etc/containerd
{{- else -}}
{{ fail (printf "kata.distro must be \"k8s\" or \"rke2\" (got %q), or set kata.containerdConfigDir explicitly" .Values.kata.distro) }}
{{- end -}}
{{- end -}}

{{- define "c8s.kataGuestReadyGate" -}}
{{- if and .Values.kata.enabled .Values.kata.guestImage.enabled -}}
true
{{- end -}}
{{- end -}}

{{- define "c8s.kataGuestReadyAffinity" -}}
{{- if include "c8s.kataGuestReadyGate" . }}
affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
        - matchExpressions:
            - key: confidential.ai/kata-guest-ready
              operator: In
              values: ["true"]
{{- end }}
{{- end -}}
