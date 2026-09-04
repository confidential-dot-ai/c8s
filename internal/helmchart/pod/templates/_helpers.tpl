{{/*
  Pod-shape helpers: the kata shim / RuntimeClass names, all derived from the
  chart's single `platform` value (snp | tdx). A cluster is one CPU TEE, so
  only its RuntimeClasses render — the other platform's classes would be
  unschedulable decoys.
*/}}

{{- define "c8s-pod.kataName" -}}
{{- printf "%s-kata-deploy" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* kata-qemu-snp | kata-qemu-tdx */}}
{{- define "c8s-pod.runtimeClass" -}}
kata-qemu-{{ include "c8s-lib.teeFamily" . }}
{{- end -}}

{{/* Shim dir kata-deploy installs for the confidential runtime. */}}
{{- define "c8s-pod.shimName" -}}
qemu-{{ include "c8s-lib.teeFamily" . }}
{{- end -}}

{{/* Confidential-GPU RuntimeClass and shim names. The NAME follows the
   kata-qemu-<tee> convention; the HANDLER stays the upstream shim name
   kata-deploy registers (qemu-nvidia-gpu-<tee>). */}}
{{- define "c8s-pod.gpuRuntimeClass" -}}
kata-qemu-{{ include "c8s-lib.teeFamily" . }}-nvidia
{{- end -}}

{{- define "c8s-pod.gpuShimName" -}}
qemu-nvidia-gpu-{{ include "c8s-lib.teeFamily" . }}
{{- end -}}

{{/* The confidential shim set, as kata-deploy SHIMS_X86_64 tokens: the CPU
   shim + the NVIDIA GPU shim. */}}
{{- define "c8s-pod.confidentialShims" -}}
{{ include "c8s-pod.shimName" . }} {{ include "c8s-pod.gpuShimName" . }}
{{- end -}}

{{/* The RuntimeClass names kata enforcement accepts, as a quoted CEL list
   body: the two non-confidential classes plus this platform's confidential
   (CPU, GPU) pair. */}}
{{- define "c8s-pod.allowedRuntimeClasses" -}}
'kata-qemu', 'kata-clh', '{{ include "c8s-pod.runtimeClass" . }}', '{{ include "c8s-pod.gpuRuntimeClass" . }}'
{{- end -}}

{{- define "c8s-pod.kataDeployImage" -}}
{{- if and .Values.kata.image.digest .Values.kata.image.tag -}}
{{ fail "kata.image.tag and kata.image.digest are mutually exclusive — set one, not both (digest wins silently otherwise, which surprises operators bumping versions)" }}
{{- else if .Values.kata.image.digest -}}
{{ .Values.kata.image.repository }}@{{ .Values.kata.image.digest }}
{{- else if .Values.kata.image.tag -}}
{{ .Values.kata.image.repository }}:{{ .Values.kata.image.tag }}
{{- else -}}
{{ fail "kata.image.tag or kata.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s-pod.kataContainerdPrepImage" -}}
{{- $img := .Values.kata.containerdPrep.image -}}
{{- if and $img.digest $img.tag -}}
{{ fail "kata.containerdPrep.image.tag and kata.containerdPrep.image.digest are mutually exclusive — set one, not both" }}
{{- else if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else if $img.tag -}}
{{ $img.repository }}:{{ $img.tag }}
{{- else -}}
{{ fail "kata.containerdPrep.image.tag or kata.containerdPrep.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{/* The kata-guest-base artifact tag the puller fetches; debug selects the
   `<tag>-debug` variant (baked policy allows host log/exec — dev only). */}}
{{- define "c8s-pod.guestImageTag" -}}
{{- if .Values.kata.guestImage.debug -}}
{{- printf "%s-debug" .Values.kata.guestImage.tag -}}
{{- else -}}
{{- .Values.kata.guestImage.tag -}}
{{- end -}}
{{- end -}}

{{/* The confidential-GPU guest-image tag: `<tag>-nvidia[-debug]`. */}}
{{- define "c8s-pod.guestImageNvidiaTag" -}}
{{- if .Values.kata.guestImage.debug -}}
{{- printf "%s-nvidia-debug" .Values.kata.guestImage.tag -}}
{{- else -}}
{{- printf "%s-nvidia" .Values.kata.guestImage.tag -}}
{{- end -}}
{{- end -}}

{{- define "c8s-pod.sandboxDevicePluginImage" -}}
{{- $img := .Values.kata.gpu.sandboxDevicePlugin.image -}}
{{- if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else if $img.tag -}}
{{ $img.repository }}:{{ $img.tag }}
{{- else -}}
{{ fail "kata.gpu.sandboxDevicePlugin.image.tag or .digest must be set" }}
{{- end -}}
{{- end -}}

{{/*
  kata-deploy reads the host's rendered containerd config at the literal
  in-container path /etc/containerd/config.toml and writes the runtime
  drop-in beside it. The chart bind-mounts the host's real containerd config
  directory there — which differs by distro.
*/}}
{{- define "c8s-pod.containerdConfigDir" -}}
{{- if .Values.kata.containerdConfigDir -}}
{{ .Values.kata.containerdConfigDir }}
{{- else if eq .Values.distro "rke2" -}}
/var/lib/rancher/rke2/agent/etc/containerd
{{- else if eq .Values.distro "k8s" -}}
/etc/containerd
{{- else -}}
{{ fail (printf "distro must be \"k8s\" or \"rke2\" (got %q), or set kata.containerdConfigDir explicitly" .Values.distro) }}
{{- end -}}
{{- end -}}
