{{/* Images helpers. See ../helpers/images/README.md. */}}

{{- define "c8s.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else if .Values.image.tag -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- else -}}
{{ fail "image.tag or image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s.attestationApiImage" -}}
{{- if .Values.attestationApi.image.digest -}}
{{ .Values.attestationApi.image.repository }}@{{ .Values.attestationApi.image.digest }}
{{- else if .Values.attestationApi.image.tag -}}
{{ .Values.attestationApi.image.repository }}:{{ .Values.attestationApi.image.tag }}
{{- else -}}
{{ fail "attestationApi.image.tag or attestationApi.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s.cdsImage" -}}
{{- if .Values.cds.image.digest -}}
{{ .Values.cds.image.repository }}@{{ .Values.cds.image.digest }}
{{- else if .Values.cds.image.tag -}}
{{ .Values.cds.image.repository }}:{{ .Values.cds.image.tag }}
{{- else -}}
{{ fail "cds.image.tag or cds.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s.kataDeployImage" -}}
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

{{- define "c8s.kataContainerdPrepImage" -}}
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

{{- define "c8s.kataGuestImageTag" -}}
{{- if .Values.kata.guestImage.debug -}}
{{- printf "%s-debug" .Values.kata.guestImage.tag -}}
{{- else -}}
{{- .Values.kata.guestImage.tag -}}
{{- end -}}
{{- end -}}

{{- define "c8s.kataGuestImageNvidiaTag" -}}
{{- if .Values.kata.guestImage.debug -}}
{{- printf "%s-nvidia-debug" .Values.kata.guestImage.tag -}}
{{- else -}}
{{- printf "%s-nvidia" .Values.kata.guestImage.tag -}}
{{- end -}}
{{- end -}}

{{- define "c8s.kataSandboxDevicePluginImage" -}}
{{- $img := .Values.kata.gpu.sandboxDevicePlugin.image -}}
{{- if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else if $img.tag -}}
{{ $img.repository }}:{{ $img.tag }}
{{- else -}}
{{ fail "kata.gpu.sandboxDevicePlugin.image.tag or .digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s.imagePullSecrets" -}}
{{- $secrets := .local | default .root.Values.imagePullSecrets | default list -}}
{{- with .root.Values.imagePullSecret -}}
{{- $secrets = uniq (append $secrets (dict "name" .)) -}}
{{- end -}}
{{- with $secrets }}
imagePullSecrets:
{{ toYaml . }}
{{- end -}}
{{- end -}}

{{- define "c8s.serviceAccountImagePullSecrets" -}}
{{- include "c8s.imagePullSecrets" (dict "root" . "local" .Values.serviceAccount.imagePullSecrets) -}}
{{- end -}}

{{- define "volumed.image" -}}
{{ include "c8s-common.image" .Values.volumed.image }}
{{- end -}}

{{- define "c8s-common.image" -}}
{{- $img := . -}}
{{- if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else -}}
{{ $img.repository }}:{{ required (printf "image.tag or image.digest is required for %s" $img.repository) $img.tag }}
{{- end -}}
{{- end }}
