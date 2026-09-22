{{/*
The installer has only flat CDS digest/register inputs. Refuse a complete policy
unless those inputs express exactly the same trust set. This is a projection
check, not a replacement for refvalues' full schema validation in the services.
Keep it scoped to the enabled installer: baked nodes can manage NRI separately.
*/}}
{{- define "nri-image-policy.validateCDSPolicy" -}}
{{- if .Values.cds.measurementsConfig -}}
{{- $error := "nri-image-policy: cds.measurementsConfig requires equivalent cds.measurements and cds.rtmrs; approver_key and per-image RTMR policies require the baked node launch flow with nriImagePolicy.enabled=false" -}}
{{- $policy := mustFromJson .Values.cds.measurementsConfig -}}
{{- if not (kindIs "map" $policy) -}}{{ fail $error }}{{- end -}}
{{- if or (ne ($policy.schema_version | toString) "1") (not (has $policy.tee (list "tdx" "sev-snp"))) -}}{{ fail $error }}{{- end -}}
{{- range $key, $_ := $policy -}}
  {{- if not (has $key (list "schema_version" "tee" "measurements")) -}}{{ fail $error }}{{- end -}}
{{- end -}}
{{- if or (not (kindIs "slice" $policy.measurements)) (empty $policy.measurements) -}}{{ fail $error }}{{- end -}}
{{- $digests := dict -}}
{{- range .Values.cds.measurements -}}
  {{- $digest := trim . -}}
  {{- if not (regexMatch "^[0-9a-f]{96}$" $digest) -}}{{ fail $error }}{{- end -}}
  {{- $_ := set $digests $digest true -}}
{{- end -}}
{{- $registers := dict -}}
{{- range .Values.cds.rtmrs -}}
  {{- $parts := splitList "=" . -}}
  {{- if ne (len $parts) 2 -}}{{ fail $error }}{{- end -}}
  {{- $index := trim (index $parts 0) -}}
  {{- $digest := trim (index $parts 1) -}}
  {{- if or (not (has $index (list "1" "2" "3"))) (not (regexMatch "^[0-9a-f]{96}$" $digest)) (hasKey $registers $index) -}}{{ fail $error }}{{- end -}}
  {{- $_ := set $registers $index $digest -}}
{{- end -}}
{{- $policyDigests := dict -}}
{{- range $policy.measurements -}}
  {{- if not (kindIs "map" .) -}}{{ fail $error }}{{- end -}}
  {{- range $key, $_ := . -}}
    {{- if not (has $key (list "name" "mrtd" "measurement" "rtmr")) -}}{{ fail $error }}{{- end -}}
  {{- end -}}
  {{- $digest := "" -}}
  {{- if eq $policy.tee "tdx" -}}
    {{- if hasKey . "measurement" -}}{{ fail $error }}{{- end -}}
    {{- $digest = .mrtd -}}
  {{- else -}}
    {{- if or (hasKey . "mrtd") (hasKey . "rtmr") -}}{{ fail $error }}{{- end -}}
    {{- $digest = .measurement -}}
  {{- end -}}
  {{- if not (kindIs "string" $digest) -}}{{ fail $error }}{{- end -}}
  {{- if not (regexMatch "^[0-9a-f]{96}$" $digest) -}}{{ fail $error }}{{- end -}}
  {{- $_ := set $policyDigests $digest true -}}
  {{- $imageRegisters := dict -}}
  {{- if .rtmr -}}
    {{- if not (kindIs "slice" .rtmr) -}}{{ fail $error }}{{- end -}}
    {{- if gt (len .rtmr) 4 -}}{{ fail $error }}{{- end -}}
    {{- range $index, $value := .rtmr -}}
      {{- if not (kindIs "invalid" $value) -}}
        {{- if or (eq $index 0) (not (kindIs "string" $value)) -}}{{ fail $error }}{{- end -}}
        {{- if eq $value "" -}}{{- $value = repeat 96 "0" -}}{{- end -}}
        {{- if not (regexMatch "^[0-9a-f]{96}$" $value) -}}{{ fail $error }}{{- end -}}
        {{- $_ := set $imageRegisters (toString $index) $value -}}
      {{- end -}}
    {{- end -}}
  {{- end -}}
  {{- if not (deepEqual $registers $imageRegisters) -}}{{ fail $error }}{{- end -}}
{{- end -}}
{{- if not (deepEqual $digests $policyDigests) -}}{{ fail $error }}{{- end -}}
{{- end -}}
{{- end -}}
