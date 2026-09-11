{{/* Allowlist helpers. See ../helpers/allowlist/README.md. */}}

{{- define "c8s.valueAtPath" -}}
{{- $cur := .root -}}
{{- range $seg := splitList "." .path -}}
{{- if kindIs "map" $cur -}}{{- $cur = index $cur $seg -}}{{- else -}}{{- $cur = "" -}}{{- end -}}
{{- end -}}
{{- $cur | toJson -}}
{{- end -}}

{{- define "c8s.components" -}}
{{- $root := . -}}
{{- $out := list -}}
{{- range $c := .Values.c8sComponents -}}
{{- $img := include "c8s.valueAtPath" (dict "root" $root.Values "path" $c.valuePath) | fromJson -}}
{{- /* enabledPath points at a JSON boolean; valueAtPath returns it as the
   string "true"/"false". Compare the string rather than `| fromJson`, whose
   Helm variant returns a (truthy) map for a scalar — which silently made this
   gate a no-op, deriving even disabled components that carry a digest. */ -}}
{{- $enabled := true -}}
{{- if $c.enabledPath -}}{{- $enabled = eq (include "c8s.valueAtPath" (dict "root" $root.Values "path" $c.enabledPath)) "true" -}}{{- end -}}
{{- $out = append $out (dict "name" $c.valuePath "image" $img "enabled" $enabled "cdsExempt" $c.cdsExempt) -}}
{{- end -}}
{{ $out | toJson }}
{{- end -}}

{{- define "c8s.imageAllowlist" -}}
{{- $digests := dict -}}
{{- if .Values.nriImagePolicy.bootstrapAllowlist.deriveComponents -}}
{{- range $c := (include "c8s.components" . | fromJsonArray) -}}
{{- $img := get $c "image" -}}
{{- if and (get $c "enabled") (get $img "digest") -}}
{{- $_ := set $digests (get $img "digest") (printf "%s@%s" (get $img "repository") (get $img "digest")) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $cdsImg := .Values.cds.image -}}
{{- if $cdsImg.digest -}}
{{- $_ := set $digests $cdsImg.digest (printf "%s@%s" $cdsImg.repository $cdsImg.digest) -}}
{{- end -}}
{{- /* tls-lb nginx self-entry: a chart-deployed non-c8s system image. It is
       independently versioned and digest-pinned, so it is not in the
       tag-locked c8sComponents derive set (the resolver would `crane digest
       nginx:<c8s-tag>`). Seed it from its pinned digest whenever tls-lb is
       enabled — like the CDS self-entry above, independent of deriveComponents
       — so a default install admits the nginx it ships without the operator
       hand-writing an entry for it. */}}
{{- if .Values.tlsLb.enabled -}}
{{- $lbImg := .Values.tlsLb.nginx.image -}}
{{- if $lbImg.digest -}}
{{- $_ := set $digests $lbImg.digest (printf "%s@%s" $lbImg.repository $lbImg.digest) -}}
{{- end -}}
{{- end -}}

{{- if .Values.nriImagePolicy.enabled -}}
{{- if and (eq .Values.nriImagePolicy.distro "rke2") (not .Values.nriImagePolicy.baked) -}}
{{- $prep := .Values.nriImagePolicy.containerdPrep.image -}}
{{- if $prep.digest -}}
{{- $_ := set $digests $prep.digest (printf "%s@%s" $prep.repository $prep.digest) -}}
{{- end -}}
{{- end -}}

{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{- define "c8s.anyArgvDigests" -}}
{{- $digests := dict -}}
{{- range $name, $entry := (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) -}}
{{- range $c := concat (default list $entry.initContainers) (default list $entry.containers) -}}
{{- if and (eq (dig "command" "policy" "" $c) "any") (eq (dig "args" "policy" "" $c) "any") -}}
{{- $_ := set $digests $c.digest (default $entry.label $c.image | default "") -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{- define "c8s.alwaysAllow" -}}
{{ merge (include "c8s.anyArgvDigests" . | fromJson) (include "c8s.imageAllowlist" . | fromJson) | toJson }}
{{- end -}}

{{- define "c8s.digestWorkloadName" -}}
{{- $base := .image | splitList "@" | first | splitList "/" | last | splitList ":" | first | trunc 50 -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._-]*$" $base) -}}{{- $base = "image" -}}{{- end -}}
{{- printf "%s-%s" $base (.digest | trimPrefix "sha256:" | lower | trunc 12) -}}
{{- end -}}

{{- define "c8s.allowlistSeedJSON" -}}
{{- $workloads := dict -}}
{{- range $digest, $image := (include "c8s.imageAllowlist" . | fromJson) -}}
{{- $name := include "c8s.digestWorkloadName" (dict "digest" $digest "image" $image) -}}
{{- $container := dict "digest" $digest "image" $image "command" (dict "policy" "any") "args" (dict "policy" "any") -}}
{{- $_ := set $workloads $name (dict "label" $image "initContainers" list "containers" (list $container)) -}}
{{- end -}}
{{- range $name, $entry := (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) -}}
{{- $_ := set $workloads $name $entry -}}
{{- end -}}
{{ dict "schema" "c8s.allowlist/v1" "workloads" $workloads | toJson }}
{{- end -}}
