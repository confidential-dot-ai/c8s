{{/* Certificates helpers. See ../helpers/certificates/README.md. */}}

{{- define "c8s.getCertContainers" -}}
{{- $root := .root -}}
- name: c8s-cert
  image: {{ include "c8s.image" $root }}
  imagePullPolicy: IfNotPresent
  restartPolicy: Always
  args:
    - get-cert
    - --cds-url={{ include "c8s.cdsURL" $root }}
    - --attestation-api-url={{ include "c8s.attestationApiURL" $root }}
    - --san={{ .san }}
    - --out={{ .certOut }}
    - --key-out={{ .keyOut }}
    {{- with .caOut }}
    - --ca-out={{ . }}
    {{- end }}
    # Retry CDS in-process during a roll instead of exiting into kubelet
    # CrashLoopBackOff; still fails closed once the timeout elapses.
    - --initial-retry-timeout={{ $root.Values.certProvisioning.initialRetryTimeout }}
    - --renew-interval={{ .renewInterval }}
    - --reload-nginx={{ default "false" .reloadNginx }}
    - --continue-on-initial-error
    {{- range .extraArgs }}
    - {{ . }}
    {{- end }}
  {{- with (include "c8s.attestationApiHostIPEnv" $root) }}
  # cvmMode=node: expands $(HOST_IP) in --attestation-api-url to the node IP so
  # this pod-netns sidecar reaches the node-baked host attestation-api.
  env:
    {{- . | nindent 4 }}
  {{- end }}
  volumeMounts:
    - name: {{ .volume }}
      mountPath: {{ .mountPath }}
    {{- with .extraMounts }}
    {{- . | nindent 4 }}
    {{- end }}
  securityContext:
    {{- include "c8s.getCertSecurityContext" . | nindent 4 }}
# c8s-cert-wait is a run-once init container that blocks on the cert file.
# Init-container completion holds the workload until the attested cert exists.
# The `/c8s` path is the binary location from cmd/c8s/Dockerfile; command
# bypasses the ENTRYPOINT so the full path must match.
- name: c8s-cert-wait
  image: {{ include "c8s.image" $root }}
  imagePullPolicy: IfNotPresent
  command:
    - /c8s
    - probe-file
    - --wait
    - --timeout=3m
    - {{ .certOut }}
  volumeMounts:
    - name: {{ .volume }}
      mountPath: {{ .mountPath }}
  securityContext:
    {{- include "c8s.getCertSecurityContext" . | nindent 4 }}
{{- end -}}

{{- define "c8s.getCertSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: {{ .runAsNonRoot }}
runAsUser: {{ include "c8s.int" .runAsUser }}
runAsGroup: {{ include "c8s.int" .runAsGroup }}
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "c8s.cdsDnsSanPattern" -}}
^[a-z0-9-]+[.][a-z0-9-]+[.]svc$
{{- end -}}
