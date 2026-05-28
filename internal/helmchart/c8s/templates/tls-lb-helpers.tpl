{{/*
Expand the name of the chart.
*/}}
{{- define "tls-lb.name" -}}
{{- default "tls-lb" .Values.tlsLb.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "tls-lb.fullname" -}}
{{- printf "%s-tls-lb" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Default the CDS certificate SAN to the chart-managed Service DNS name. Public
deployments should set .Values.tlsLb.san to the externally routed hostname.
*/}}
{{- define "tls-lb.san" -}}
{{- default (printf "%s.%s.svc" (include "tls-lb.fullname" .) .Release.Namespace) .Values.tlsLb.san }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "tls-lb.labels" -}}
helm.sh/chart: tls-lb-0.5.0
{{ include "tls-lb.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Validate that san contains only safe characters for use in nginx config.
Allows DNS hostnames and wildcards (e.g. *.example.com).
*/}}
{{- define "tls-lb.validateSan" -}}
{{- if regexMatch `[^a-zA-Z0-9.*-]` . -}}
{{- fail (printf "san contains invalid characters: %s - only alphanumeric, dots, hyphens, and wildcards are allowed" .) -}}
{{- end -}}
{{- end -}}

{{/*
Validate that the protocol used for an upstream is only http or https
*/}}
{{- define "tls-lb.validateProtocol" -}}
{{- if not (or (eq . "http") (eq . "https")) -}}
{{- fail (printf "upstream.protocol must be 'http' or 'https', got: %s" .) -}}
{{- end -}}
{{- end -}}

{{/*
Catch the umbrella chart's default tee-proxy HTTP service port when callers
switch tls-lb to HTTPS upstream mode without also moving the backend port.
*/}}
{{- define "tls-lb.validateUpstreamAddress" -}}
{{- if and (eq .protocol "https") (eq .address "c8s-tee-proxy:80") -}}
{{- fail "tlsLb.upstream.protocol=https requires tlsLb.upstream.address to point at a TLS port; for the chart-managed tee-proxy use c8s-tee-proxy:443" -}}
{{- end -}}
{{- end -}}

{{/*
Derive an SNI/verification name from a host:port upstream address.
*/}}
{{- define "tls-lb.serverNameFromAddress" -}}
{{- $serverName := regexReplaceAll `^\[([^\]]+)\](?::[0-9]+)?$` . "${1}" -}}
{{- regexReplaceAll `^([^:]+)(?::[0-9]+)?$` $serverName "${1}" -}}
{{- end -}}

{{/*
Validate the proxy TLS settings for an HTTPS backend (the default upstream or a
route backend). Fails the render on values that would be silently ignored or
break out of the generated nginx directives. Args: protocol, tls (dict),
serverName, trustedCAPath, label.
*/}}
{{- define "tls-lb.validateProxyTLS" -}}
{{- $tls := default dict .tls -}}
{{- range $k := list "verify" "useCDSClientCert" -}}
{{- if and (hasKey $tls $k) (not (kindIs "bool" (index $tls $k))) -}}
{{- fail (printf "%s.tls.%s must be a boolean; do not set it via --set-string, got: %v" $.label $k (index $tls $k)) -}}
{{- end -}}
{{- end -}}
{{- if hasKey $tls "verifyDepth" -}}
{{- if not (regexMatch `^[0-9]+$` (printf "%v" $tls.verifyDepth)) -}}
{{- fail (printf "%s.tls.verifyDepth must be a non-negative integer, got: %v" $.label $tls.verifyDepth) -}}
{{- end -}}
{{- end -}}
{{- if eq $.protocol "https" -}}
{{- if not (regexMatch `^[^[:space:]{};/#]+$` $.serverName) -}}
{{- fail (printf "%s.tls.serverName must not contain whitespace, semicolons, braces, slashes, or '#', got: %s" $.label $.serverName) -}}
{{- end -}}
{{- if (default false $tls.verify) -}}
{{- if not (regexMatch `^/[^[:space:]{};]+$` $.trustedCAPath) -}}
{{- fail (printf "%s.tls.trustedCAPath must be an absolute path without whitespace, semicolons, or braces, got: %s" $.label $.trustedCAPath) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Render nginx proxy TLS directives for an HTTPS backend.
*/}}
{{- define "tls-lb.proxySSLDirectives" -}}
{{- if eq .protocol "https" -}}
{{- $tls := default dict .tls -}}
{{- if (default false $tls.useCDSClientCert) }}
proxy_ssl_certificate {{ .tlsMountPath }}/cert.pem;
proxy_ssl_certificate_key {{ .tlsMountPath }}/key.pem;
{{- end }}
proxy_ssl_server_name on;
proxy_ssl_name {{ .serverName }};
{{- if (default false $tls.verify) }}
{{- $verifyDepth := 2 }}
{{- if hasKey $tls "verifyDepth" }}{{- $verifyDepth = $tls.verifyDepth }}{{- end }}
proxy_ssl_verify on;
proxy_ssl_verify_depth {{ $verifyDepth }};
proxy_ssl_trusted_certificate {{ .trustedCAPath }};
{{- else }}
proxy_ssl_verify off;
{{- end }}
{{- end -}}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "tls-lb.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tls-lb.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Path to the public-TLS certificate nginx serves. Resolves to the
operator-provided publicTLS secret when set, otherwise the CDS-issued
cert under tlsMountPath.
*/}}
{{- define "tls-lb.publicCertPath" -}}
{{- if .Values.tlsLb.publicTLS.secretName -}}
{{- printf "%s/%s" .Values.tlsLb.publicTLS.mountPath .Values.tlsLb.publicTLS.certKey -}}
{{- else -}}
{{- printf "%s/cert.pem" .Values.tlsLb.tlsMountPath -}}
{{- end -}}
{{- end -}}

{{- define "tls-lb.publicKeyPath" -}}
{{- if .Values.tlsLb.publicTLS.secretName -}}
{{- printf "%s/%s" .Values.tlsLb.publicTLS.mountPath .Values.tlsLb.publicTLS.keyKey -}}
{{- else -}}
{{- printf "%s/key.pem" .Values.tlsLb.tlsMountPath -}}
{{- end -}}
{{- end -}}

{{- define "tls-lb.discoveryFilePath" -}}
{{- printf "%s/%s" .Values.tlsLb.discovery.mountPath .Values.tlsLb.discovery.fileName -}}
{{- end -}}

{{/*
c8s sidecar-injection annotations consumed by the c8s admission webhook
(internal/webhook/pod_mutator.go). Caller must nindent into the Pod template
metadata annotations.
*/}}
{{- define "tls-lb.c8s-annotations" -}}
{{- $publicTLSMode := "cds" -}}
{{- if .Values.tlsLb.publicTLS.secretName -}}{{- $publicTLSMode = "webpki" -}}{{- end -}}
confidential.ai/cw: {{ include "tls-lb.san" . | quote }}
confidential.ai/c8s-cert-volume: "tls-certs"
confidential.ai/c8s-cert-dir: {{ .Values.tlsLb.tlsMountPath | quote }}
confidential.ai/c8s-cert-file: "cert.pem"
confidential.ai/c8s-key-file: "key.pem"
confidential.ai/c8s-renew-interval: {{ .Values.tlsLb.certProvisioning.renewInterval | quote }}
confidential.ai/c8s-reload-nginx: "true"
confidential.ai/c8s-get-cert-run-as-user: {{ .Values.tlsLb.nginx.runAsUser | quote }}
confidential.ai/c8s-get-cert-run-as-group: {{ .Values.tlsLb.nginx.runAsGroup | quote }}
{{- /* webhook default already matches runAsNonRoot=true; emit only on override. */ -}}
{{- if not .Values.tlsLb.nginx.runAsNonRoot }}
confidential.ai/c8s-get-cert-run-as-non-root: "false"
{{- end }}
{{- if .Values.tlsLb.certProvisioning.verbose }}
confidential.ai/c8s-get-cert-verbose: "true"
{{- end }}
{{- if .Values.tlsLb.publicTLS.secretName }}
confidential.ai/c8s-reload-watch-volume: "public-tls"
confidential.ai/c8s-reload-watch-mount-path: {{ .Values.tlsLb.publicTLS.mountPath | quote }}
confidential.ai/c8s-reload-watch-paths: {{ printf "%s,%s" (include "tls-lb.publicCertPath" .) (include "tls-lb.publicKeyPath" .) | quote }}
{{- end }}
{{- if .Values.tlsLb.discovery.enabled }}
confidential.ai/c8s-discovery-volume: "discovery"
confidential.ai/c8s-discovery-mount-path: {{ .Values.tlsLb.discovery.mountPath | quote }}
confidential.ai/c8s-discovery-out: {{ include "tls-lb.discoveryFilePath" . | quote }}
confidential.ai/c8s-discovery-cds-cert-url: {{ .Values.tlsLb.discovery.cdsCertPath | quote }}
confidential.ai/c8s-discovery-public-tls-mode: {{ $publicTLSMode | quote }}
{{- if .Values.tlsLb.meshCA.expose }}
confidential.ai/c8s-discovery-mesh-ca-url: {{ .Values.tlsLb.discovery.meshCAPath | quote }}
{{- end }}
{{- end }}
{{- end }}
