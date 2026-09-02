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
The tlsLb.san list, defaulted. Empty -> the chart-managed Service DNS name
(<release>-tls-lb.<namespace>.svc) as a single entry. The first entry is the
CDS mesh-cert identity (see tls-lb.san); the whole list is joined into nginx
server_name by tls-lb-configmap.yaml. Fails if san is set but not a list.
*/}}
{{- define "tls-lb.sanList" -}}
{{- $san := .Values.tlsLb.san -}}
{{- if not (kindIs "slice" $san) -}}
{{- fail (printf "tlsLb.san must be a list of hostnames, got %s: %v" (kindOf $san) $san) -}}
{{- end -}}
{{- if $san -}}
{{- toJson $san -}}
{{- else -}}
{{- toJson (list (printf "%s.%s.svc" (include "tls-lb.fullname" .) .Release.Namespace)) -}}
{{- end -}}
{{- end -}}

{{/*
The single identity baked into the CDS-issued mesh cert (get-cert) and validated
by cds.dnsSanPatterns: the first entry of tls-lb.sanList. Extra san entries
widen only nginx server_name, not the mesh cert.
*/}}
{{- define "tls-lb.san" -}}
{{- first (include "tls-lb.sanList" . | fromJsonArray) -}}
{{- end -}}

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
tls-lb.requireSecuredBackend fails the render on a proxied backend hop that is
not authenticated: plaintext http, or https without tls.verify. A confidential
platform has exactly two safe paths to a backend and this helper admits only
them: an adopted workload (a mesh-wrapped headless Service, validated separately),
or an https backend that terminates and verifies TLS itself (app-TLS). There is
no plaintext-to-unattested escape hatch. Shared by the catch-all upstream and
every route backend so the invariant lives in one place.
Args: protocol, tls (dict), address, label, kind, suggest (leading hint prose,
may be "").
*/}}
{{- define "tls-lb.requireSecuredBackend" -}}
{{- $tls := default dict .tls -}}
{{- $secured := and (eq .protocol "https") (default false $tls.verify) -}}
{{- if not $secured -}}
{{- fail (printf "VALIDATION_ERROR kind=%s: %s.address=%q is a plaintext http or unverified-https hop the chart cannot confirm the node mesh wraps. %sUse https with tls.verify=true so the backend authenticates itself (app-TLS)" .kind .label .address .suggest) -}}
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
Return true when the built-in /allowlist route renders: allowlist.enabled is a
real bool set to true and no legacy typed route owns /allowlist. The nginx
locations, the loopback proxy sidecar, and the Service traffic policy must all
flip on this one predicate.
*/}}
{{- define "tls-lb.renderAllowlistRoute" -}}
{{- if not (kindIs "bool" .Values.tlsLb.allowlist.enabled) -}}
{{- fail (printf "tlsLb.allowlist.enabled must be a boolean; do not set it via --set-string, got: %v" .Values.tlsLb.allowlist.enabled) -}}
{{- end -}}
{{- and .Values.tlsLb.allowlist.enabled (ne (include "tls-lb.hasExplicitAllowlistRoute" .) "true") -}}
{{- end -}}

{{/*
Return true when a legacy typed route owns /allowlist. Such a route suppresses
both the built-in nginx locations and their loopback proxy sidecar.
*/}}
{{- define "tls-lb.hasExplicitAllowlistRoute" -}}
{{- $found := false -}}
{{- range $route := .Values.tlsLb.routes -}}
{{- $path := toString (default "" $route.path) -}}
{{- if or (eq $path "/allowlist") (eq $path "/allowlist/") -}}
{{- $found = true -}}
{{- end -}}
{{- end -}}
{{- $found -}}
{{- end -}}

{{/*
Render one half of the built-in CDS allowlist route. The caller emits an exact
/allowlist location and a /allowlist/ prefix location so unrelated paths such
as /allowlisted never reach the loopback proxy. proxy_pass includes $request_uri
explicitly: operator authorization signs the HTTP method, exact path, and body,
so nginx must not normalize or replace the path before CDS verifies the token.

The loopback proxy verifies CDS's RA-TLS evidence. Stock nginx cannot verify
the attestation extension itself, so it must never dial CDS directly here.

Args: root, exact (bool), path, proxyPort, writeBurst, writeTotalBurst,
readBurst — the numeric args arrive pre-validated by the configmap prologue.
*/}}
{{- define "tls-lb.allowlistLocation" -}}
{{- $root := .root -}}
location{{ if .exact }} ={{ end }} {{ .path }} {
    {{- if default false $root.Values.tlsLb.cors.enabled }}
    {{- include "tls-lb.corsLocationDirectives" $root.Values.tlsLb.cors | nindent 4 }}
    {{- else if eq (include "tls-lb.protocolCorsEnabled" $root) "true" }}
    {{- include "tls-lb.protocolCorsLocationDirectives" $root | nindent 4 }}
    {{- end }}
    # These run before nginx collapses callers onto the loopback proxy source.
    # Each zone's map key is empty for the methods it does not cover, so
    # mutations count per client and in aggregate, reads per client only.
    limit_req zone=allowlist_write_per_client burst={{ .writeBurst }} nodelay;
    limit_req zone=allowlist_write_total burst={{ .writeTotalBurst }} nodelay;
    limit_req zone=allowlist_read_per_client burst={{ .readBurst }} nodelay;
    limit_req_status 429;
    proxy_pass http://127.0.0.1:{{ .proxyPort }}$request_uri;
    proxy_set_header Host $host;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
{{- end -}}

{{/*
Validate the global CORS configuration. Skips when disabled.
*/}}
{{- define "tls-lb.validateCORS" -}}
{{- $cors := default dict . -}}
{{- if hasKey $cors "enabled" -}}
{{- if not (kindIs "bool" $cors.enabled) -}}
{{- fail (printf "tlsLb.cors.enabled must be a boolean; do not set it via --set-string, got: %v" $cors.enabled) -}}
{{- end -}}
{{- end -}}
{{- if hasKey $cors "protocolEndpoints" -}}
{{- if not (kindIs "bool" $cors.protocolEndpoints) -}}
{{- fail (printf "tlsLb.cors.protocolEndpoints must be a boolean; do not set it via --set-string, got: %v" $cors.protocolEndpoints) -}}
{{- end -}}
{{- end -}}
{{- if default false $cors.enabled -}}
{{- $origins := default (list) $cors.allowOrigins -}}
{{- if not $origins -}}
{{- fail "tlsLb.cors.enabled=true requires tlsLb.cors.allowOrigins to be non-empty" -}}
{{- end -}}
{{- range $o := $origins -}}
{{- if not (or (eq $o "*") (regexMatch `^https?://[A-Za-z0-9.-]+(?::[0-9]+)?$` $o)) -}}
{{- fail (printf "tlsLb.cors.allowOrigins entry %q must be \"*\" or a scheme://host[:port] URL" $o) -}}
{{- end -}}
{{- end -}}
{{- if and (default false $cors.allowCredentials) (has "*" $origins) -}}
{{- fail "tlsLb.cors.allowCredentials=true is incompatible with allowOrigins containing \"*\" (browsers reject this combination)" -}}
{{- end -}}
{{- range $field := list "allowMethods" "allowHeaders" "exposeHeaders" -}}
{{- range $v := default (list) (index $cors $field) -}}
{{- if regexMatch `[\r\n";{}\\]` $v -}}
{{- fail (printf "tlsLb.cors.%s entry %q must not contain CR, LF, quotes, semicolons, braces, or backslashes" $field $v) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if hasKey $cors "maxAge" -}}
{{- if not (regexMatch `^[0-9]+$` (printf "%v" $cors.maxAge)) -}}
{{- fail (printf "tlsLb.cors.maxAge must be a non-negative integer, got: %v" $cors.maxAge) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Validate a per-route CORS override. Only the `enabled` field is honored;
shared knobs live on tlsLb.cors. Args: dict { "cors": route.cors, "label": ... }.
*/}}
{{- define "tls-lb.validateRouteCORS" -}}
{{- if .cors -}}
{{- $cors := .cors -}}
{{- range $k, $_ := $cors -}}
{{- if ne $k "enabled" -}}
{{- fail (printf "%s.cors only supports the `enabled` field; remove %q (configure shared CORS knobs under tlsLb.cors)" $.label $k) -}}
{{- end -}}
{{- end -}}
{{- if hasKey $cors "enabled" -}}
{{- if not (kindIs "bool" $cors.enabled) -}}
{{- fail (printf "%s.cors.enabled must be a boolean; do not set it via --set-string, got: %v" $.label $cors.enabled) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Render the http-level CORS maps. `$cors_origin` echoes a matching request
Origin from tlsLb.cors.allowOrigins. The remaining maps implement
upstream-pass-through: when the upstream emits Access-Control-Allow-Origin
we adopt its full CORS header set verbatim (so browsers never see duplicate
headers); otherwise we fall back to tls-lb's configured values.

Access-Control-Expose-Headers is the one exception: tls-lb's configured
exposeHeaders are ALWAYS advertised (and merged in front of upstream's
value when in pass-through mode), so browsers can read custom response
headers the upstream does not know to advertise.

Emitted only when CORS is enabled. Caller nindents into the nginx `http {}`
context.
*/}}
{{- define "tls-lb.corsMap" -}}
{{- $cors := default dict .Values.tlsLb.cors -}}
{{- if default false $cors.enabled -}}
{{- $origins := default (list) $cors.allowOrigins -}}
{{- $methods := join ", " (default (list "GET" "POST" "OPTIONS") $cors.allowMethods) -}}
{{- $headers := join ", " (default (list "Authorization" "Content-Type" "X-C8s-Session") $cors.allowHeaders) -}}
{{- $exposeHeaders := default (list) $cors.exposeHeaders -}}
{{- $credentials := ternary "true" "" (default false $cors.allowCredentials) }}
map $http_origin $cors_origin {
{{- if has "*" $origins }}
    default "*";
{{- else }}
    default "";
{{- range $o := $origins }}
    "{{ $o }}" "{{ $o }}";
{{- end }}
{{- end }}
}

map $upstream_http_access_control_allow_origin $cors_passthrough {
    default "0";
    "~.+"   "1";
}

map $cors_passthrough $cors_out_origin {
    "0" $cors_origin;
    "1" $upstream_http_access_control_allow_origin;
}

map $cors_passthrough $cors_out_methods {
    "0" "{{ $methods }}";
    "1" $upstream_http_access_control_allow_methods;
}

map $cors_passthrough $cors_out_headers {
    "0" "{{ $headers }}";
    "1" $upstream_http_access_control_allow_headers;
}

map $cors_passthrough $cors_out_credentials {
    "0" "{{ $credentials }}";
    "1" $upstream_http_access_control_allow_credentials;
}

{{- if $exposeHeaders }}
map $upstream_http_access_control_expose_headers $cors_upstream_expose_suffix {
    default "";
    "~.+"   ", $upstream_http_access_control_expose_headers";
}

map $cors_passthrough $cors_out_expose {
    "0" "{{ join ", " $exposeHeaders }}";
    "1" "{{ join ", " $exposeHeaders }}$cors_upstream_expose_suffix";
}
{{- else }}
map $cors_passthrough $cors_out_expose {
    "0" "";
    "1" $upstream_http_access_control_expose_headers;
}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
Render per-location CORS directives. Non-preflight responses go through
$cors_out_* — either the upstream's CORS headers (passed through unchanged)
or tls-lb's configured ones, never both. proxy_hide_header drops the
upstream copies so the maps' re-emitted version is the only one on the
wire. Preflight OPTIONS short-circuits at nginx with tls-lb's configured
policy. Caller passes the effective CORS dict and guarantees CORS is
enabled. Caller nindents into a `location {}` block.
*/}}
{{- define "tls-lb.corsLocationDirectives" -}}
{{- $cors := default dict . -}}
{{- $methods := join ", " (default (list "GET" "POST" "OPTIONS") $cors.allowMethods) -}}
{{- $headers := join ", " (default (list "Authorization" "Content-Type" "X-C8s-Session") $cors.allowHeaders) -}}
{{- $maxAge := default 600 $cors.maxAge }}
proxy_hide_header Access-Control-Allow-Origin;
proxy_hide_header Access-Control-Allow-Methods;
proxy_hide_header Access-Control-Allow-Headers;
proxy_hide_header Access-Control-Allow-Credentials;
proxy_hide_header Access-Control-Expose-Headers;
if ($request_method = 'OPTIONS') {
    add_header Access-Control-Allow-Origin  $cors_origin always;
    add_header Access-Control-Allow-Methods "{{ $methods }}" always;
    add_header Access-Control-Allow-Headers "{{ $headers }}" always;
{{- if default false $cors.allowCredentials }}
    add_header Access-Control-Allow-Credentials "true" always;
{{- end }}
    add_header Access-Control-Max-Age       "{{ $maxAge }}" always;
    add_header Content-Length 0;
    return 204;
}
add_header Access-Control-Allow-Origin      $cors_out_origin always;
add_header Access-Control-Allow-Methods     $cors_out_methods always;
add_header Access-Control-Allow-Headers     $cors_out_headers always;
add_header Access-Control-Allow-Credentials $cors_out_credentials always;
add_header Access-Control-Expose-Headers    $cors_out_expose always;
{{- end -}}

{{/*
Whether the c8s protocol-owned locations get the built-in wide-open CORS
block: tlsLb.cors.protocolEndpoints (default true), unless the operator's
global CORS block is enabled — an explicit policy already covers every
location, so the built-in one steps aside. hasKey instead of `default`
because sprig's default treats an explicit false as unset.
*/}}
{{- define "tls-lb.protocolCorsEnabled" -}}
{{- $cors := default dict .Values.tlsLb.cors -}}
{{- $pe := true -}}
{{- if hasKey $cors "protocolEndpoints" -}}{{- $pe = $cors.protocolEndpoints -}}{{- end -}}
{{- and $pe (not (default false $cors.enabled)) -}}
{{- end -}}

{{/*
Render wide-open CORS directives for a c8s protocol-owned location (the
attestation/handshake/tunnel namespace, the discovery document and
certificate endpoints, the built-in allowlist route). These endpoints exist
to be verified by any browser anywhere: every response is either
self-authenticating (hardware evidence, CDS-signed certificates, sealed
tunnel records) or public by design, and no request relies on ambient
browser credentials (allowlist mutations are operator-signed over method,
path, and body). An origin allowlist here cannot protect anything and only
breaks third-party verifiers, so the policy is a constant: any origin, no
credentials. Self-contained on purpose — no http-level maps and no
upstream pass-through; these endpoints are c8s-owned end to end, so tls-lb
states their CORS policy itself. Caller nindents into a `location {}`
block.
*/}}
{{- define "tls-lb.protocolCorsLocationDirectives" -}}
proxy_hide_header Access-Control-Allow-Origin;
proxy_hide_header Access-Control-Allow-Methods;
proxy_hide_header Access-Control-Allow-Headers;
proxy_hide_header Access-Control-Allow-Credentials;
proxy_hide_header Access-Control-Expose-Headers;
if ($request_method = 'OPTIONS') {
    add_header Access-Control-Allow-Origin  "*" always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Authorization, Content-Type, X-C8s-Session" always;
    add_header Access-Control-Max-Age       "600" always;
    add_header Content-Length 0;
    return 204;
}
add_header Access-Control-Allow-Origin "*" always;
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "tls-lb.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tls-lb.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The validated public front-door mode: cds | webpki | acme. Fails the render on
a mode/values mismatch: webpki needs the Secret and is the only mode that may
carry one; acme needs a TEE-held key (kata or node-CVM), a reachable :80
challenge (the kata guest exempts only tcp:8443 from the inbound mesh
redirect, so no acme under kata), and HTTP-01-issuable sanList entries.
*/}}
{{- define "tls-lb.publicTLSMode" -}}
{{- $mode := printf "%v" .Values.tlsLb.publicTLS.mode -}}
{{- if not (has $mode (list "cds" "webpki" "acme")) -}}
{{- fail (printf "tlsLb.publicTLS.mode must be cds, webpki, or acme, got: %s" $mode) -}}
{{- end -}}
{{- if and (eq $mode "webpki") (not .Values.tlsLb.publicTLS.secretName) -}}
{{- fail "tlsLb.publicTLS.mode=webpki requires tlsLb.publicTLS.secretName" -}}
{{- end -}}
{{- if and (ne $mode "webpki") .Values.tlsLb.publicTLS.secretName -}}
{{- fail (printf "tlsLb.publicTLS.secretName is set but tlsLb.publicTLS.mode is %q; set mode=webpki to serve the Secret, or clear secretName" $mode) -}}
{{- end -}}
{{- if eq $mode "acme" -}}
{{- if not (or .Values.kata.enabled (eq .Values.attestationApi.cvmMode "node")) -}}
{{- fail "VALIDATION_ERROR kind=tlslb_acme_runtime: tlsLb.publicTLS.mode=acme requires a confidential runtime (kata.enabled=true or attestationApi.cvmMode=node) so the ACME account and serving keys are TEE-held" -}}
{{- end -}}
{{- if .Values.kata.enabled -}}
{{- fail "VALIDATION_ERROR kind=tlslb_acme_kata_port: tlsLb.publicTLS.mode=acme cannot render under kata.enabled: the guest exempts only tcp:8443 from the inbound mesh redirect (C8S_MESH_INBOUND_PASSTHROUGH), so the HTTP-01 challenge on :80 never reaches nginx. Use the node-CVM shape (attestationApi.cvmMode=node)" -}}
{{- end -}}
{{- range $s := (include "tls-lb.sanList" . | fromJsonArray) -}}
{{- if contains "*" $s -}}
{{- fail (printf "tlsLb.publicTLS.mode=acme cannot issue for wildcard san %q: HTTP-01 forbids wildcards" $s) -}}
{{- end -}}
{{- end -}}
{{- if and (not .Values.tlsLb.hostPort.enabled) (eq .Values.tlsLb.service.type "ClusterIP") -}}
{{- fail "VALIDATION_ERROR kind=tlslb_acme_front_door: tlsLb.publicTLS.mode=acme needs an internet-reachable front door for the HTTP-01 challenge: set tlsLb.service.type=LoadBalancer (any LB implementation: cloud controller, MetalLB, kube-vip, ...) or tlsLb.hostPort.enabled=true" -}}
{{- end -}}
{{- end -}}
{{- $mode -}}
{{- end -}}

{{/*
ACME constants shared by the acme sidecar args, the deployment mounts, the
nginx :80 server, and the cert-path helpers below.
*/}}
{{- define "tls-lb.acmeCertDir" -}}/etc/c8s-acme-tls{{- end -}}
{{- define "tls-lb.acmeChallengePort" -}}8402{{- end -}}
{{- define "tls-lb.acmeHTTPPort" -}}8080{{- end -}}

{{/*
Path to the public-TLS certificate nginx serves: the publicTLS Secret
(webpki), the sidecar-issued ACME leaf (acme), or the CDS-issued cert under
tlsMountPath (cds).
*/}}
{{- define "tls-lb.publicCertPath" -}}
{{- $mode := include "tls-lb.publicTLSMode" . -}}
{{- if eq $mode "webpki" -}}
{{- printf "%s/%s" .Values.tlsLb.publicTLS.mountPath .Values.tlsLb.publicTLS.certKey -}}
{{- else if eq $mode "acme" -}}
{{- printf "%s/cert.pem" (include "tls-lb.acmeCertDir" .) -}}
{{- else -}}
{{- printf "%s/cert.pem" .Values.tlsLb.tlsMountPath -}}
{{- end -}}
{{- end -}}

{{- define "tls-lb.publicKeyPath" -}}
{{- $mode := include "tls-lb.publicTLSMode" . -}}
{{- if eq $mode "webpki" -}}
{{- printf "%s/%s" .Values.tlsLb.publicTLS.mountPath .Values.tlsLb.publicTLS.keyKey -}}
{{- else if eq $mode "acme" -}}
{{- printf "%s/key.pem" (include "tls-lb.acmeCertDir" .) -}}
{{- else -}}
{{- printf "%s/key.pem" .Values.tlsLb.tlsMountPath -}}
{{- end -}}
{{- end -}}

{{- define "tls-lb.discoveryFilePath" -}}
{{- printf "%s/%s" .Values.tlsLb.discovery.mountPath .Values.tlsLb.discovery.fileName -}}
{{- end -}}

{{/*
tls-lb's discovery + verbose get-cert args, as a YAML list (one arg per line)
for c8s.getCertContainers' extraArgs. tls-lb owns its own cert provisioning,
so it adds discovery output and verbose logging to the shared get-cert flow.
*/}}
{{- define "tls-lb.getCertCommonArgs" -}}
{{- if .Values.tlsLb.discovery.enabled }}
- --discovery-out={{ include "tls-lb.discoveryFilePath" . }}
- --discovery-cds-cert-url={{ .Values.tlsLb.discovery.cdsCertPath }}
- --discovery-public-tls-mode={{ include "tls-lb.publicTLSMode" . }}
{{- if .Values.tlsLb.meshCA.expose }}
- --discovery-mesh-ca-url={{ .Values.tlsLb.discovery.meshCAPath }}
{{- end }}
{{- end }}
{{- with .Values.tlsLb.certProvisioning.caWatchInterval }}
- --ca-watch-interval={{ . }}
{{- end }}
{{- if .Values.tlsLb.certProvisioning.verbose }}
- --verbose
{{- end }}
{{- end }}

{{/*
"true" when the tls-lb pod must mount the node inventory's socket directory:
the readiness gate is on and this is the node-CVM shape. Under kata the
in-guest policy-monitor serves the inventory on loopback, so nothing is
mounted and the pod needs no socket group either.

The non-kata arm mirrors the operator's own inventory condition
(operator.yaml): the directory exists only where an installer put it, and a
`type: Directory` hostPath naming a path nothing created wedges the pod in
ContainerCreating. validations.yaml (kind=require_host_image_policy) makes that
arm true in every renderable non-kata shape today; the condition is spelled out
anyway so the two consumers of the socket stay on one rule.
*/}}
{{- define "tls-lb.mountInventorySocket" -}}
{{- if and .Values.tlsLb.attest.expectedWorkload (not .Values.kata.enabled) (or .Values.nriImagePolicy.enabled (eq .Values.attestationApi.cvmMode "node")) -}}
true
{{- end -}}
{{- end -}}

{{/*
c8s-cert native sidecar (restartPolicy: Always): obtains the leaf on startup
and renews it on a ticker, SIGHUP-ing nginx after each renewal. Long-lived so
its PID namespace can anchor shareProcessNamespace under kata (see
c8s.getCertContainers). Caller nindents into the Pod spec's initContainers
list.
*/}}
{{- define "tls-lb.getCertContainers" -}}
{{- $mounts := list -}}
{{- if .Values.tlsLb.discovery.enabled -}}
{{- $mounts = append $mounts (printf "- name: discovery\n  mountPath: %s" .Values.tlsLb.discovery.mountPath) -}}
{{- end -}}
{{- if eq (include "c8s.attestationApiHostSocket" .) "true" -}}
{{- $mounts = append $mounts (printf "- name: attestation-api-socket\n  mountPath: %s\n  readOnly: true" .Values.nriImagePolicy.hostPaths.runtimeDir) -}}
{{- end -}}
{{- $extraArgs := include "tls-lb.getCertCommonArgs" . | fromYamlArray -}}
{{- if .Values.tlsLb.attest.expectedWorkload -}}
{{- /* The readiness gate (cds-attest /readyz) demands a matched-workload
       stamp on the mesh leaf, which only exists when get-cert redeems a
       sandbox token from the inventory — so wire the claims flow whenever
       the gate is enabled (the deployment fails the render if the gate is
       set without the sidecar it gates). Node-CVM mounts the inventory
       socket directory at get-cert's compiled path
       (workloadclaims.SidecarSocketDir); the kata guest serves it on
       loopback instead, nothing to mount. The deployment adds the hostPath
       volume and the socket's supplemental group
       (workloadclaims.InventorySocketGID) on the same condition. */ -}}
{{- $extraArgs = append $extraArgs "--workload-claims" -}}
{{- if .Values.kata.enabled -}}
{{- $extraArgs = append $extraArgs "--workload-claims-guest" -}}
{{- else if eq (include "tls-lb.mountInventorySocket" .) "true" -}}
{{- $mounts = append $mounts "- name: workload-claims\n  mountPath: /run/c8s/workload-claims\n  readOnly: true" -}}
{{- end -}}
{{- end -}}
{{- if eq (include "tls-lb.publicTLSMode" .) "webpki" -}}
{{- $mounts = append $mounts (printf "- name: public-tls\n  mountPath: %s\n  readOnly: true" .Values.tlsLb.publicTLS.mountPath) -}}
{{- $extraArgs = append $extraArgs (printf "--reload-watch=%s" (include "tls-lb.publicCertPath" .)) -}}
{{- $extraArgs = append $extraArgs (printf "--reload-watch=%s" (include "tls-lb.publicKeyPath" .)) -}}
{{- end -}}
{{- include "c8s.getCertContainers" (dict
  "root" .
  "san" (include "tls-lb.san" .)
  "certOut" (printf "%s/cert.pem" .Values.tlsLb.tlsMountPath)
  "keyOut" (printf "%s/key.pem" .Values.tlsLb.tlsMountPath)
  "caOut" (printf "%s/ca.pem" .Values.tlsLb.tlsMountPath)
  "volume" "tls-certs"
  "mountPath" .Values.tlsLb.tlsMountPath
  "renewInterval" .Values.tlsLb.certProvisioning.renewInterval
  "keyMode" "0640"
  "runAsUser" .Values.tlsLb.nginx.runAsUser
  "runAsGroup" .Values.tlsLb.nginx.runAsGroup
  "runAsNonRoot" .Values.tlsLb.nginx.runAsNonRoot
  "reloadNginx" "true"
  "extraArgs" $extraArgs
  "extraMounts" (join "\n" $mounts)
) -}}
{{- end }}

{{/*
tls-lb.meshWrappedUpstream — "true" when the address is an operator-managed
headless Service (c8s-<id>.<ns>.svc.cluster.local:<port>, the exact
webhook.WorkloadServiceFQDN form). c8s-<id> is a DNS-1035 label, <ns> a
DNS-1123 label. That shape is the one upstream whose backing pod IPs churn, so
it is dialed through a variable and re-resolved per request; every other
address gets a static upstream block resolved once at startup. validations.yaml
(kind=workload_https_upstream, kind=tlslb_unsecured_upstream) branches on the
same predicate. Call with the address string.
*/}}
{{- define "tls-lb.meshWrappedUpstream" -}}
{{- if regexMatch "^c8s-[a-z]([-a-z0-9]*[a-z0-9])?\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?\\.svc\\.cluster\\.local:[0-9]+$" . -}}
true
{{- end -}}
{{- end -}}
