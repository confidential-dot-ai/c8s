{{/*
  Shared helpers for the c8s shape charts. Named templates here render full
  manifests (the c8s-lib.<component> files) or derive shared values. Keep the
  shape vocabulary out of this file: a helper reads plain values (platform,
  attestation.url, the presence of a kata/attestationApi section), never a
  shape name.
*/}}

{{- define "c8s-lib.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s-lib.operatorName" -}}
{{- printf "%s-operator" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s-lib.attestationApiName" -}}
{{- printf "%s-attestation-api" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s-lib.cdsName" -}}
{{- printf "%s-cds" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "c8s-lib.volumedName" -}}
{{- printf "%s-volumed" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* int64 (fixes float64 -f values rendering as 7e+06) + reject non-ints so a
   bad -f can't fall open to UID 0. */}}
{{- define "c8s-lib.int" -}}
{{- if and (not (kindIs "int" .)) (not (kindIs "float64" .)) (not (regexMatch "^-?[0-9]+$" (toString .))) -}}
{{- fail (printf "expected an integer, got %q" (toString .)) -}}
{{- end -}}
{{- int64 . -}}
{{- end -}}

{{/* Positive integer or fail with the value's label. Args: value, label. */}}
{{- define "c8s-lib.positiveInt" -}}
{{- if not (regexMatch `^[1-9][0-9]*$` (toString .value)) -}}
{{- fail (printf "%s must be a positive integer, got: %v" .label .value) -}}
{{- end -}}
{{- toString .value -}}
{{- end -}}

{{/*
  Image refs prefer digest when set — floating tags silently drift the
  binary running inside the TEE and invalidate the measurement allowlist.
  The charts do not ship a default tag; the consumer (c8s install CLI
  or fleet HelmRelease) must supply either tag or digest, otherwise the
  helper fails rendering rather than producing a silently-broken manifest.
*/}}
{{- define "c8s-lib.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else if .Values.image.tag -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- else -}}
{{ fail "image.tag or image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s-lib.attestationApiImage" -}}
{{- if .Values.attestationApi.image.digest -}}
{{ .Values.attestationApi.image.repository }}@{{ .Values.attestationApi.image.digest }}
{{- else if .Values.attestationApi.image.tag -}}
{{ .Values.attestationApi.image.repository }}:{{ .Values.attestationApi.image.tag }}
{{- else -}}
{{ fail "attestationApi.image.tag or attestationApi.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{- define "c8s-lib.cdsImage" -}}
{{- if .Values.cds.image.digest -}}
{{ .Values.cds.image.repository }}@{{ .Values.cds.image.digest }}
{{- else if .Values.cds.image.tag -}}
{{ .Values.cds.image.repository }}:{{ .Values.cds.image.tag }}
{{- else -}}
{{ fail "cds.image.tag or cds.image.digest must be set" }}
{{- end -}}
{{- end -}}

{{/*
  Image reference with digest support. Usage:
  {{ include "c8s-lib.common.image" .Values.<x>.image }}
*/}}
{{- define "c8s-lib.common.image" -}}
{{- $img := . -}}
{{- if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else -}}
{{ $img.repository }}:{{ required (printf "image.tag or image.digest is required for %s" $img.repository) $img.tag }}
{{- end -}}
{{- end }}

{{/*
  Platform derivations. .Values.platform is one of snp | tdx | az-snp | az-tdx
  (pod and node-metal charts accept only snp | tdx). Everything else keys off
  it: the TEE device the attestation-api mounts, the RA-TLS platform strings
  CDS and the mesh embed in certs, and the kata RuntimeClass names in the pod
  chart. A cluster is one CPU TEE.
*/}}

{{/* teeFamily is the silicon family: snp or tdx, with the cloud vTPM variants
   (az-snp/az-tdx) normalized onto their underlying TEE. */}}
{{- define "c8s-lib.teeFamily" -}}
{{- if has .Values.platform (list "snp" "az-snp") -}}
snp
{{- else if has .Values.platform (list "tdx" "az-tdx") -}}
tdx
{{- else -}}
{{ fail (printf "platform must be one of snp, tdx, az-snp, az-tdx (got %q)" .Values.platform) }}
{{- end -}}
{{- end -}}

{{/* teeDevice selects the device mounts on the attestation-api DaemonSet:
   native guest ioctl on SNP/TDX, the vTPM pair on Azure. */}}
{{- define "c8s-lib.teeDevice" -}}
{{- if eq (include "c8s-lib.teeFamily" .) "snp" -}}
{{- if eq .Values.platform "az-snp" -}}tpm{{- else -}}sev-guest{{- end -}}
{{- else -}}
{{- if eq .Values.platform "az-tdx" -}}tpm{{- else -}}tdx{{- end -}}
{{- end -}}
{{- end -}}

{{/* The platform string CDS embeds in its RA-TLS certs (snp|tdx). */}}
{{- define "c8s-lib.ratlsPlatform" -}}
{{ include "c8s-lib.teeFamily" . }}
{{- end -}}

{{/* The platform string ratls-mesh embeds in mesh certs (sev-snp|tdx). */}}
{{- define "c8s-lib.meshPlatform" -}}
{{- if eq (include "c8s-lib.teeFamily" .) "snp" -}}sev-snp{{- else -}}tdx{{- end -}}
{{- end -}}

{{/* tls-lb attestation sidecar platform/generation: the evidence shape the
   sidecar requests from the attestation-api (az-* ride the vTPM). generation
   is AMD-only and meaningful only for bare SNP — az-snp auto-detects from the
   report CPUID and TDX has no such concept — so it renders only there. */}}
{{- define "c8s-lib.attestPlatform" -}}
{{ .Values.platform }}
{{- end -}}

{{- define "c8s-lib.attestGeneration" -}}
{{- if eq .Values.platform "snp" -}}
{{ .Values.tlsLb.attest.generation }}
{{- end -}}
{{- end -}}

{{/*
  c8s-lib.kata is "true" in the pod chart (the only chart with a kata
  section): workloads run as kata CVMs, the host-side attestation/mesh/policy
  components are baked into the guest image instead, and chart-managed pods
  that must be confidential (CDS, tls-lb) pin a kata RuntimeClass directly.
*/}}
{{- define "c8s-lib.kata" -}}
{{- if .Values.kata -}}true{{- end -}}
{{- end -}}

{{/*
  RuntimeClass the pod chart pins on CDS / tls-lb control-plane pods. They
  pin it directly rather than via the confidential.ai/cw webhook path: a
  get-cert sidecar would dial CDS, and CDS fetching a leaf from itself is a
  bootstrap cycle (docs/install-flows.md). Empty outside the pod chart.
*/}}
{{- define "c8s-lib.controlPlaneRuntimeClass" -}}
{{- if eq (include "c8s-lib.kata" .) "true" -}}
kata-qemu-{{ include "c8s-lib.teeFamily" . }}
{{- end -}}
{{- end -}}

{{/* kata guest-ready gate: confidential chart pods wait for the node's guest
   image to be reconciled. Only while the puller runs. */}}
{{- define "c8s-lib.kataGuestReadyGate" -}}
{{- if and (eq (include "c8s-lib.kata" .) "true") .Values.kata.guestImage.enabled -}}
true
{{- end -}}
{{- end -}}

{{- define "c8s-lib.kataGuestReadyAffinity" -}}
{{- if include "c8s-lib.kataGuestReadyGate" . }}
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

{{/*
  Attestation wiring, derived from the chart's shape: which optional sections
  the chart carries. Every consumer (CDS, operator, injected get-cert
  sidecars) reads c8s-lib.attestationURL.

    attestationApi section present (node-cloud, node-metal): the chart runs
      the attestation-api DaemonSet, whose attest-proxy sidecar serves a
      hostPath Unix socket in runtimeDir; consumers mount that directory.
    kata section present (pod): consumers run inside the CVM and dial the
      in-guest attestation-service on loopback.
    neither (node-image): the node image bakes a host-netns attestation-api;
      pod-netns consumers dial the node's own IP via the $(HOST_IP)
      downward-API env var c8s-lib.attestationHostIPEnv renders.
*/}}
{{- define "c8s-lib.attestationURL" -}}
{{- if .Values.attestationApi -}}
unix://{{ .Values.runtimeDir }}/attestation-api.sock
{{- else if .Values.kata -}}
http://127.0.0.1:{{ .Values.attestation.port }}
{{- else -}}
http://$(HOST_IP):{{ .Values.attestation.port }}
{{- end -}}
{{- end -}}

{{- define "c8s-lib.attestationSocket" -}}
{{- if .Values.attestationApi -}}
{{ .Values.runtimeDir }}/attestation-api.sock
{{- end -}}
{{- end -}}

{{/* hostPath pair a pod needs to reach the on-node socket. Mounted at the
   host path so c8s-lib.attestationURL is verbatim in-container. */}}
{{- define "c8s-lib.attestationSocketVolume" -}}
{{- if .Values.attestationApi }}
- name: attestation-api-socket
  hostPath:
    path: {{ .Values.runtimeDir }}
    type: DirectoryOrCreate
{{- end }}
{{- end -}}

{{- define "c8s-lib.attestationSocketMount" -}}
{{- if .Values.attestationApi }}
- name: attestation-api-socket
  mountPath: {{ .Values.runtimeDir }}
  readOnly: true
{{- end }}
{{- end -}}

{{/* HOST_IP downward-API env var for the node-image shape, expanding the
   $(HOST_IP) placeholder in c8s-lib.attestationURL. The operator forwards the
   URL verbatim to tenant get-cert sidecars, so it deliberately omits this env
   var; each tenant pod expands it against its own node. */}}
{{- define "c8s-lib.attestationHostIPEnv" -}}
{{- if and (not .Values.attestationApi) (not .Values.kata) -}}
- name: HOST_IP
  valueFrom:
    fieldRef:
      fieldPath: status.hostIP
{{- end -}}
{{- end -}}

{{- /*
The URL the host NRI plugin pulls the allowlist from. cds.service.nodePort is
the source; set nriImagePolicy.cds.url only to override the whole address.
*/ -}}
{{- define "c8s-lib.nriCDSURL" -}}
{{- if .Values.nriImagePolicy.cds.url -}}
{{ .Values.nriImagePolicy.cds.url }}
{{- else -}}
{{ printf "https://127.0.0.1:%d" (int .Values.cds.service.nodePort) }}
{{- end -}}
{{- end -}}

{{- define "c8s-lib.cdsURL" -}}
https://{{ include "c8s-lib.cdsName" . }}.{{ .Release.Namespace }}.svc:{{ .Values.cds.port }}
{{- end -}}

{{- define "c8s-lib.trustRootURL" -}}
{{ include "c8s-lib.cdsURL" . }}
{{- end -}}

{{/*
c8s-lib.getCertContainers renders the c8s-cert native sidecar (restartPolicy:
Always) a chart-owned component uses to self-provision and renew a CDS-issued
mesh cert over RA-TLS. Long-lived so its PID namespace can anchor
shareProcessNamespace (under kata the agent anchors on the first container's
pidns; a run-once init would let the anchor die). --key-out is idempotent
(load-or-generate), so kubelet restarts keep the cert chain.

Caller passes a dict:
  root            - the root context
  san             - --san for the cert (the workload identity / Service DNS name)
  certOut/keyOut  - --out / --key-out paths
  caOut           - optional --ca-out path for the mesh CA bundle (discovery)
  volume/mountPath - the writable cert volume and where to mount it
  renewInterval   - --renew-interval (Go duration string)
  keyMode         - --key-mode (octal)
  runAsUser/runAsGroup/runAsNonRoot - securityContext (match the consumer)
  reloadNginx     - "true"/"false": SIGHUP nginx on renewal (tls-lb only)
  extraArgs       - optional list of additional get-cert args
  extraMounts     - optional rendered volumeMount YAML
*/}}
{{- define "c8s-lib.getCertContainers" -}}
{{- $root := .root -}}
- name: c8s-cert
  image: {{ include "c8s-lib.image" $root }}
  imagePullPolicy: IfNotPresent
  restartPolicy: Always
  args:
    - get-cert
    - --cds-url={{ include "c8s-lib.cdsURL" $root }}
    - --attestation-api-url={{ include "c8s-lib.attestationURL" $root }}
    - --san={{ .san }}
    - --out={{ .certOut }}
    - --key-out={{ .keyOut }}
    - --key-mode={{ default "0640" .keyMode }}
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
  {{- with (include "c8s-lib.attestationHostIPEnv" $root) }}
  env:
    {{- . | nindent 4 }}
  {{- end }}
  volumeMounts:
    - name: {{ .volume }}
      mountPath: {{ .mountPath }}
    {{- with .extraMounts }}
    {{- . | nindent 4 }}
    {{- end }}
  # The workload is gated on the initial cert by the c8s-cert-wait init
  # container below, not a startupProbe here: a native sidecar is "started"
  # the moment its process launches, and an exec startupProbe is denied by the
  # locked kata-qemu-snp guest (ExecProcessRequest := false), so it could never
  # pass there and the workload would hang in Init forever.
  securityContext:
    {{- include "c8s-lib.getCertSecurityContext" . | nindent 4 }}
# c8s-cert-wait gates the workload on the initial cert without an exec probe.
# A plain (run-once) init container that blocks on the cert file is a
# CreateContainerRequest the locked guest allows, and normal init-completion
# ordering holds the workload until the attested cert exists — fail-closed.
# The `/c8s` path is the binary location from cmd/c8s/Dockerfile; command
# bypasses the ENTRYPOINT so the full path must match.
- name: c8s-cert-wait
  image: {{ include "c8s-lib.image" $root }}
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
    {{- include "c8s-lib.getCertSecurityContext" . | nindent 4 }}
{{- end -}}

{{/*
SecurityContext for the get-cert containers: runs as the consumer's UID/GID so
the shared cert volume is writable, locked down otherwise. dict keys:
runAsUser, runAsGroup, runAsNonRoot.
*/}}
{{- define "c8s-lib.getCertSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: {{ .runAsNonRoot }}
runAsUser: {{ include "c8s-lib.int" .runAsUser }}
runAsGroup: {{ include "c8s-lib.int" .runAsGroup }}
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
  c8s-lib.cdsDnsSanPattern is the in-cluster --dns-san-pattern the chart always
  passes to CDS: a regex matching any in-cluster Service DNS name
  (<name>.<namespace>.svc). CDS full-matches it, so workloads in any namespace
  (tls-lb, ratls-mesh in the release namespace; tenant workloads in
  their own) can request a leaf for their Service name. Operators fronting a
  public domain append that hostname via cds.dnsSanPatterns, which adds further
  --dns-san-pattern args alongside this one rather than replacing it.
*/}}
{{- define "c8s-lib.cdsDnsSanPattern" -}}
^[a-z0-9-]+[.][a-z0-9-]+[.]svc$
{{- end -}}

{{- define "c8s-lib.attestationApiConfig" -}}
{{- $root := .root -}}
[server]
# Pod loopback only: consumers enter through the attest-proxy sidecar's
# node-local Unix socket; nothing routable can reach /attest.
bind = "127.0.0.1:{{ $root.Values.attestation.port }}"

[server.tls]
enabled = false

[attestation]
enabled = true
platforms = ["snp", "tdx", "az-snp", "az-tdx", "gcp-snp", "gcp-tdx"]

[certs]
cache_max_entries = 1024
{{- end -}}

{{/*
  c8s-lib.valueAtPath resolves a dotted path against a root dict. Call with
  (dict "root" <dict> "path" "a.b.c"); returns the value at that path (nil if
  any segment is missing). Lets c8s-lib.components drive off the declarative
  .Values.c8sComponents paths instead of hardcoding each .Values.x.y.
*/}}
{{- define "c8s-lib.valueAtPath" -}}
{{- $cur := .root -}}
{{- range $seg := splitList "." .path -}}
{{- if kindIs "map" $cur -}}{{- $cur = index $cur $seg -}}{{- else -}}{{- $cur = "" -}}{{- end -}}
{{- end -}}
{{- $cur | toJson -}}
{{- end -}}

{{/*
  c8s-lib.components is the single source of truth for the c8s component image
  set, resolved from the declarative .Values.c8sComponents list. It returns a
  JSON list of {name, image, enabled, cdsExempt}, one per component, so the
  derivation (c8s-lib.imageAllowlist) and the fail-closed coverage guard
  (validations) range over the same list — and `c8s install` reads the same
  .Values.c8sComponents via `helm show values`. Adding a component is one edit
  in the chart's values.yaml.

  - image:     the image object at valuePath (.repository/.digest)
  - enabled:   true when enabledPath is "" or resolves truthy; a disabled
               component is neither derived nor coverage-checked.
  - cdsExempt: cds is always seeded via its self-entry (independent of
               deriveComponents), so the coverage guard skips it.
*/}}
{{- define "c8s-lib.components" -}}
{{- $root := . -}}
{{- $out := list -}}
{{- range $c := .Values.c8sComponents -}}
{{- $img := include "c8s-lib.valueAtPath" (dict "root" $root.Values "path" $c.valuePath) | fromJson -}}
{{- /* enabledPath points at a JSON boolean; valueAtPath returns it as the
   string "true"/"false" — compare the string, not `| fromJson`, whose Helm
   variant returns a (truthy) map for a scalar. */ -}}
{{- $enabled := true -}}
{{- if $c.enabledPath -}}{{- $enabled = eq (include "c8s-lib.valueAtPath" (dict "root" $root.Values "path" $c.enabledPath)) "true" -}}{{- end -}}
{{- $out = append $out (dict "name" $c.valuePath "image" $img "enabled" $enabled "cdsExempt" $c.cdsExempt) -}}
{{- end -}}
{{ $out | toJson }}
{{- end -}}

{{/*
  c8s-lib.imageAllowlist returns the merged image-digest allowlist as a dict
  (sha256 -> image reference). It is the single source the NRI allowlist is
  built from — both CDS's served seed (c8s-lib.allowlistSeedJSON) and each
  plugin's always_allow (c8s-lib.nri.bootConfig) render from it.

  Contents, lowest precedence first:
    1. derived c8s component images (from c8s-lib.components) whose
       image.digest is set — only when bootstrapAllowlist.deriveComponents is
       true, so a digest-pinned `c8s install` self-allows the c8s components
       it deploys;
    2. the CDS image self-entry (cds.image) — always present (independent of
       deriveComponents) so CDS is admitted on whichever node it lands;
    3. operator-supplied nriImagePolicy.bootstrapAllowlist.digests, which
       override a derived entry for the same sha256 (fleet values win).
*/}}
{{- define "c8s-lib.imageAllowlist" -}}
{{- $digests := dict -}}
{{- if .Values.nriImagePolicy.bootstrapAllowlist.deriveComponents -}}
{{- range $c := (include "c8s-lib.components" . | fromJsonArray) -}}
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
       hand-pinning it in bootstrapAllowlist.digests. Operator-supplied digests
       below still override. */}}
{{- if .Values.tlsLb.enabled -}}
{{- $lbImg := .Values.tlsLb.nginx.image -}}
{{- if $lbImg.digest -}}
{{- $_ := set $digests $lbImg.digest (printf "%s@%s" $lbImg.repository $lbImg.digest) -}}
{{- end -}}
{{- end -}}
{{- /* containerd-prep init-container images (rke2-only): the admission
       plugin checks every container node-wide, so a prep image an installer
       runs must be in the floor or its DaemonSet re-roll self-deadlocks on
       "image not in allowlist: busybox". Only charts that run a prep
       container carry the section. */}}
{{- if and (eq (include "c8s-lib.distro" .) "rke2") (ne (include "c8s-lib.kata" .) "true") -}}
{{- with .Values.nriImagePolicy.containerdPrep -}}
{{- if .image.digest -}}
{{- $_ := set $digests .image.digest (printf "%s@%s" .image.repository .image.digest) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- range $digest, $image := .Values.nriImagePolicy.bootstrapAllowlist.digests -}}
{{- $_ := set $digests $digest $image -}}
{{- end -}}
{{ $digests | toJson }}
{{- end -}}

{{/*
  c8s-lib.allowlistSeedJSON renders the allowlist document CDS's
  --allowlist-seed expects: the c8s-lib.imageAllowlist floor under "digests",
  plus any bootstrapAllowlist.workloads under "workloads" ({} by default).
  CDS seeds its served /allowlist from it so the first worker pull returns a
  real list rather than an empty set. The document validates against
  pkg/allowlist.ParseJSON.
*/}}
{{- define "c8s-lib.allowlistSeedJSON" -}}
{{ dict "schema" "c8s.allowlist/v1" "digests" (include "c8s-lib.imageAllowlist" . | fromJson) "workloads" (.Values.nriImagePolicy.bootstrapAllowlist.workloads | default dict) | toJson }}
{{- end -}}

{{/*
  c8s-lib.distro — the host Kubernetes distro (k8s | rke2). It selects the
  containerd config layout for the kata and NRI installers and the CoreDNS
  Service name tls-lb resolves upstreams against. Absent (node-image), the
  distro is RKE2.
*/}}
{{- define "c8s-lib.distro" -}}
{{- if .Values.distro -}}
{{ .Values.distro }}
{{- else -}}
rke2
{{- end -}}
{{- end -}}

{{/*
  c8s-lib.tlsLbResolver — the DNS server nginx re-resolves upstreams against.
  An explicit tlsLb.nginx.resolver wins; empty derives from the distro. RKE2
  names its CoreDNS Service rke2-coredns-rke2-coredns, and nginx exits at
  startup on a resolver name that does not resolve — the wrong default is a
  tls-lb crash-loop, not a degraded mode.
*/}}
{{- define "c8s-lib.tlsLbResolver" -}}
{{- if .Values.tlsLb.nginx.resolver -}}
{{- .Values.tlsLb.nginx.resolver -}}
{{- else if eq (include "c8s-lib.distro" .) "rke2" -}}
rke2-coredns-rke2-coredns.kube-system.svc.cluster.local
{{- else -}}
kube-dns.kube-system.svc.cluster.local
{{- end -}}
{{- end -}}

{{- define "c8s-lib.commonLabels" -}}
app.kubernetes.io/name: c8s-operator
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: Helm
{{- end -}}

{{/* Emits an imagePullSecrets: block from .local, falling back to chart-wide
  .Values.imagePullSecrets. The install-time pull secret
  (.Values.imagePullSecret, the name of a pre-existing Secret) is appended to
  whichever list won, so it reaches every component even when a component
  overrides its local list; uniq keeps an operator's explicit reference to the
  same Secret from rendering twice. Callers place it with nindent. Call with
  (dict "root" $ "local" <list>). */}}
{{- define "c8s-lib.imagePullSecrets" -}}
{{- $secrets := .local | default .root.Values.imagePullSecrets | default list -}}
{{- with .root.Values.imagePullSecret -}}
{{- $secrets = uniq (append $secrets (dict "name" .)) -}}
{{- end -}}
{{- with $secrets }}
imagePullSecrets:
{{ toYaml . }}
{{- end -}}
{{- end -}}

{{- define "c8s-lib.serviceAccountImagePullSecrets" -}}
{{- include "c8s-lib.imagePullSecrets" (dict "root" . "local" .Values.serviceAccount.imagePullSecrets) -}}
{{- end -}}

{{/*
  Namespace exclusions of the pod-injection webhook, as namespaceSelector
  matchExpressions. Shared by the webhook config and the admission policies
  that mirror its scope (kata enforcement, cw-label integrity): a namespace
  the webhook skips but a policy covers would fail closed on every pod in it,
  so all consumers must render the identical list.
*/}}
{{- define "c8s-lib.webhookExcludedNamespaces" -}}
- key: kubernetes.io/metadata.name
  operator: NotIn
  values:
    - {{ .Release.Namespace }}
    - kube-system
    - kube-public
    - kube-node-lease
    {{- range .Values.webhook.extraExcluded }}
    - {{ . }}
    {{- end }}
{{- end }}

{{/* operator's --hardware-platform vocabulary (sev-snp|tdx). */}}
{{- define "c8s-lib.hardwarePlatform" -}}
{{- if eq (include "c8s-lib.teeFamily" .) "snp" -}}sev-snp{{- else -}}tdx{{- end -}}
{{- end -}}
