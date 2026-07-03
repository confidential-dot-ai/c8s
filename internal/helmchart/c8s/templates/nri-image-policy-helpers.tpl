{{/*
Expand the name of the chart.
*/}}
{{- define "nri-image-policy.name" -}}
nri-image-policy
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "nri-image-policy.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "nri-image-policy.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "nri-image-policy.labels" -}}
helm.sh/chart: {{ include "nri-image-policy.name" . }}-0.3.0
{{ include "nri-image-policy.selectorLabels" . }}
app.kubernetes.io/version: ""
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: c8s
{{- end }}

{{/*
Selector labels
*/}}
{{- define "nri-image-policy.selectorLabels" -}}
app: {{ include "nri-image-policy.fullname" . }}
app.kubernetes.io/name: {{ include "nri-image-policy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Install image reference.
*/}}
{{- define "nri-image-policy.image" -}}
{{ include "c8s-common.image" .Values.nriImagePolicy.image }}
{{- end }}

{{/*
Component-label prefix of the installer DaemonSet pods ("nri-installer-cds" /
"nri-installer-worker"). pushImage's pod lookup filters on it — shared so a
rename moves both.
*/}}
{{- define "nri-image-policy.installerComponentPrefix" -}}
nri-installer-
{{- end }}

{{/*
Image for the pre-upgrade push-hook pod. The old CDS-node plugin only admits
digests in its old floor, so the hook must run an already-admitted image: a
Running installer pod's install image (DS rolls maxUnavailable:1, so one
survives mid-roll). Prefer a cds-archetype pod — it ran on the CDS node, so
its image is admitted by the plugin the hook talks to; a worker pod's image
only proves admissibility under that node's floor ∪ CDS-pull. The DaemonSet
object is no use — a failed upgrade attempt already points its spec at the
new, denied digest. Falls back to the chart's own image when lookup is empty
(fresh install, helm template) — no plugin is enforcing there.
*/}}
{{- define "nri-image-policy.pushImage" -}}
{{- $name := include "nri-image-policy.name" . -}}
{{- $prefix := include "nri-image-policy.installerComponentPrefix" . -}}
{{- $cdsImg := "" -}}
{{- $anyImg := "" -}}
{{- range dig "items" (list) (lookup "v1" "Pod" .Release.Namespace "") -}}
{{- $labels := dig "metadata" "labels" (dict) . -}}
{{- $component := dig "app.kubernetes.io/component" "" $labels -}}
{{- if and (eq (dig "app.kubernetes.io/name" "" $labels) $name)
           (eq (dig "app.kubernetes.io/instance" "" $labels) $.Release.Name)
           (hasPrefix $prefix $component)
           (eq (dig "status" "phase" "" .) "Running") -}}
{{- range dig "spec" "initContainers" (list) . -}}
{{- if eq (dig "name" "" .) "install" -}}
{{- if eq $component (printf "%scds" $prefix) -}}
{{- $cdsImg = dig "image" "" . -}}
{{- else -}}
{{- $anyImg = dig "image" "" . -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- coalesce $cdsImg $anyImg (include "nri-image-policy.image" .) -}}
{{- end }}

{{/*
cdsPartitioned is true when cds.node.selector pins CDS to a dedicated node, so
the installer renders the CDS/worker split (CDS-installer affinity In the
selector, worker-installer anti-affinity NotIn it). An empty selector means "no
dedicated CDS node" (single-node / single-CVM): every node is CDS-eligible, the
split collapses to a single push-mode installer everywhere, and the worker
variant is not rendered. A nil selector (helm `--set cds.node.selector=null`)
is a zero reflect.Value that panics len(), so test emptiness with `not` first.
*/}}
{{- define "nri-image-policy.cdsPartitioned" -}}
{{- $sel := .Values.cds.node.selector -}}
{{- if not $sel -}}false
{{- else if eq (len $sel) 1 -}}true
{{- else -}}{{- fail "cds.node.selector must be empty (no dedicated CDS node) or exactly one key/value pair (e.g. {role: cds})" -}}
{{- end -}}
{{- end }}

{{/*
The single nodeSelector key/value of cds.node.selector. Only meaningful when
cdsPartitioned is true; callers must gate on it.
*/}}
{{- define "nri-image-policy.cdsNodeKey" -}}
{{- range $k, $_ := .Values.cds.node.selector }}{{ $k }}{{ end -}}
{{- end }}

{{- define "nri-image-policy.cdsNodeValue" -}}
{{- range $_, $v := .Values.cds.node.selector }}{{ $v }}{{ end -}}
{{- end }}

{{/*
Host paths derived from values.
*/}}
{{- define "nri-image-policy.hostPluginPath" -}}
{{ printf "%s/%s" .Values.nriImagePolicy.hostPaths.pluginDir .Values.nriImagePolicy.pluginFilename }}
{{- end }}

{{- define "nri-image-policy.hostConfigPath" -}}
{{ printf "%s/image-policy.yaml" .Values.nriImagePolicy.hostPaths.configDir }}
{{- end }}

{{- define "nri-image-policy.hostHealthSocket" -}}
{{ printf "%s/%s" .Values.nriImagePolicy.hostPaths.runtimeDir .Values.nriImagePolicy.healthSocketName }}
{{- end }}

{{/*
Shared hostPath mounts and volumes used by installer DaemonSets and the
uninstall hook.
*/}}
{{- define "nri-image-policy.hostVolumeMounts" -}}
- name: host-plugin-dir
  mountPath: /host{{ .Values.nriImagePolicy.hostPaths.pluginDir }}
- name: host-config-dir
  mountPath: /host{{ .Values.nriImagePolicy.hostPaths.configDir }}
- name: host-containerd-config
  mountPath: /host{{ include "nri-image-policy.containerdConfigDir" . }}
- name: host-cache-dir
  mountPath: /host{{ .Values.nriImagePolicy.hostPaths.cacheDir }}
- name: host-runtime-dir
  mountPath: /host{{ .Values.nriImagePolicy.hostPaths.runtimeDir }}
{{- end }}

{{- define "nri-image-policy.hostVolumes" -}}
- name: host-plugin-dir
  hostPath:
    path: {{ .Values.nriImagePolicy.hostPaths.pluginDir }}
    type: DirectoryOrCreate
- name: host-config-dir
  hostPath:
    path: {{ .Values.nriImagePolicy.hostPaths.configDir }}
    type: DirectoryOrCreate
- name: host-containerd-config
  hostPath:
    path: {{ include "nri-image-policy.containerdConfigDir" . }}
    type: Directory
- name: host-cache-dir
  hostPath:
    path: {{ .Values.nriImagePolicy.hostPaths.cacheDir }}
    type: DirectoryOrCreate
- name: host-runtime-dir
  hostPath:
    path: {{ .Values.nriImagePolicy.hostPaths.runtimeDir }}
    type: DirectoryOrCreate
{{- end }}

{{/*
Host containerd config directory bind-mounted into the installer.
*/}}
{{- define "nri-image-policy.containerdConfigDir" -}}
{{- if .Values.nriImagePolicy.containerd.configDir -}}
{{ .Values.nriImagePolicy.containerd.configDir }}
{{- else if eq .Values.nriImagePolicy.distro "rke2" -}}
/var/lib/rancher/rke2/agent/etc/containerd
{{- else if eq .Values.nriImagePolicy.distro "k8s" -}}
/etc/containerd
{{- else -}}
{{ fail (printf "nri-image-policy: distro must be \"k8s\" or \"rke2\" (got %q), or set containerd.configDir explicitly" .Values.nriImagePolicy.distro) }}
{{- end -}}
{{- end -}}

{{/*
patch  = splice an in-place sentinel-delimited block into config.toml.
dropin = write a standalone file the installer owns entirely.
*/}}
{{- define "nri-image-policy.containerdConfigMode" -}}
{{- if eq .Values.nriImagePolicy.distro "rke2" -}}
dropin
{{- else if eq .Values.nriImagePolicy.distro "k8s" -}}
patch
{{- else -}}
{{ fail (printf "nri-image-policy: distro must be \"k8s\" or \"rke2\" (got %q)" .Values.nriImagePolicy.distro) }}
{{- end -}}
{{- end -}}

{{/*
Host service restart that makes containerd re-read its config.
*/}}
{{- define "nri-image-policy.restartCommand" -}}
{{- if .Values.nriImagePolicy.containerd.restartCommand -}}
{{ .Values.nriImagePolicy.containerd.restartCommand }}
{{- else if eq .Values.nriImagePolicy.distro "rke2" -}}
{{- /* A server/control-plane node runs rke2-server (which owns containerd); a
       worker node runs rke2-agent. Restart whichever unit is active so the
       install works on a single-node/server cluster too, not just workers. */ -}}
if systemctl is-active --quiet rke2-server; then systemctl restart rke2-server; else systemctl restart rke2-agent; fi
{{- else -}}
systemctl restart containerd
{{- end -}}
{{- end -}}

{{/*
Host containerd socket the plugin connects to.
*/}}
{{- define "nri-image-policy.containerdSocket" -}}
{{- if .Values.nriImagePolicy.containerd.socket -}}
{{ .Values.nriImagePolicy.containerd.socket }}
{{- else if eq .Values.nriImagePolicy.distro "rke2" -}}
/run/k3s/containerd/containerd.sock
{{- else -}}
/run/containerd/containerd.sock
{{- end -}}
{{- end -}}
