//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"maps"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

// kataSweepScript sweeps c8s host state off a single node (see the script
// header for the full inventory). Kept as a standalone POSIX-shell file (like
// the chart's files/scripts/*) so it gets shellcheck; it runs as the init
// container of the sweep DaemonSet built in kataSweepDaemonSet.
//
//go:embed kata-sweep.sh
var kataSweepScript string

var (
	uninstallNamespace       string
	uninstallRelease         string
	uninstallWait            bool
	uninstallKataSweep       bool
	uninstallHostSweepOnly   bool
	uninstallForce           bool
	uninstallDeleteCRDs      bool
	uninstallDeleteNamespace bool
)

// kataRuntimeClassNames are the RuntimeClass objects the pod chart renders —
// a fixed contract with its templates/kata.yaml (and, there, with
// kata-deploy's SHIMS_X86_64 and the kata-enforcement allowlist).
// kata-qemu-snp-nvidia / kata-qemu-tdx-nvidia are the confidential-GPU classes
// that ship with every kata install; listing them here keeps the running-pods
// guard covering GPU pods too.
var kataRuntimeClassNames = []string{"kata-qemu", "kata-clh", "kata-qemu-snp", "kata-qemu-tdx", "kata-qemu-snp-nvidia", "kata-qemu-tdx-nvidia"}

// confidentialWorkloadCRD is the chart's one CRD (crds/ dir, so helm never
// deletes it); --delete-crds removes it by name.
const confidentialWorkloadCRD = "confidentialworkloads.confidential.ai"

// chartInstanceLabel is on every pod template the chart renders (c8s.commonLabels
// and tls-lb.selectorLabels) and on nothing the operator creates. With the
// release namespace it identifies the release's own kata pods — see
// docs/kata.md "Uninstalling".
const chartInstanceLabel = "app.kubernetes.io/instance"

// kataPodJSONPath dumps one "namespace\tname\truntimeClass\tinstance" line per
// pod; jsonpath needs the dots in a label key escaped.
var kataPodJSONPath = `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.runtimeClassName}{"\t"}{.metadata.labels.` +
	strings.ReplaceAll(chartInstanceLabel, ".", `\.`) + `}{"\n"}{end}`

// volumePodJSONPath dumps one "namespace\tname\tphase\tvolumes" line per pod,
// where volumes is the webhook's volume-request annotation; jsonpath needs the
// dots in an annotation key escaped.
var volumePodJSONPath = `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.metadata.annotations.` +
	strings.ReplaceAll(webhook.AnnotationVolumes, ".", `\.`) + `}{"\n"}{end}`

// kataRuntimeNodeLabel is the label kata-deploy stamps on each node once the
// runtime is installed (and removes again in its cleanup, when that runs to
// completion).
const kataRuntimeNodeLabel = "katacontainers.io/kata-runtime"

// snpCapabilityNodeLabel is the c8s-owned SNP platform label the install
// applies under --hardware-platform=sev-snp (the chart's kata.snpNodeSelector
// default — keep in lockstep with internal/helmchart/pod/values.yaml). The
// sweep removes only this exact key (plus tdxHostLabelKey, the TDX
// counterpart the install applies under --hardware-platform=tdx): a custom
// kata.snpNodeSelector (an NFD or provisioning-owned label) was never applied
// by c8s and is not c8s's to strip.
const snpCapabilityNodeLabel = "confidential.ai/sev-snp"

// kataUninstallConfig is the slice of the release's computed values the host
// sweep needs. It is read from `helm get values --all` BEFORE the release is
// deleted — afterwards the -f/--set overrides from install time (custom
// guestImage.hostPath, distro, nriImagePolicy.hostPaths) are unrecoverable.
type kataUninstallConfig struct {
	Enabled             bool
	Distro              string
	ContainerdConfigDir string // resolved absolute host dir (distro)
	GuestImageHostPath  string
	// GuestImageNvidiaHostPath is the GPU guest-image dir (kata.gpu.guestImage.hostPath),
	// defaulting to the chart path so a release without the block still sweeps
	// the standard leftover.
	GuestImageNvidiaHostPath string
	SweepImage               string
	// NRI image-policy host paths (nriImagePolicy.*): where the chart's
	// installer DaemonSet wrote the plugin, or where the node image baked it.
	// The sweep distinguishes the two via a baked-only marker on the host.
	NriContainerdDir   string // resolved from nriImagePolicy.containerd.configDir/.distro
	NriPluginDir       string
	NriPluginFilename  string
	NriConfigDir       string
	NriRuntimeDir      string
	NriCacheDir        string
	ImagePullSecretRef []string // Secret names for the sweep pod's imagePullSecrets
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the c8s Helm release and sweep kata artifacts off the hosts",
	Long: `Removes the release 'c8s install' deployed and, for a --cvm-mode=pod install,
sweeps the host-side kata artifacts off every node.

'helm uninstall' already unwinds most of the install: the release resources
(operator, CDS, attestation-api, ratls-mesh, tls-lb, webhook
configuration, RuntimeClasses, enforcement policy), the NRI image-policy host
plugin (pre-delete hook), and — best-effort — the kata runtime itself:
deleting the kata-deploy DaemonSet runs 'kata-deploy cleanup' in its preStop
hook on each node.

The host sweep then nukes what that path cannot guarantee. The preStop hook
is bounded by the pod's termination grace period (and the runtime restart it
triggers can kill the pod mid-cleanup), the pre-delete hooks only fire on a
release healthy enough to run them, and none of them knows about the
c8s-side artifacts. The sweep runs on every uninstall — not only kata
releases — because the host state below is not confined to the release's own
shape: a previous install on the same host may have had a different shape
(node vs pod), and leftovers brick or degrade the next cluster. After the
release is gone the sweep runs a short-lived privileged DaemonSet on every
linux node — with the release's NRI plugin image where the fail-closed
plugin is live (the sweep image must already be on the allowlist; the sweep
is what removes the plugin), else the digest-pinned busybox image the
install's containerd-prep uses — and removes, idempotently:

  - the NRI image-policy host plugin: containerd registration (drop-in or
    managed config block), the plugin binary, its config/cache/runtime dirs —
    skipped entirely on c8s node images, where the whole stack is baked into
    the measured image (detected via nri-node-ip.service) and is the image's
    to keep, not the release's to delete
  - the ratls-mesh netfilter state: the RATLS-MESH chains and their
    base-chain jumps in iptables and ip6tables, and the RATLS-MESH-* ipsets
    (the mesh's own preStop deliberately keeps the fail-closed guard, so this
    survives every healthy uninstall too)
  - the nydus-for-kata-tee systemd unit kata-deploy installs (its data dir
    /var/lib/nydus-for-kata-tee is preserved on purpose: containerd's
    meta.db keeps nydus snapshot records, and wiping the backend behind them
    breaks the next install's pulls)
  - /opt/kata (the kata-static payload) and the containerd-shim-kata-*
    symlinks
  - kata-deploy's containerd runtime drop-in, restarting containerd/RKE2
    (detached, via systemd-run) only if a drop-in was still registered
  - the pulled kata-guest-base artifact (kata.guestImage.hostPath, multi-GB —
    nothing else cleans this up), and the separate GPU guest image
    (kata.gpu.guestImage.hostPath); loop devices still bound under those dirs
    are unmounted and detached first, or the rm unlinks files the loops keep
    pinning and the space is never reclaimed
  - on RKE2: the c8s-managed containerd template (skipped on c8s node images,
    same baked-state rule) and the containerd-prep lock
  - the katacontainers.io/kata-runtime node labels and the
    confidential.ai/sev-snp capability labels the install's probe applied
    (via kubectl)

Which host paths and distro layout to sweep is read from the release's
computed values ('helm get values --all') before the release is deleted, so
-f overrides from install time are honored. For a release that is already
gone (e.g. a previous bare 'helm uninstall' left the hosts dirty), pass
--host-sweep-only: the helm step is skipped and the sweep uses the embedded
chart's defaults plus the distro detected from the cluster.

The uninstall refuses to proceed while pods with a kata RuntimeClass are
still running — removing the runtime under a running confidential workload
kills it without cleanup. Delete those workloads first, or pass --force. The
release's own chart-managed pods (CDS and tls-lb pin a kata RuntimeClass) do
not count: they are matched by the release namespace plus the chart's
app.kubernetes.io/instance label and are torn down by this uninstall.

It refuses the same way while a pod holds a c8s encrypted volume: volumed is
the only component that unmaps the dm-crypt/dm-verity stack behind one, so
removing it under a live volume strands the mappings on the node, where they
keep the backing disk open against the next install. Scale those workloads to
zero first — volumed tears the volumes down — or pass --force. Whatever is
still mapped when the release goes is reaped by the chart's volumed pre-delete
hook, which runs on every node before the daemon is removed. That hook can only
close a mapping nothing is using: a live consumer keeps the device open through
its own mount namespace, which the hook's host-side unmount does not reach, so
under --force the hook fails on those and names them. Whatever it leaves is
swept by volumed the next time it starts.

Left in place by default: the ConfidentialWorkload CRD (helm never deletes
crds/; --delete-crds removes it ALONG WITH EVERY ConfidentialWorkload object)
and the release namespace (--delete-namespace).

Requires the 'helm' and 'kubectl' CLIs to be on PATH.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateUninstallFlags(uninstallKataSweep, uninstallHostSweepOnly); err != nil {
			return err
		}
		if _, err := exec.LookPath("helm"); err != nil {
			return fmt.Errorf("helm CLI not found on PATH: %w", err)
		}
		if _, err := exec.LookPath("kubectl"); err != nil {
			return fmt.Errorf("kubectl CLI not found on PATH: %w", err)
		}

		ctx := cmd.Context()
		values, found, err := releaseValues(ctx, uninstallRelease, uninstallNamespace)
		if err != nil {
			return err
		}
		if !found && !uninstallHostSweepOnly {
			return fmt.Errorf("helm release %q not found in namespace %q — nothing to uninstall. If a previous uninstall already deleted the release but left kata artifacts on the nodes, re-run with --host-sweep-only", uninstallRelease, uninstallNamespace)
		}

		var cfg kataUninstallConfig
		if found {
			chartName, _, err := releaseChartName(ctx, uninstallRelease, uninstallNamespace)
			if err != nil {
				return err
			}
			cfg, err = kataConfigFromValues(chartName, values)
			if err != nil {
				return fmt.Errorf("read kata config from release values: %w", err)
			}
		} else {
			fmt.Fprintf(os.Stdout, "+ release %q not found — sweeping with chart defaults and detected distro\n", uninstallRelease)
			cfg, err = chartDefaultKataConfig(ctx)
			if err != nil {
				return err
			}
		}
		// The host sweep runs on every uninstall, whatever the release's
		// shape: the artifacts it removes (NRI plugin, mesh netfilter state,
		// kata payload, guest images) may be cross-shape leftovers the
		// release's own values cannot see, and the chart's pre-delete hooks
		// are only a healthy-release first line. --kata-sweep=false opts out.
		sweep := uninstallKataSweep

		// Deleting the kata-deploy DaemonSet removes the runtime from under
		// any pod still using a kata RuntimeClass (its preStop cleanup runs
		// regardless of the sweep), so the guard applies whenever kata is
		// being uninstalled, not only when the sweep runs.
		if (cfg.Enabled || uninstallHostSweepOnly) && !uninstallForce {
			pods, chartManaged, err := listKataPods(ctx, uninstallNamespace, uninstallRelease)
			if err != nil {
				return err
			}
			if len(pods) > 0 {
				return kataPodsRunningError(pods, chartManaged, uninstallNamespace, uninstallRelease)
			}
		}

		// volumed goes with the release and is the only component that unmaps
		// a pod's volume devices, so the teardown order is load-bearing.
		if boolAtPath(values, "volumed.enabled") {
			pods, err := listVolumePods(ctx)
			if err != nil {
				return err
			}
			if len(pods) > 0 {
				if !uninstallForce {
					return volumePodsRunningError(pods)
				}
				fmt.Fprintf(os.Stdout, "%s\n", forcedVolumePodsWarning(pods))
			}
		}

		if !uninstallHostSweepOnly {
			helmArgs := buildHelmUninstallArgs(uninstallRelease, uninstallNamespace, uninstallWait)
			fmt.Fprintf(os.Stdout, "+ helm %s\n", strings.Join(helmArgs, " "))
			hc := exec.CommandContext(ctx, "helm", helmArgs...)
			hc.Stdout = os.Stdout
			hc.Stderr = os.Stderr
			if err := hc.Run(); err != nil {
				return fmt.Errorf("helm uninstall failed: %w — a wedged pre-delete hook blocks the sweep too; recover with 'helm uninstall --no-hooks %s --namespace %s' followed by 'c8s uninstall --host-sweep-only'", err, uninstallRelease, uninstallNamespace)
			}
		}

		if sweep {
			if err := runKataSweep(ctx, uninstallNamespace, uninstallRelease, cfg, uninstallHostSweepOnly); err != nil {
				return err
			}
		}

		if uninstallDeleteCRDs {
			if err := kubectlRun(ctx, "delete", "crd", confidentialWorkloadCRD, "--ignore-not-found"); err != nil {
				return err
			}
		}
		if uninstallDeleteNamespace {
			if err := kubectlRun(ctx, "delete", "namespace", uninstallNamespace, "--ignore-not-found"); err != nil {
				return err
			}
		}
		return nil
	},
}

// validateUninstallFlags rejects --host-sweep-only with --kata-sweep=false:
// the former exists only to run the sweep, so together they ask for nothing.
func validateUninstallFlags(kataSweep, hostSweepOnly bool) error {
	if hostSweepOnly && !kataSweep {
		return fmt.Errorf("--host-sweep-only runs only the kata host sweep, which --kata-sweep=false disables; drop one of the two flags")
	}
	return nil
}

// buildHelmUninstallArgs assembles the helm uninstall invocation. --wait
// holds helm until the release resources are actually gone — which is also
// when the kata-deploy preStop cleanup has had its chance to run — with the
// same fixed timeout the install uses.
func buildHelmUninstallArgs(release, namespace string, wait bool) []string {
	helmArgs := []string{"uninstall", release, "--namespace", namespace}
	if wait {
		helmArgs = append(helmArgs, "--wait", "--timeout=5m")
	}
	return helmArgs
}

// releaseValues reads the release's computed values (chart defaults merged
// with install-time -f/--set) as a decoded tree. found=false means the
// release does not exist; any other helm failure is an error.
func releaseValues(ctx context.Context, release, namespace string) (map[string]any, bool, error) {
	out, err := exec.CommandContext(ctx, "helm", "get", "values", release,
		"--namespace", namespace, "--all", "--output", "json").Output()
	if err != nil {
		var ee *exec.ExitError
		// helm reports a missing release as "Error: release: not found".
		if errors.As(err, &ee) && strings.Contains(string(ee.Stderr), "release: not found") {
			return nil, false, nil
		}
		if errors.As(err, &ee) {
			return nil, false, fmt.Errorf("helm get values %s -n %s: %w: %s", release, namespace, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, false, fmt.Errorf("helm get values %s -n %s: %w", release, namespace, err)
	}
	var tree map[string]any
	if err := json.Unmarshal(out, &tree); err != nil {
		return nil, false, fmt.Errorf("parse release values: %w", err)
	}
	return tree, true, nil
}

// chartDefaultKataConfig builds the sweep config for the --host-sweep-only
// path when the release (and with it the install-time values) is already
// gone: the embedded chart's defaults, with the distro detected from the
// cluster exactly as the install detects it (the chart default k8s would
// silently mis-target RKE2 hosts).
func chartDefaultKataConfig(ctx context.Context) (kataUninstallConfig, error) {
	// The merged defaults of the pod chart (kata paths) and a node chart (NRI
	// paths, runtimeDir): no single shape chart carries both, and the sweep
	// covers cross-shape leftovers.
	merged := map[string]any{}
	for _, shape := range []helmchart.Shape{helmchart.ShapePod, helmchart.ShapeNodeMetal} {
		chartPath, tmpRoot, err := helmchart.ExtractChart(shape)
		if err != nil {
			return kataUninstallConfig{}, fmt.Errorf("extract embedded chart: %w", err)
		}
		out, err := exec.CommandContext(ctx, "helm", "show", "values", chartPath).Output()
		os.RemoveAll(tmpRoot)
		if err != nil {
			return kataUninstallConfig{}, fmt.Errorf("helm show values %s: %w", chartPath, err)
		}
		var tree map[string]any
		if err := yaml.Unmarshal(out, &tree); err != nil {
			return kataUninstallConfig{}, fmt.Errorf("parse chart values: %w", err)
		}
		maps.Copy(merged, tree)
	}

	distro, err := detectDistro(ctx)
	if err != nil {
		return kataUninstallConfig{}, err
	}
	fmt.Fprintf(os.Stdout, "+ detected host distro: %s\n", distro)
	merged["distro"] = distro

	cfg, err := kataConfigFromValues(helmchart.ShapePod.ChartName(), merged)
	if err != nil {
		return kataUninstallConfig{}, err
	}
	// The sweep is the whole point of this path; it must not be vetoed.
	cfg.Enabled = true
	return cfg, nil
}

// kataConfigFromValues extracts the sweep config from a decoded values tree
// (helm get values --all, or helm show values for the chart-defaults path).
// Any missing piece is an error: sweeping with a guessed path either misses
// the artifacts or removes the wrong directory, both silently.
// releaseChartName reads the deployed release's chart name (c8s-pod,
// c8s-node-cloud, ..., or "c8s" for a pre-split monolith release). found=false
// means the release does not exist.
func releaseChartName(ctx context.Context, release, namespace string) (string, bool, error) {
	out, err := exec.CommandContext(ctx, "helm", "list", "--namespace", namespace,
		"--filter", "^"+release+"$", "--output", "json").Output()
	if err != nil {
		return "", false, fmt.Errorf("helm list %s -n %s: %w", release, namespace, err)
	}
	var entries []struct {
		Name  string `json:"name"`
		Chart string `json:"chart"`
	}
	if err := json.Unmarshal(out, &entries); err != nil {
		return "", false, fmt.Errorf("parse helm list: %w", err)
	}
	if len(entries) == 0 {
		return "", false, nil
	}
	// The chart column is <name>-<version>; the shape chart names are known,
	// so match by prefix. The monolith was exactly "c8s-<version>".
	for _, s := range helmchart.Shapes {
		if strings.HasPrefix(entries[0].Chart, s.ChartName()+"-") {
			return s.ChartName(), true, nil
		}
	}
	if strings.HasPrefix(entries[0].Chart, "c8s-") {
		return "c8s", true, nil
	}
	return "", false, fmt.Errorf("release %q deploys an unrecognized chart %q", release, entries[0].Chart)
}

// kataConfigFromValues builds the sweep config from the release's computed
// values and its chart identity. chartName is a shape chart name (kata state
// exists only under c8s-pod) or "c8s" for a pre-split monolith release (kata
// state when its values set kata.enabled). Values from a release of either
// generation are honored: new paths win, the monolith's old paths are the
// fallback, chart defaults the last resort.
func kataConfigFromValues(chartName string, tree map[string]any) (kataUninstallConfig, error) {
	cfg := kataUninstallConfig{}
	if shape, err := helmchart.ShapeForChartName(chartName); err == nil {
		cfg.Enabled = shape == helmchart.ShapePod
	} else {
		kata, _ := nestedMap(tree, "kata")
		cfg.Enabled, _ = kata["enabled"].(bool)
	}

	// distro is a single top-level value in the shape charts; the monolith
	// carried it per-component (kata.distro / nriImagePolicy.distro).
	distro := stringOrDefault(tree, "distro", "")
	if distro == "" {
		distro = stringOrDefault(tree, "kata.distro", "")
	}
	if distro == "" {
		// node-image carries no distro value: its nodes are RKE2.
		distro = "rke2"
	}
	cfg.Distro = distro

	kata, _ := nestedMap(tree, "kata")
	override, _ := kata["containerdConfigDir"].(string)
	var err error
	cfg.ContainerdConfigDir, err = containerdConfigDirFor(override, distro)
	if err != nil {
		return kataUninstallConfig{}, err
	}

	// Guest-image dirs: only a pod release could have written them, but the
	// sweep cleans cross-shape leftovers, so default to the chart's paths
	// rather than refuse a node release's tree (which has no kata block).
	cfg.GuestImageHostPath = stringOrDefault(tree, "kata.guestImage.hostPath", "/var/lib/c8s/kata-images")
	cfg.GuestImageNvidiaHostPath = stringOrDefault(tree, "kata.gpu.guestImage.hostPath", "/var/lib/c8s/kata-images-nvidia")

	cfg.SweepImage, err = sweepImageRef(tree)
	if err != nil {
		return kataUninstallConfig{}, err
	}

	cfg = nriConfigFromValues(tree, cfg)
	cfg.ImagePullSecretRef = imagePullSecretNames(tree)
	return cfg, nil
}

// nriConfigFromValues fills the NRI image-policy host paths, defaulting to
// the chart's values.yaml constants when a key is absent (an old or foreign
// release). The containerd dir follows nriImagePolicy.*, not kata.*: the CLI
// sets both distros together at install, but a -f release can diverge them,
// and the NRI installer targeted its own.
func nriConfigFromValues(tree map[string]any, cfg kataUninstallConfig) kataUninstallConfig {
	cfg.NriPluginDir = stringOrDefault(tree, "nriImagePolicy.hostPaths.pluginDir", "/opt/nri/plugins")
	cfg.NriPluginFilename = stringOrDefault(tree, "nriImagePolicy.pluginFilename", "10-nri-image-policy")
	cfg.NriConfigDir = stringOrDefault(tree, "nriImagePolicy.hostPaths.configDir", "/etc/nri/conf.d")
	cfg.NriRuntimeDir = stringOrDefault(tree, "runtimeDir", stringOrDefault(tree, "nriImagePolicy.hostPaths.runtimeDir", "/var/run/nri-image-policy"))
	cfg.NriCacheDir = stringOrDefault(tree, "nriImagePolicy.hostPaths.cacheDir", "/var/lib/nri-image-policy")
	distro := stringOrDefault(tree, "distro", stringOrDefault(tree, "nriImagePolicy.distro", cfg.Distro))
	override := stringOrDefault(tree, "nriImagePolicy.containerd.configDir", "")
	dir, err := containerdConfigDirFor(override, distro)
	if err != nil {
		// An exotic NRI distro the mapping does not know: fall back to the
		// kata-resolved dir rather than refuse the whole sweep.
		dir = cfg.ContainerdConfigDir
	}
	cfg.NriContainerdDir = dir
	return cfg
}

// stringOrDefault reads a dotted path from a decoded values tree, returning
// fallback when the path is absent or not a string.
func stringOrDefault(tree map[string]any, path, fallback string) string {
	s, err := stringAtPath(tree, path)
	if err != nil {
		return fallback
	}
	return s
}

// imagePullSecretNames collects the chart-wide pull secret references
// (imagePullSecret + imagePullSecrets[].name) so the sweep pod can pull its
// image where the install needed credentials. Absent on a default release.
func imagePullSecretNames(tree map[string]any) []string {
	var names []string
	if s, err := stringAtPath(tree, "imagePullSecret"); err == nil && s != "" {
		names = append(names, s)
	}
	if list, ok := tree["imagePullSecrets"].([]any); ok {
		for _, item := range list {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if name, ok := m["name"].(string); ok && name != "" && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return names
}

// containerdConfigDirFor resolves the host containerd config directory a
// component targeted — the same mapping as the chart's helpers
// (c8s.kataContainerdConfigDir, nri-image-policy.containerdConfigDir), so the
// sweep cleans exactly where the install wrote.
func containerdConfigDirFor(override, distro string) (string, error) {
	if override != "" {
		return override, nil
	}
	switch distro {
	case "rke2":
		return "/var/lib/rancher/rke2/agent/etc/containerd", nil
	case "k8s":
		return "/etc/containerd", nil
	}
	return "", fmt.Errorf("distro %q has no known containerd config dir and kata.containerdConfigDir is unset", distro)
}

// kataRestartCommand picks the host service restart that makes containerd
// drop the kata runtime registration — the same per-distro choice as the
// chart's nri-image-policy.restartCommand helper. The sweep only runs it
// when it removed a still-registered drop-in.
func kataRestartCommand(distro string) string {
	if distro == "rke2" {
		// A server/control-plane node runs rke2-server (which owns
		// containerd); a worker runs rke2-agent. Restart whichever is active
		// so single-node/server clusters work too.
		return "if systemctl is-active --quiet rke2-server; then systemctl restart rke2-server; else systemctl restart rke2-agent; fi"
	}
	return "systemctl restart containerd"
}

// sweepImageRef picks the image the sweep DaemonSet runs. On shapes where
// the fail-closed NRI plugin is live on the host, the sweep pod's image must
// already be on the allowlist — the sweep is what removes the plugin, so it
// cannot ask for admission afterwards. The one image guaranteed admitted
// there is the plugin's own (the installer DaemonSet ran it), so a release
// that resolved nriImagePolicy.image sweeps with it (debian-based: sh,
// coreutils, and util-linux's nsenter are all present). Everywhere else the
// digest-pinned containerd-prep busybox is enough: no host NRI to consult,
// or the baked node image whose floor already admits it. Digest wins over
// tag, mirroring the chart helper; neither set on either image is an error,
// never a silently-floating default.
func sweepImageRef(tree map[string]any) (string, error) {
	if ref, ok := imageRefAt(tree, "nriImagePolicy.image"); ok {
		return ref, nil
	}
	if ref, ok := imageRefAt(tree, "kata.containerdPrep.image"); ok {
		return ref, nil
	}
	return "", fmt.Errorf("neither nriImagePolicy.image nor kata.containerdPrep.image resolves to a pinned reference (digest or tag)")
}

// imageRefAt renders values image block <path> (repository + digest|tag) as
// a pullable reference. ok=false when the block is missing, incomplete, or
// carries neither digest nor tag.
func imageRefAt(tree map[string]any, path string) (string, bool) {
	img, ok := nestedMap(tree, strings.Split(path, ".")...)
	if !ok {
		return "", false
	}
	repo, _ := img["repository"].(string)
	digest, _ := img["digest"].(string)
	tag, _ := img["tag"].(string)
	if repo == "" {
		return "", false
	}
	if digest != "" {
		return repo + "@" + digest, true
	}
	if tag != "" {
		return repo + ":" + tag, true
	}
	return "", false
}

// listKataPods returns "namespace/name (runtimeClass)" for every pod the guard
// protects, plus the count of the release's own pods it skipped.
// runtimeClassName is not a server-side field selector, so the filter runs
// client-side over a one-line-per-pod jsonpath dump.
func listKataPods(ctx context.Context, namespace, release string) ([]string, int, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "pods", "--all-namespaces",
		"-o", "jsonpath="+kataPodJSONPath).Output()
	if err != nil {
		return nil, 0, fmt.Errorf("kubectl get pods --all-namespaces: %w", err)
	}
	pods, chartManaged := filterKataPods(strings.Split(strings.TrimSpace(string(out)), "\n"), namespace, release)
	return pods, chartManaged, nil
}

// filterKataPods keeps the "namespace\tname\truntimeClass\tinstanceLabel" lines
// whose class is a kata RuntimeClass, dropping the release's own chart-managed
// pods (release namespace AND chartInstanceLabel == release) and counting them
// separately: the chart pins kata on CDS and tls-lb, so counting them would
// refuse every clean uninstall. Pods without a runtimeClassName emit an empty
// third field and are skipped, as is anything malformed.
func filterKataPods(lines []string, namespace, release string) ([]string, int) {
	var pods []string
	chartManaged := 0
	for _, l := range lines {
		fields := strings.Split(l, "\t")
		if len(fields) != 4 || !slices.Contains(kataRuntimeClassNames, fields[2]) {
			continue
		}
		if fields[0] == namespace && fields[3] == release {
			chartManaged++
			continue
		}
		pods = append(pods, fmt.Sprintf("%s/%s (%s)", fields[0], fields[1], fields[2]))
	}
	return pods, chartManaged
}

// listVolumePods returns "namespace/name" for every pod holding a c8s volume.
// The annotation is not a server-side field selector, so the filter runs
// client-side over a one-line-per-pod jsonpath dump.
func listVolumePods(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "pods", "--all-namespaces",
		"-o", "jsonpath="+volumePodJSONPath).Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl get pods --all-namespaces: %w", err)
	}
	return filterVolumePods(strings.Split(strings.TrimSpace(string(out)), "\n")), nil
}

// filterVolumePods keeps the "namespace\tname\tphase\tvolumes" lines of pods
// that requested a volume and have not finished. A pod in a terminal phase has
// no container left holding a mapping, so counting it would refuse an
// uninstall that has nothing to lose.
func filterVolumePods(lines []string) []string {
	var pods []string
	for _, l := range lines {
		fields := strings.Split(l, "\t")
		if len(fields) != 4 || fields[3] == "" {
			continue
		}
		if fields[2] == string(corev1.PodSucceeded) || fields[2] == string(corev1.PodFailed) {
			continue
		}
		pods = append(pods, fields[0]+"/"+fields[1])
	}
	return pods
}

// volumePodsRunningError is the volume guard's refusal: it names the pods and
// the ordering that avoids the leak.
func volumePodsRunningError(pods []string) error {
	return fmt.Errorf("pods are still holding c8s encrypted volumes, and volumed is the only thing that unmaps them:\n  %s\nscale those workloads to zero first (volumed then tears the volumes down), or pass --force to uninstall with those mappings still open",
		strings.Join(pods, "\n  "))
}

// forcedVolumePodsWarning is what --force buys: the uninstall proceeds, and the
// mappings these pods hold stay open on their nodes, because the pre-delete
// hook cannot close a device a live mount namespace still references.
func forcedVolumePodsWarning(pods []string) string {
	return fmt.Sprintf("! --force: these pods still hold c8s encrypted volumes:\n  %s\nthe volumed pre-delete hook will fail to close their dm-crypt/dm-verity mappings, which then hold the backing disks open. Delete these pods and re-run the uninstall to leave the nodes clean; otherwise volumed sweeps the residue the next time it starts, so a reinstall clears it",
		strings.Join(pods, "\n  "))
}

// kataPodsRunningError is the guard's refusal. It reports the chart-managed
// pods it skipped so the operator sees the guard is scoped, not blanket, and
// does not reach for --force reflexively.
func kataPodsRunningError(pods []string, chartManaged int, namespace, release string) error {
	skipped := ""
	if chartManaged > 0 {
		plural := "s"
		if chartManaged == 1 {
			plural = ""
		}
		skipped = fmt.Sprintf("\n(skipped %d chart-managed pod%s of release %q in namespace %q)", chartManaged, plural, release, namespace)
	}
	return fmt.Errorf("pods with a kata RuntimeClass are still running and would lose their runtime:\n  %s%s\ndelete them first, or pass --force to uninstall anyway",
		strings.Join(pods, "\n  "), skipped)
}

// runKataSweep removes the kata host artifacts from every node kata-deploy
// targeted, after the release is gone: a short-lived privileged DaemonSet
// runs kata-sweep.sh as an init container on each node, the CLI waits for it
// to complete everywhere (rollout status blocks until every pod has passed
// init), then deletes it.
// sweepGuestImagePrefix is the only host directory tree the kata sweep is
// allowed to recursively delete. The guest-image host paths come from Helm
// release values (kata.guestImage.hostPath, kata.gpu.guestImage.hostPath); the
// sweep concatenates them below /host and runs `rm -rf`, so a hostile or
// malformed value like "", "/", "..", or "/host" would otherwise destroy the
// mounted host filesystem. The chart's defaults live under this prefix
// (/var/lib/c8s/kata-images{,-nvidia}); kata-sweep.sh re-checks the same
// invariant as an independent guard.
const sweepGuestImagePrefix = "/var/lib/c8s"

// validateSweepPath rejects a guest-image host path that is not a dedicated
// c8s directory strictly beneath sweepGuestImagePrefix. allowEmpty is true for
// the optional GPU path (empty ⇒ the sweep skips it). A rejected custom path
// fails safe: the operator is told to remove that directory manually rather
// than have the privileged sweep delete an unvetted location.
func validateSweepPath(field, p string, allowEmpty bool) error {
	if p == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s is empty; refusing to run the privileged host sweep", field)
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s %q is not an absolute path; refusing to sweep", field, p)
	}
	if filepath.Clean(p) != p {
		return fmt.Errorf("%s %q is not a clean path (has '..', '.', or redundant separators); refusing to sweep", field, p)
	}
	if p == sweepGuestImagePrefix || !strings.HasPrefix(p, sweepGuestImagePrefix+"/") {
		return fmt.Errorf("%s %q must be a directory under %s/; the c8s sweep refuses to recursively delete anything else (remove a custom location manually)", field, p, sweepGuestImagePrefix)
	}
	return nil
}

func runKataSweep(ctx context.Context, namespace, release string, cfg kataUninstallConfig, hostSweepOnly bool) error {
	// The sweep launches a privileged DaemonSet that recursively deletes the
	// guest-image dirs below the mounted host root. Validate those release-
	// derived paths before doing anything destructive so a hostile/malformed
	// value cannot turn the sweep into host destruction (defense in depth with
	// the guard inside kata-sweep.sh). Only a kata release could have written
	// those dirs, so only a kata release fails pre-flight on a bad one — for
	// other shapes the script's own guard presence-gates the deletion instead
	// of failing the whole uninstall over a dir c8s never wrote.
	if cfg.Enabled || hostSweepOnly {
		if err := validateSweepPath("kata.guestImage.hostPath", cfg.GuestImageHostPath, false); err != nil {
			return err
		}
		if err := validateSweepPath("kata.gpu.guestImage.hostPath", cfg.GuestImageNvidiaHostPath, true); err != nil {
			return err
		}
	}

	// The kata-deploy preStop cleanup and the image-puller's reconcile loop
	// both race the sweep (the puller re-pulls a guest image it sees
	// missing), so wait for their pods to be fully gone first. A no-op when
	// helm --wait already drained them or the release was already deleted.
	// Polled via kubectl get rather than `kubectl wait --for=delete`, whose
	// zero-matches exit status varies across kubectl versions.
	for _, component := range []string{"kata-deploy", "kata-image-puller", "kata-image-puller-nvidia"} {
		selector := fmt.Sprintf("app.kubernetes.io/instance=%s,app.kubernetes.io/component=%s", release, component)
		if err := waitPodsGone(ctx, namespace, selector); err != nil {
			return fmt.Errorf("waiting for %s pods to terminate: %w", component, err)
		}
	}
	// Same for the mesh: it re-asserts its base-chain iptables jumps on a
	// watchdog, so sweeping while a mesh pod still runs leaks the rules the
	// sweep just deleted (helm --wait=false leaves pods terminating).
	meshSelector := fmt.Sprintf("app.kubernetes.io/instance=%s,app.kubernetes.io/name=ratls-mesh", release)
	if err := waitPodsGone(ctx, namespace, meshSelector); err != nil {
		return fmt.Errorf("waiting for ratls-mesh pods to terminate: %w", err)
	}

	// The sweep pods are privileged; re-assert the namespace's privileged
	// pod-security labels (idempotent — the install already set them, but on
	// the --host-sweep-only path the namespace may have been deleted).
	if err := applyNamespace(ctx, namespace); err != nil {
		return err
	}

	// kata-deploy's cleanup unlabels nodes when it runs to completion; sweep
	// the stragglers. The platform labels the install applied from
	// --hardware-platform are swept the same way (only the c8s-owned default
	// keys — see snpCapabilityNodeLabel). Best-effort — a leftover label is
	// cosmetic and must not abort the nuke mid-flight. The pre-check avoids
	// handing `kubectl label` an empty node set, whose exit status varies
	// across kubectl versions.
	// GuestReadyNodeLabel joins them: its controller goes with the release, so
	// the node would keep asserting a readiness nothing maintains.
	for _, label := range []string{kataRuntimeNodeLabel, snpCapabilityNodeLabel, tdxHostLabelKey, webhook.GuestReadyNodeLabel} {
		labelled, err := exec.CommandContext(ctx, "kubectl", "get", "nodes",
			"-l", label, "-o", "name").Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: listing %s-labelled nodes failed (continuing): %v\n", label, err)
		} else if strings.TrimSpace(string(labelled)) != "" {
			fmt.Fprintf(os.Stdout, "+ kubectl label nodes -l %s %s-\n", label, label)
			if out, err := exec.CommandContext(ctx, "kubectl", "label", "nodes",
				"-l", label, label+"-").CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: removing %s node labels failed (continuing): %v: %s\n", label, err, bytes.TrimSpace(out))
			}
		}
	}

	manifest, err := json.Marshal(kataSweepDaemonSet(release, namespace, cfg))
	if err != nil {
		return fmt.Errorf("render sweep manifest: %w", err)
	}
	name := kataSweepName(release)
	fmt.Fprintf(os.Stdout, "+ kubectl apply -f - # DaemonSet/%s (kata host sweep)\n", name)
	kc := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	kc.Stdin = bytes.NewReader(manifest)
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("kubectl apply sweep DaemonSet: %w", err)
	}

	if err := kubectlRun(ctx, "rollout", "status", "daemonset/"+name,
		"-n", namespace, "--timeout=5m"); err != nil {
		// Leave the DaemonSet in place: its sweep container logs are the
		// only record of which node failed and why.
		return fmt.Errorf("kata host sweep did not complete: %w — inspect with 'kubectl -n %s logs ds/%s -c sweep', then remove it with 'kubectl -n %s delete ds %s'", err, namespace, name, namespace, name)
	}

	return kubectlRun(ctx, "delete", "daemonset", name, "-n", namespace, "--ignore-not-found")
}

func kataSweepName(release string) string {
	return release + "-kata-sweep"
}

// waitPodsGone polls until no pod in the namespace matches the selector.
// Terminating pods still list, so an empty result means every container —
// including any preStop hook — is finished.
func waitPodsGone(ctx context.Context, namespace, selector string) error {
	const timeout = 5 * time.Minute
	fmt.Fprintf(os.Stdout, "+ waiting for pods -l %s to terminate\n", selector)
	deadline := time.Now().Add(timeout)
	for {
		out, err := exec.CommandContext(ctx, "kubectl", "get", "pods",
			"-n", namespace, "-l", selector, "-o", "name").Output()
		if err != nil {
			return fmt.Errorf("kubectl get pods -n %s -l %s: %w", namespace, selector, err)
		}
		if strings.TrimSpace(string(out)) == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pods -l %s still present after %s", selector, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// kataSweepDaemonSet renders the sweep DaemonSet: every linux node (the
// swept artifacts are not confined to kata-selected nodes — the NRI installer
// and the mesh DaemonSets land on all of them — and a node can carry a
// previous shape's leftovers), tolerating all taints, with kata-sweep.sh as
// an init container and a pause container whose readiness lets `kubectl
// rollout status` double as "every node finished sweeping".
func kataSweepDaemonSet(release, namespace string, cfg kataUninstallConfig) *appsv1.DaemonSet {
	labels := map[string]string{
		"app.kubernetes.io/name":      "c8s-operator",
		"app.kubernetes.io/instance":  release,
		"app.kubernetes.io/component": "kata-sweep",
	}
	nodeSelector := map[string]string{"kubernetes.io/os": "linux"}
	privileged := true
	pullSecrets := make([]corev1.LocalObjectReference, 0, len(cfg.ImagePullSecretRef))
	for _, n := range cfg.ImagePullSecretRef {
		pullSecrets = append(pullSecrets, corev1.LocalObjectReference{Name: n})
	}
	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "DaemonSet"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      kataSweepName(release),
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					// hostPID: the sweep nsenters into PID 1 for host binaries
					// (systemctl, iptables, losetup) and the runtime restart.
					HostPID:      true,
					NodeSelector: nodeSelector,
					// The install's pull secret, so the sweep image pulls on
					// private-mirror clusters too (chart-wide values).
					ImagePullSecrets: pullSecrets,
					// Sweep everywhere kata-deploy installed — including
					// control-plane and otherwise-tainted nodes (mirrors the
					// install's one-shot posture).
					Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					InitContainers: []corev1.Container{{
						Name:            "sweep",
						Image:           cfg.SweepImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"/bin/sh", "-c"},
						Args:            []string{kataSweepScript},
						Env: []corev1.EnvVar{
							{Name: "HOST_CONTAINERD_DIR", Value: cfg.ContainerdConfigDir},
							{Name: "GUEST_IMAGE_DIR", Value: cfg.GuestImageHostPath},
							// Empty only for a pre-GPU release; the sweep skips it then.
							{Name: "GUEST_IMAGE_DIR_NVIDIA", Value: cfg.GuestImageNvidiaHostPath},
							{Name: "RKE2_PREP", Value: strconv.FormatBool(cfg.Distro == "rke2")},
							{Name: "RESTART_COMMAND", Value: kataRestartCommand(cfg.Distro)},
							{Name: "NRI_CONTAINERD_DIR", Value: cfg.NriContainerdDir},
							{Name: "NRI_PLUGIN_DIR", Value: cfg.NriPluginDir},
							{Name: "NRI_PLUGIN_FILENAME", Value: cfg.NriPluginFilename},
							{Name: "NRI_CONFIG_DIR", Value: cfg.NriConfigDir},
							{Name: "NRI_RUNTIME_DIR", Value: cfg.NriRuntimeDir},
							{Name: "NRI_CACHE_DIR", Value: cfg.NriCacheDir},
						},
						// Privileged with the host root mounted — the same
						// posture as kata-deploy: removing a runtime from a
						// host is inherently this shape.
						SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
						VolumeMounts:    []corev1.VolumeMount{{Name: "host", MountPath: "/host"}},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("32Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("200m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
						},
					}},
					Containers: []corev1.Container{{
						Name:            "pause",
						Image:           cfg.SweepImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						// busybox sleep has no "infinity"; the pod lives only
						// until the CLI's rollout-status wait returns anyway.
						Command: []string{"/bin/sh", "-c", "sleep 2147483647"},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("10m"),
								corev1.ResourceMemory: resource.MustParse("16Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("32Mi"),
							},
						},
					}},
					Volumes: []corev1.Volume{{
						Name: "host",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/"},
						},
					}},
				},
			},
		},
	}
}

// kubectlRun executes kubectl streaming output to the user, prefixed with the
// echoed command line like the install's helm/kubectl calls.
func kubectlRun(ctx context.Context, args ...string) error {
	fmt.Fprintf(os.Stdout, "+ kubectl %s\n", strings.Join(args, " "))
	kc := exec.CommandContext(ctx, "kubectl", args...)
	kc.Stdout = os.Stdout
	kc.Stderr = os.Stderr
	if err := kc.Run(); err != nil {
		return fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func init() {
	uninstallCmd.Flags().StringVar(&uninstallNamespace, "namespace", "c8s-system", "namespace the release was installed into")
	uninstallCmd.Flags().StringVar(&uninstallRelease, "release", "c8s", "Helm release name")
	uninstallCmd.Flags().BoolVar(&uninstallWait, "wait", true, "wait for the release deletion to complete (helm --wait); the kata host sweep additionally waits for the kata pods to be gone either way")
	uninstallCmd.Flags().BoolVar(&uninstallKataSweep, "kata-sweep", true, "after the release is deleted, sweep c8s host artifacts (NRI image-policy plugin, ratls-mesh netfilter state, nydus unit, /opt/kata, containerd drop-in, kata-guest-base images, RKE2 prep template, node labels) off every node via a short-lived privileged DaemonSet. Runs for every release shape — leftovers may come from a previous install's shape, not this release's")
	uninstallCmd.Flags().BoolVar(&uninstallHostSweepOnly, "host-sweep-only", false, "skip the helm uninstall and only run the host sweep — for a cluster whose release is already gone (e.g. a previous bare 'helm uninstall') but whose nodes still carry c8s artifacts. Uses the chart defaults and the distro detected from the cluster when the release values are unavailable")
	uninstallCmd.Flags().BoolVar(&uninstallForce, "force", false, "uninstall even while pods with a kata RuntimeClass are running (they lose their runtime: kata VMs keep running unmanaged but cannot restart), or while pods hold c8s encrypted volumes (the pre-delete hook cannot close a mapping a live pod holds, and fails naming it). With pods left running, the sweep's loop detach and guest-image deletion also cut devices and images out from under live guests")
	uninstallCmd.Flags().BoolVar(&uninstallDeleteCRDs, "delete-crds", false, "also delete the ConfidentialWorkload CRD — this deletes EVERY ConfidentialWorkload object in the cluster with it")
	uninstallCmd.Flags().BoolVar(&uninstallDeleteNamespace, "delete-namespace", false, "also delete the release namespace (and everything left in it, e.g. an operator-created image pull Secret)")
	rootCmd.AddCommand(uninstallCmd)
}
