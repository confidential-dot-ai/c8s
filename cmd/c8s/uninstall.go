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

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

// hostSweepScript sweeps c8s host state off a single node (see the script
// header for the full inventory). Kept as a standalone POSIX-shell file (like
// the chart's files/scripts/*) so it gets shellcheck; it runs as the init
// container of the sweep DaemonSet built in hostSweepDaemonSet.
//
//go:embed host-sweep.sh
var hostSweepScript string

var (
	uninstallNamespace       string
	uninstallRelease         string
	uninstallWait            bool
	uninstallHostSweep       bool
	uninstallHostSweepOnly   bool
	uninstallForce           bool
	uninstallDeleteCRDs      bool
	uninstallDeleteNamespace bool
)

// confidentialWorkloadCRD is the chart's one CRD (crds/ dir, so helm never
// deletes it); --delete-crds removes it by name.
const confidentialWorkloadCRD = "confidentialworkloads.confidential.ai"

// volumePodJSONPath dumps one "namespace\tname\tphase\tvolumes" line per pod,
// where volumes is the webhook's volume-request annotation; jsonpath needs the
// dots in an annotation key escaped.
var volumePodJSONPath = `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.metadata.annotations.` +
	strings.ReplaceAll(webhook.AnnotationVolumes, ".", `\.`) + `}{"\n"}{end}`

type hostUninstallConfig struct {
	Distro              string
	ContainerdConfigDir string
	SweepImage          string
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
	Short: "Uninstall the c8s Helm release and sweep host artifacts off the hosts",
	Long: `Uninstall the c8s Helm release and sweep node-side NRI and mesh state.
Use --host-sweep-only to recover cleanup after a previously deleted release.
Baked node image components are preserved. Delete volume workloads first;
--force bypasses this guard and can leave device mappings behind.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateUninstallFlags(uninstallHostSweep, uninstallHostSweepOnly); err != nil {
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
			return fmt.Errorf("helm release %q not found in namespace %q — nothing to uninstall. If a previous uninstall already deleted the release but left host artifacts on the nodes, re-run with --host-sweep-only", uninstallRelease, uninstallNamespace)
		}

		var cfg hostUninstallConfig
		if found {
			cfg, err = hostConfigFromValues(values)
			if err != nil {
				return fmt.Errorf("read host config from release values: %w", err)
			}
		} else {
			fmt.Fprintf(os.Stdout, "+ release %q not found — sweeping with chart defaults and detected distro\n", uninstallRelease)
			cfg, err = chartDefaultHostConfig(ctx)
			if err != nil {
				return err
			}
		}
		sweep := uninstallHostSweep

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
			if err := runHostSweep(ctx, uninstallNamespace, uninstallRelease, cfg, uninstallHostSweepOnly); err != nil {
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

// validateUninstallFlags rejects --host-sweep-only with --host-sweep=false:
// the former exists only to run the sweep, so together they ask for nothing.
func validateUninstallFlags(hostSweep, hostSweepOnly bool) error {
	if hostSweepOnly && !hostSweep {
		return fmt.Errorf("--host-sweep-only runs only the host sweep, which --host-sweep=false disables; drop one of the two flags")
	}
	return nil
}

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

// chartDefaultHostConfig builds the sweep config for the --host-sweep-only
// path when the release (and with it the install-time values) is already
// gone: the embedded chart's defaults, with the distro detected from the
// cluster exactly as the install detects it (the chart default k8s would
// silently mis-target RKE2 hosts).
func chartDefaultHostConfig(ctx context.Context) (hostUninstallConfig, error) {
	dir, err := extractChart()
	if err != nil {
		return hostUninstallConfig{}, fmt.Errorf("extract embedded chart: %w", err)
	}
	defer os.RemoveAll(dir)

	out, err := exec.CommandContext(ctx, "helm", "show", "values", filepath.Join(dir, helmchart.ChartRoot)).Output()
	if err != nil {
		return hostUninstallConfig{}, fmt.Errorf("helm show values: %w", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		return hostUninstallConfig{}, fmt.Errorf("parse chart values: %w", err)
	}

	distro, err := detectDistro(ctx)
	if err != nil {
		return hostUninstallConfig{}, err
	}
	fmt.Fprintf(os.Stdout, "+ detected host distro: %s\n", distro)
	if nri, ok := nestedMap(tree, "nriImagePolicy"); ok {
		nri["distro"] = distro
	}

	cfg, err := hostConfigFromValues(tree)
	if err != nil {
		return hostUninstallConfig{}, err
	}
	return cfg, nil
}

// hostConfigFromValues extracts the sweep config from a decoded values tree
// (helm get values --all, or helm show values for the chart-defaults path).
// Any missing piece is an error: sweeping with a guessed path either misses
// the artifacts or removes the wrong directory, both silently.
func hostConfigFromValues(tree map[string]any) (hostUninstallConfig, error) {
	distro := stringOrDefault(tree, "nriImagePolicy.distro", "k8s")
	override := stringOrDefault(tree, "nriImagePolicy.containerd.configDir", "")
	dir, err := containerdConfigDirFor(override, distro)
	if err != nil {
		return hostUninstallConfig{}, err
	}
	cfg := hostUninstallConfig{Distro: distro, ContainerdConfigDir: dir}
	cfg.SweepImage, err = sweepImageRef(tree)
	if err != nil {
		return hostUninstallConfig{}, err
	}

	cfg = nriConfigFromValues(tree, cfg)
	cfg.ImagePullSecretRef = imagePullSecretNames(tree)
	return cfg, nil
}

// nriConfigFromValues fills the NRI image-policy host paths, defaulting to
// the chart's values.yaml constants when a key is absent (an old or foreign
// release). The containerd dir follows nriImagePolicy.*, not host.*: the CLI
// sets both distros together at install, but a -f release can diverge them,
// and the NRI installer targeted its own.
func nriConfigFromValues(tree map[string]any, cfg hostUninstallConfig) hostUninstallConfig {
	cfg.NriPluginDir = stringOrDefault(tree, "nriImagePolicy.hostPaths.pluginDir", "/opt/nri/plugins")
	cfg.NriPluginFilename = stringOrDefault(tree, "nriImagePolicy.pluginFilename", "10-nri-image-policy")
	cfg.NriConfigDir = stringOrDefault(tree, "nriImagePolicy.hostPaths.configDir", "/etc/nri/conf.d")
	cfg.NriRuntimeDir = stringOrDefault(tree, "nriImagePolicy.hostPaths.runtimeDir", "/var/run/nri-image-policy")
	cfg.NriCacheDir = stringOrDefault(tree, "nriImagePolicy.hostPaths.cacheDir", "/var/lib/nri-image-policy")
	distro := stringOrDefault(tree, "nriImagePolicy.distro", cfg.Distro)
	override := stringOrDefault(tree, "nriImagePolicy.containerd.configDir", "")
	dir, err := containerdConfigDirFor(override, distro)
	if err != nil {
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
// (c8s.hostContainerdConfigDir, nri-image-policy.containerdConfigDir), so the
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
	return "", fmt.Errorf("nriImagePolicy.distro %q has no known containerd config dir and nriImagePolicy.containerd.configDir is unset", distro)
}

// hostRestartCommand picks the host service restart that makes containerd
// drop the host runtime registration — the same per-distro choice as the
// chart's nri-image-policy.restartCommand helper. The sweep only runs it
// when it removed a still-registered drop-in.
func hostRestartCommand(distro string) string {
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
	if ref, ok := imageRefAt(tree, "nriImagePolicy.containerdPrep.image"); ok {
		return ref, nil
	}
	return "", fmt.Errorf("neither nriImagePolicy.image nor nriImagePolicy.containerdPrep.image resolves to a pinned reference (digest or tag)")
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

func runHostSweep(ctx context.Context, namespace, release string, cfg hostUninstallConfig, hostSweepOnly bool) error {
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

	manifest, err := json.Marshal(hostSweepDaemonSet(release, namespace, cfg))
	if err != nil {
		return fmt.Errorf("render sweep manifest: %w", err)
	}
	name := hostSweepName(release)
	fmt.Fprintf(os.Stdout, "+ kubectl apply -f - # DaemonSet/%s (host sweep)\n", name)
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
		return fmt.Errorf("host sweep did not complete: %w — inspect with 'kubectl -n %s logs ds/%s -c sweep', then remove it with 'kubectl -n %s delete ds %s'", err, namespace, name, namespace, name)
	}

	return kubectlRun(ctx, "delete", "daemonset", name, "-n", namespace, "--ignore-not-found")
}

func hostSweepName(release string) string {
	return release + "-host-sweep"
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

// hostSweepDaemonSet renders the sweep DaemonSet: every linux node (the
// swept artifacts are not confined to host-selected nodes — the NRI installer
// and the mesh DaemonSets land on all of them — and a node can carry a
// previous shape's leftovers), tolerating all taints, with host-sweep.sh as
// an init container and a pause container whose readiness lets `kubectl
// rollout status` double as "every node finished sweeping".
func hostSweepDaemonSet(release, namespace string, cfg hostUninstallConfig) *appsv1.DaemonSet {
	labels := map[string]string{
		"app.kubernetes.io/name":      "c8s-operator",
		"app.kubernetes.io/instance":  release,
		"app.kubernetes.io/component": "host-sweep",
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
			Name:      hostSweepName(release),
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
					Tolerations:      []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					InitContainers: []corev1.Container{{
						Name:            "sweep",
						Image:           cfg.SweepImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"/bin/sh", "-c"},
						Args:            []string{hostSweepScript},
						Env: []corev1.EnvVar{
							{Name: "HOST_CONTAINERD_DIR", Value: cfg.ContainerdConfigDir},
							{Name: "RKE2_PREP", Value: strconv.FormatBool(cfg.Distro == "rke2")},
							{Name: "RESTART_COMMAND", Value: hostRestartCommand(cfg.Distro)},
							{Name: "NRI_CONTAINERD_DIR", Value: cfg.NriContainerdDir},
							{Name: "NRI_PLUGIN_DIR", Value: cfg.NriPluginDir},
							{Name: "NRI_PLUGIN_FILENAME", Value: cfg.NriPluginFilename},
							{Name: "NRI_CONFIG_DIR", Value: cfg.NriConfigDir},
							{Name: "NRI_RUNTIME_DIR", Value: cfg.NriRuntimeDir},
							{Name: "NRI_CACHE_DIR", Value: cfg.NriCacheDir},
						},
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
	uninstallCmd.Flags().BoolVar(&uninstallWait, "wait", true, "wait for the release deletion to complete (helm --wait); the host sweep additionally waits for the host pods to be gone either way")
	uninstallCmd.Flags().BoolVar(&uninstallHostSweep, "host-sweep", true, "after deleting the release, clean chart-installed NRI policy and mesh network state on every node; preserves baked node components")
	uninstallCmd.Flags().BoolVar(&uninstallHostSweepOnly, "host-sweep-only", false, "skip the helm uninstall and only run the host sweep — for a cluster whose release is already gone (e.g. a previous bare 'helm uninstall') but whose nodes still carry c8s artifacts. Uses the chart defaults and the distro detected from the cluster when the release values are unavailable")
	uninstallCmd.Flags().BoolVar(&uninstallForce, "force", false, "uninstall while pods still hold c8s encrypted volumes; their live mappings may prevent the teardown hook from completing")
	uninstallCmd.Flags().BoolVar(&uninstallDeleteCRDs, "delete-crds", false, "also delete the ConfidentialWorkload CRD — this deletes EVERY ConfidentialWorkload object in the cluster with it")
	uninstallCmd.Flags().BoolVar(&uninstallDeleteNamespace, "delete-namespace", false, "also delete the release namespace (and everything left in it, e.g. an operator-created image pull Secret)")
	rootCmd.AddCommand(uninstallCmd)
}
