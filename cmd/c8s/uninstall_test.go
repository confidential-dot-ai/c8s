//go:build !c8s_node

package main

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBuildHelmUninstallArgs(t *testing.T) {
	got := buildHelmUninstallArgs("c8s", "c8s-system", true)
	assertArgsEqual(t, got, []string{
		"uninstall", "c8s", "--namespace", "c8s-system", "--wait", "--timeout=5m",
	})

	got = buildHelmUninstallArgs("c8s", "c8s-system", false)
	assertArgsEqual(t, got, []string{"uninstall", "c8s", "--namespace", "c8s-system"})
}

// --host-sweep-only exists only to run the sweep, so combining it with
// --host-sweep=false asks for nothing and must error rather than silently
// no-op.
func TestValidateUninstallFlagsRejectsSweepOnlyWithoutSweep(t *testing.T) {
	if err := validateUninstallFlags(false, true); err == nil {
		t.Fatal("--host-sweep-only with --host-sweep=false: want error, got nil")
	}
	for _, tc := range []struct{ hostSweep, hostSweepOnly bool }{
		{true, true}, {true, false}, {false, false},
	} {
		if err := validateUninstallFlags(tc.hostSweep, tc.hostSweepOnly); err != nil {
			t.Errorf("hostSweep=%t hostSweepOnly=%t: unexpected error: %v", tc.hostSweep, tc.hostSweepOnly, err)
		}
	}
}

// The sweep must target exactly the directory the install wrote into — the
// same mapping as the chart's c8s.hostContainerdConfigDir helper.
func TestContainerdConfigDirFor(t *testing.T) {
	tests := []struct {
		name     string
		override string
		distro   string
		want     string
		wantErr  bool
	}{
		{name: "k8s", distro: "k8s", want: "/etc/containerd"},
		{name: "rke2", distro: "rke2", want: "/var/lib/rancher/rke2/agent/etc/containerd"},
		{name: "override wins over distro", override: "/etc/k0s/containerd.d", distro: "rke2", want: "/etc/k0s/containerd.d"},
		// An unknown distro with no override has no safe directory to sweep;
		// guessing would rm -rf the wrong place or silently miss the files.
		{name: "unknown distro fails", distro: "k3s", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := containerdConfigDirFor(tt.override, tt.distro)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %t", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("dir = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHostRestartCommandPerDistro(t *testing.T) {
	// RKE2 owns containerd inside its server/agent unit, so a bare containerd
	// restart there would not re-read the config.
	rke2 := hostRestartCommand("rke2")
	for _, unit := range []string{"rke2-server", "rke2-agent"} {
		if !strings.Contains(rke2, unit) {
			t.Errorf("rke2 restart command %q missing unit %q", rke2, unit)
		}
	}
	if got := hostRestartCommand("k8s"); got != "systemctl restart containerd" {
		t.Errorf("k8s restart command = %q, want plain containerd restart", got)
	}
}

// chartValuesTree decodes a YAML values document the way the uninstall reads
// helm output into a values tree.
func chartValuesTree(t *testing.T, doc string) map[string]any {
	t.Helper()
	var tree map[string]any
	if err := yaml.Unmarshal([]byte(doc), &tree); err != nil {
		t.Fatalf("unmarshal test values: %v", err)
	}
	return tree
}

// The sweep uses the release's NRI distro and host-path overrides.
func TestHostConfigFromValuesUsesNRIPaths(t *testing.T) {
	tree := chartValuesTree(t, `
nriImagePolicy:
  distro: k8s
  containerdPrep:
    image:
      repository: busybox
      tag: "1.37"
  hostPaths:
    pluginDir: /custom/nri/plugins
`)
	cfg, err := hostConfigFromValues(tree)
	if err != nil {
		t.Fatalf("hostConfigFromValues: %v", err)
	}
	if cfg.ContainerdConfigDir != "/etc/containerd" {
		t.Errorf("ContainerdConfigDir = %q, want /etc/containerd (nriImagePolicy.distro)", cfg.ContainerdConfigDir)
	}
	if cfg.NriPluginDir != "/custom/nri/plugins" {
		t.Errorf("NriPluginDir = %q, want the values override", cfg.NriPluginDir)
	}
}

func TestImagePullSecretNames(t *testing.T) {
	tree := chartValuesTree(t, `
imagePullSecret: regcred
imagePullSecrets:
  - name: regcred
  - name: mirrorcred
`)
	got := imagePullSecretNames(tree)
	want := []string{"regcred", "mirrorcred"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("imagePullSecretNames = %v, want %v (uniq, secret first)", got, want)
	}
	if got := imagePullSecretNames(map[string]any{}); len(got) != 0 {
		t.Errorf("imagePullSecretNames(empty) = %v, want none", got)
	}
}

func TestSweepImageRefRequiresPin(t *testing.T) {
	// Neither digest nor tag — never fall back to a floating default for a
	// privileged image with the host root mounted.
	tree := chartValuesTree(t, `
nriImagePolicy:
  containerdPrep:
    image:
      repository: busybox
      tag: ""
      digest: ""
`)
	if _, err := sweepImageRef(tree); err == nil {
		t.Fatal("unpinned containerdPrep image: want error, got nil")
	}
}

// On a host running the fail-closed NRI plugin the sweep pod's image must
// already be admitted; the plugin's own image is the one image guaranteed
// on the allowlist (the installer ran it).
func TestSweepImageRefPrefersNriImageOnNriReleases(t *testing.T) {
	tree := chartValuesTree(t, `
nriImagePolicy:
  containerdPrep:
    image:
      repository: busybox
      digest: "sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028"
  image:
    repository: ghcr.io/confidential-dot-ai/nri-image-policy
    digest: "sha256:aaa"
`)
	ref, err := sweepImageRef(tree)
	if err != nil {
		t.Fatalf("sweepImageRef: %v", err)
	}
	if ref != "ghcr.io/confidential-dot-ai/nri-image-policy@sha256:aaa" {
		t.Errorf("sweepImageRef = %q, want the NRI plugin image", ref)
	}
	// Unpinned NRI image (a release that never resolved it) falls back to
	// the containerd-prep busybox.
	tree = chartValuesTree(t, `
nriImagePolicy:
  containerdPrep:
    image:
      repository: busybox
      digest: "sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028"
  image:
    repository: ghcr.io/confidential-dot-ai/nri-image-policy
`)
	ref, err = sweepImageRef(tree)
	if err != nil {
		t.Fatalf("sweepImageRef: %v", err)
	}
	if ref != "busybox@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028" {
		t.Errorf("sweepImageRef = %q, want the busybox fallback", ref)
	}
}

// The volume guard keys on the webhook's volume-request annotation, and only
// on pods that still have a container to hold a mapping: a Succeeded or Failed
// pod has none, so counting it would refuse an uninstall with nothing to lose.
func TestFilterVolumePodsKeepsOnlyLivePodsHoldingVolumes(t *testing.T) {
	lines := []string{
		"default\tinference-0\tRunning\tweights=/tenant-a/volumes/weights",
		"default\tweb-0\tRunning\t", // no volume annotation
		"team-a\tloader-1\tPending\tmodel=/tenant-b/volumes/model",
		"team-b\timport-0\tSucceeded\tmodel=/tenant-b/volumes/model",
		"team-c\timport-1\tFailed\tmodel=/tenant-b/volumes/model",
		"", // trailing blank line from kubectl
		"malformed-line-no-tabs",
	}
	want := []string{"default/inference-0", "team-a/loader-1"}
	if got := filterVolumePods(lines); !reflect.DeepEqual(got, want) {
		t.Errorf("filterVolumePods = %v, want %v", got, want)
	}
}

// --force does not make the leak clean, and the text has to say so: the
// operator's only other chance to learn it is a hook log that goes with the
// release.
func TestForcedVolumePodsWarning(t *testing.T) {
	got := forcedVolumePodsWarning([]string{"default/inference-0", "tenant-a/rag-1"})
	for _, want := range []string{
		"default/inference-0",
		"tenant-a/rag-1",
		"re-run the uninstall",
		"volumed sweeps",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("warning does not carry %q:\n%s", want, got)
		}
	}
}

// TestHostSweepScriptMeshNetfilterNames pins the netfilter names the sweep
// script removes to the mesh's fixed contract (internal/cmds/ratlsmesh:
// jumpRules, managedChains, managedIPSetNames + the -TMP swap variants). The
// two cleanup paths must not drift: a name added or renamed on the mesh side
// must be added here too.
func TestHostSweepScriptMeshNetfilterNames(t *testing.T) {
	names := []string{
		// Base-chain jumps (as "parent -j chain" in -D form).
		"-D OUTPUT -j RATLS-MESH",
		"-D PREROUTING -j RATLS-MESH-PREROUTING",
		"-D FORWARD -j RATLS-MESH-CW",
		"-D FORWARD -j RATLS-MESH-CW-EGRESS",
		// Chains (as "table:chain" sweep specs).
		"nat:RATLS-MESH",
		"nat:RATLS-MESH-PREROUTING",
		"filter:RATLS-MESH-CW",
		"filter:RATLS-MESH-CW-EGRESS",
		// ipsets.
		"RATLS-MESH-PODS",
		"RATLS-MESH-PODS6",
		"RATLS-MESH-LOCAL-PODS",
		"RATLS-MESH-LOCAL-PODS6",
		"RATLS-MESH-CW-PODS",
		"RATLS-MESH-CW-PODS6",
	}
	for _, name := range names {
		// Delimit the match so a suffixed sibling (RATLS-MESH-PODS6) cannot
		// satisfy a missing shorter name (RATLS-MESH-PODS).
		if !strings.Contains(hostSweepScript, name+" ") && !strings.Contains(hostSweepScript, name+"\n") {
			t.Errorf("host-sweep.sh does not sweep %q (mesh netfilter contract)", name)
		}
	}
	// The -TMP swap variants are destroyed alongside each ipset.
	if !strings.Contains(hostSweepScript, `"$s-TMP"`) {
		t.Error("host-sweep.sh does not destroy the -TMP ipset swap variants")
	}
}
