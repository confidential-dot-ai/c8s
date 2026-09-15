// Tests for the chart's argv-pinned seed entries (c8s.argvPinnedEntries):
// platform images that carry a shell — the nri-image-policy installer image
// and the rke2 busybox uses (containerd-prep, local-path helper) — must be
// admitted by the served allowlist only under their exact expected argv,
// never by digest alone. The boot config's always_allow is digest-only
// admission, so it must not carry any of them either.
package helmchart

import (
	"os"
	"regexp"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	corev1 "k8s.io/api/core/v1"
)

const (
	// prepBusyboxDigest is values.yaml's nriImagePolicy.containerdPrep.image.digest.
	prepBusyboxDigest = "sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028"
	// localPathHelperManifest is the node image's baked local-path provisioner
	// manifest, whose helper pod the rke2.localPathHelper values pin in lockstep.
	localPathHelperManifest = "../../node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/local-path-storage.yaml"
)

// renderedSeed parses the allowlist document out of the rendered CDS seed
// ConfigMap — the same JSON CDS feeds to pkg/allowlist.ParseJSON at startup.
func renderedSeed(t *testing.T, manifest string) *pkgallowlist.Allowlist {
	t.Helper()
	cm := renderedConfigMap(t, manifest, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	return seed
}

// effectiveArgv is the OCI process.args an enforcer observes: the pod spec's
// command and args concatenated.
func effectiveArgv(c corev1.Container) []string {
	return append(append([]string{}, c.Command...), c.Args...)
}

// admitArgvs fails unless the seed admits (digest, argv) via some entry.
func admitArgvs(t *testing.T, seed *pkgallowlist.Allowlist, digest string, argv []string) {
	t.Helper()
	if !seed.BuildIndex().AdmitsContainer(pkgallowlist.RunningContainer{Digest: digest, Argv: argv}) {
		t.Errorf("seed does not admit %s argv %q", digest[:19], argv[:2])
	}
}

// denyArgvs fails if the seed admits (digest, argv) via any entry.
func denyArgvs(t *testing.T, seed *pkgallowlist.Allowlist, digest string, argv []string) {
	t.Helper()
	if seed.BuildIndex().AdmitsContainer(pkgallowlist.RunningContainer{Digest: digest, Argv: argv}) {
		t.Errorf("seed admits %s argv %q — the argv pin is not enforcing", digest[:19], argv[:2])
	}
}

// Every container the chart runs from the nri-image-policy image — the
// installer DaemonSet's install init and pause, the uninstall hook's
// uninstall init and pause — must be admitted by the seed under its exact
// rendered argv, and nothing else from that image may be admitted.
func TestChartPinnedSeedAdmitsNriInstallerArgv(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)

	worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	for _, c := range allContainers(&worker) {
		admitArgvs(t, seed, baseNRIDigest, effectiveArgv(c))
	}
	uninstall := renderedDaemonSet(t, out, "c8s-nri-image-policy-uninstall")
	for _, c := range allContainers(&uninstall) {
		admitArgvs(t, seed, baseNRIDigest, effectiveArgv(c))
	}

	// The pin is argv-exact: any other command line from the same image is denied.
	denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "-c", "rm -rf /"})
	denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "/tmp/x"})
	denyArgvs(t, seed, baseNRIDigest, []string{"sleep", "infinity"}) // argv[0] must be /bin/sh
}

// The node-as-CVM (baked) installer runs the pins script instead of the
// install script; the seed must admit exactly that argv from the nri image.
func TestChartPinnedSeedAdmitsBakedPinsArgv(t *testing.T) {
	out, err := helmTemplate(t, "--set", "nriImagePolicy.baked=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	for _, c := range allContainers(&worker) {
		admitArgvs(t, seed, baseNRIDigest, effectiveArgv(c))
	}
	denyArgvs(t, seed, baseNRIDigest, []string{"/bin/sh", "-c", "rm -rf /"})
}

// On rke2 the installer DaemonSet's containerd-prep initContainer runs the
// busybox prep image under the prep script; the seed must admit that exact
// argv and no other from that image.
func TestChartPinnedSeedAdmitsRKE2ContainerdPrepArgv(t *testing.T) {
	out, err := helmTemplate(t, "--set", "nriImagePolicy.distro=rke2")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	prep, ok := findContainer(worker.Spec.Template.Spec.InitContainers, "containerd-prep")
	if !ok {
		t.Fatalf("rke2 render missing the containerd-prep initContainer")
	}
	admitArgvs(t, seed, prepBusyboxDigest, effectiveArgv(prep))
	denyArgvs(t, seed, prepBusyboxDigest, []string{"/bin/sh", "-c", "rm -rf /"})
	denyArgvs(t, seed, prepBusyboxDigest, []string{"/bin/sh", "/script/setup"})
}

// The local-path helper entry pins the node image's baked helper pod to its
// two provisioner command prefixes; the per-PVC flags stay open.
func TestChartPinnedSeedAdmitsLocalPathHelperArgv(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	helperDigest := localPathHelperDigest(t)

	for _, script := range []string{"/script/setup", "/script/teardown"} {
		admitArgvs(t, seed, helperDigest, []string{
			"/bin/sh", script,
			"-p", "/opt/local-path-provisioner/pvc-123", "-s", "1073741824", "-m", "Filesystem", "-a", "create",
		})
	}
	denyArgvs(t, seed, helperDigest, []string{"/bin/sh", "-c", "rm -rf /"})
	denyArgvs(t, seed, helperDigest, []string{"/bin/sh", "/script/setup-evil"})
	denyArgvs(t, seed, helperDigest, []string{"/bin/busybox", "/script/setup"})
}

// always_allow is digest-only admission — carrying an argv-pinned image there
// would bypass the pin. Neither the installer image nor any busybox may
// appear, in either the k8s or the rke2 shape.
func TestChartPinnedDigestsAbsentFromBootConfig(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--set", "nriImagePolicy.distro=rke2"},
	} {
		out, err := helmTemplate(t, args...)
		if err != nil {
			t.Fatalf("helm template %v: %v\n%s", args, err, out)
		}
		cfg := bootConfigFromInstaller(t, out, "c8s-nri-image-policy-worker")
		if len(cfg.Allowlist.AlwaysAllow) == 0 {
			t.Fatalf("always_allow must stay non-empty (pull bootstrap): %v", args)
		}
		for digest, image := range cfg.Allowlist.AlwaysAllow {
			if digest == baseNRIDigest {
				t.Errorf("installer image self-allowed in always_allow (%v): the argv pin would be bypassed", args)
			}
			if strings.Contains(image, "busybox") {
				t.Errorf("busybox %s in always_allow (%v): admits any command line on any pod", digest, args)
			}
		}
	}
}

// localPathHelperDigest reads the helper image digest the chart pins from
// values.yaml and proves it is the digest the node image's baked manifest
// runs, with no setupCommand/teardownCommand override that would change the
// helper's effective argv away from the pinned prefixes.
func localPathHelperDigest(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("c8s/values.yaml")
	if err != nil {
		t.Fatalf("read values.yaml: %v", err)
	}
	m := regexp.MustCompile(`(?ms)localPathHelper:\s*
\s*image:\s*
\s*repository: (\S+)\s*
\s*digest: "?(sha256:[0-9a-f]{64})"?`).FindSubmatch(raw)
	if m == nil {
		t.Fatalf("rke2.localPathHelper.image not found in values.yaml")
	}
	repo, digest := string(m[1]), string(m[2])

	manifest, err := os.ReadFile(localPathHelperManifest)
	if err != nil {
		t.Fatalf("read node-image manifest: %v", err)
	}
	helper := regexp.MustCompile(`(?ms)helperPod.yaml:.*?image: (\S+?@(sha256:[0-9a-f]{64}))`).FindSubmatch(manifest)
	if helper == nil {
		t.Fatalf("no digest-pinned helper image in %s", localPathHelperManifest)
	}
	// The manifest ref may carry a tag beside the digest (busybox:1.38.0@…);
	// the repository is the ref before "@", with any ":tag" stripped.
	manifestRepo, _, _ := strings.Cut(string(helper[1]), "@")
	manifestRepo, _, _ = strings.Cut(manifestRepo, ":")
	if manifestRepo != repo || string(helper[2]) != digest {
		t.Fatalf("helper image drift: chart pins %s@%s, node image runs %s — bump rke2.localPathHelper.image", repo, digest, helper[1])
	}
	for _, key := range []string{"setupCommand", "teardownCommand"} {
		if strings.Contains(string(manifest), key) {
			t.Fatalf("%s sets %s: the helper's argv is then %s, not the seeded /script pin", localPathHelperManifest, key, key)
		}
	}
	return digest
}

// An any-argv entry for a pinned digest voids the pin (admission is the union
// across entries): with deriveComponents on, the derive loop must never emit
// one for the installer or busybox images — the argvPinned skip is the only
// thing between the pin and a silent any-argv shadow.
func TestChartPinnedSeedHasNoAnyArgvShadow(t *testing.T) {
	out, err := helmTemplate(t,
		"--set", "nriImagePolicy.distro=rke2",
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	seed := renderedSeed(t, out)
	for _, digest := range []string{baseNRIDigest, prepBusyboxDigest, localPathHelperDigest(t)} {
		for name, w := range seed.Workloads {
			for _, c := range append(append([]pkgallowlist.Container{}, w.Containers...), w.InitContainers...) {
				if c.Digest.String() == digest && c.AnyArgv() {
					t.Errorf("entry %q grants any argv for pinned digest %s — the pin is void", name, digest[:19])
				}
			}
		}
	}
}
