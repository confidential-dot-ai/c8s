//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	staticCDSDigest      = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	staticOperatorDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	staticTenantDigest   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// sealedEntry is a complete unprivileged rule for image at digest.
func sealedEntry(image, digest string) string {
	return `{"digest":"` + digest + `","image":"` + image + `@` + digest + `",` +
		`"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},` +
		`"mounts":{"policy":"exact","destinations":["/etc/hosts"],"rules":{"/etc/hosts":{"source":"platform"}}},` +
		`"env":{"policy":"exact","names":["PATH"],"values":{"PATH":{"value":"/bin"}}}}`
}

// writeStaticFixture writes a bundle directory naming the cds and operator
// images plus a tenant, and a TDX manifest; both are what --static-allowlist
// and --image-manifest take.
func writeStaticFixture(t *testing.T) (bundleDir, manifest string, al *pkgallowlist.Allowlist) {
	t.Helper()
	doc := `{"schema":"c8s.allowlist/v1","digests":{},"workloads":{` +
		`"cds":{"containers":[` + sealedEntry("ghcr.io/confidential-dot-ai/cds", staticCDSDigest) + `]},` +
		`"operator":{"containers":[` + sealedEntry("ghcr.io/confidential-dot-ai/c8s", staticOperatorDigest) + `]},` +
		`"web":{"containers":[` + sealedEntry("registry.example/web", staticTenantDigest) + `]}}}`
	parsed, err := pkgallowlist.ParseJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := parsed.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	bundleDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(bundleDir, policybundle.MemberStaticAllowlist), canonical, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest = filepath.Join(t.TempDir(), "manifest.json")
	content := `{"mrtd":"` + strings.Repeat("1a", 48) + `","rtmr1":"` + strings.Repeat("2b", 48) + `","rtmr2":"` + strings.Repeat("3c", 48) + `"}`
	if err := os.WriteFile(manifest, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return bundleDir, manifest, parsed
}

// staticFlags sets the install flag state of a static node/tdx install and
// restores everything at cleanup.
func staticFlags(t *testing.T, bundle, manifest string) *cobra.Command {
	t.Helper()
	resetCLIState(t)
	installCvmMode, installHardwarePlatform = "node", "tdx"
	installStaticAllowlist, installImageManifest = bundle, manifest
	cmd := &cobra.Command{}
	cmd.Flags().String(flagCvmMode, "node", "")
	cmd.Flags().BoolVar(&installResolveDigests, "resolve-digests", true, "")
	return cmd
}

func TestStaticInstallPreflightFlagRules(t *testing.T) {
	bundle, manifest, _ := writeStaticFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(cmd *cobra.Command)
		want   string
	}{
		{"no image manifest", func(*cobra.Command) { installImageManifest = "" }, "requires --image-manifest"},
		{"pod mode", func(*cobra.Command) { installCvmMode = "pod" }, "--cvm-mode=node"},
		{"snp", func(*cobra.Command) { installHardwarePlatform = "sev-snp" }, "--hardware-platform=tdx"},
		{"operator keys", func(*cobra.Command) { installOperatorKeys = "keys.pem" }, "--operator-keys"},
		{"measurements", func(*cobra.Command) { installMeasurements = []string{"aa"} }, "--measurements"},
		{"measurements config", func(*cobra.Command) { installMeasurementsConfig = "m.json" }, "--measurements-config"},
		{"rtmrs", func(*cobra.Command) { installRTMRs = []string{"1=aa"} }, "--rtmrs"},
		{"node attest without a bundle", func(*cobra.Command) {
			installStaticAllowlist = ""
			installStaticNodeAttest = map[string]string{"a": "203.0.113.9:8400"}
		}, "--static-node-attest requires --static-allowlist"},
		{"node attest without a port", func(*cobra.Command) {
			installStaticNodeAttest = map[string]string{"a": "203.0.113.9"}
		}, "--static-node-attest a=203.0.113.9"},
		{"explicit resolve-digests", func(cmd *cobra.Command) {
			if err := cmd.Flags().Set("resolve-digests", "true"); err != nil {
				t.Fatal(err)
			}
		}, "--resolve-digests=true"},
		{"iso bundle", func(*cobra.Command) { installStaticAllowlist = filepath.Join(bundle, "policydata.iso") }, "ISO images cannot be read here"},
		{"snp manifest", func(*cobra.Command) {
			p := filepath.Join(t.TempDir(), "snp.json")
			if err := os.WriteFile(p, []byte(`{"version":3,"snp_variants":[]}`), 0o600); err != nil {
				t.Fatal(err)
			}
			installImageManifest = p
		}, "--image-manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := staticFlags(t, bundle, manifest)
			tc.mutate(cmd)
			err := staticInstallPreflight(cmd)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("staticInstallPreflight(%s) = %v, want error containing %q", tc.name, err, tc.want)
			}
			if staticState != nil {
				t.Errorf("staticInstallPreflight(%s) left state loaded after refusing", tc.name)
			}
		})
	}

	t.Run("valid", func(t *testing.T) {
		cmd := staticFlags(t, bundle, manifest)
		if err := staticInstallPreflight(cmd); err != nil {
			t.Fatalf("staticInstallPreflight: %v", err)
		}
		if installResolveDigests {
			t.Error("installResolveDigests left on; a static install must not consult a registry")
		}
		if staticState == nil {
			t.Fatal("staticState not loaded")
		}
		doc, err := os.ReadFile(staticState.measurementsFile)
		if err != nil {
			t.Fatalf("measurements file: %v", err)
		}
		set, err := measurements.Parse(doc)
		if err != nil {
			t.Fatalf("Parse(measurements file) = %v", err)
		}
		entry, err := set.StaticEntry()
		if err != nil {
			t.Fatalf("StaticEntry() = %v", err)
		}
		if want := staticState.bundle.RTMR3(); !bytes.Equal(entry.RTMRs[3], want[:]) {
			t.Errorf("entry RTMR[3] = %x, want the bundle's %x", entry.RTMRs[3], want)
		}
		file := staticState.measurementsFile
		cleanupStaticInstall()
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Errorf("cleanup left %s behind: %v", file, err)
		}
	})

	t.Run("unsealed member", func(t *testing.T) {
		dir := t.TempDir()
		data, _ := os.ReadFile(filepath.Join(bundle, policybundle.MemberStaticAllowlist))
		if err := os.WriteFile(filepath.Join(dir, policybundle.MemberStaticAllowlist), append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := staticFlags(t, dir, manifest)
		err := staticInstallPreflight(cmd)
		if err == nil || !strings.Contains(err.Error(), "not its canonical form") {
			t.Fatalf("staticInstallPreflight(unsealed) = %v, want the sealed lint error", err)
		}
	})
}

// The flat lists carry the image tuple only: RTMR[3] would otherwise reach
// container argv, and the bundle carrying that argv is what the register is
// derived from (see pinArgs).
func TestInstallPinsStaticKeepsRTMR3OutOfTheFlatLists(t *testing.T) {
	bundle, manifest, _ := writeStaticFixture(t)
	cmd := staticFlags(t, bundle, manifest)
	if err := staticInstallPreflight(cmd); err != nil {
		t.Fatal(err)
	}
	digests, rtmrs, helmArgs, err := installPins()
	if err != nil {
		t.Fatalf("installPins: %v", err)
	}
	if len(digests) != 1 || hex.EncodeToString(digests[0]) != strings.Repeat("1a", 48) {
		t.Errorf("digests = %x, want the manifest MRTD only", digests)
	}
	if _, pinned := rtmrs[3]; pinned || len(rtmrs) != 2 {
		t.Errorf("flat rtmrs = %v, want RTMR[1] and RTMR[2] only", rtmrs)
	}
	joined := strings.Join(helmArgs, " ")
	for _, want := range []string{"--set-file cds.measurementsConfig=" + staticState.measurementsFile, "--set-file ratlsMesh.measurementsConfig=" + staticState.measurementsFile} {
		if !strings.Contains(joined, want) {
			t.Errorf("helm args %v missing %s", helmArgs, want)
		}
	}

	got, err := appendCvmModeInstallArgs([]string{"upgrade"}, "node", "tdx")
	if err != nil {
		t.Fatalf("appendCvmModeInstallArgs: %v", err)
	}
	for _, arg := range got {
		if strings.HasPrefix(arg, "cds.rtmrs[") && strings.HasPrefix(strings.SplitN(arg, "=", 2)[1], "3=") {
			t.Errorf("flat value %q pins RTMR[3]", arg)
		}
	}
	if !slices.Contains(got, "cds.rtmrs[0]=1="+strings.Repeat("2b", 48)) {
		t.Errorf("args %v missing the RTMR[1] flat pin", got)
	}
}

func TestStaticDigestArgs(t *testing.T) {
	_, _, al := writeStaticFixture(t)
	components := []c8sComponent{
		{valuePrefix: "cds.image", repository: "ghcr.io/confidential-dot-ai/cds"},
		{valuePrefix: "image", repository: "ghcr.io/confidential-dot-ai/c8s"},
		{valuePrefix: "nriImagePolicy.image", repository: "ghcr.io/confidential-dot-ai/nri-image-policy", enabledPath: "nriImagePolicy.enabled"},
	}
	enabled := func(path string) (bool, error) { return path != "nriImagePolicy.enabled", nil }

	got, err := staticDigestArgs(nil, components, al, enabled)
	if err != nil {
		t.Fatalf("staticDigestArgs: %v", err)
	}
	for _, want := range []string{
		"cds.image.repository=ghcr.io/confidential-dot-ai/cds", "cds.image.digest=" + staticCDSDigest,
		"image.repository=ghcr.io/confidential-dot-ai/c8s", "image.digest=" + staticOperatorDigest,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("args %v missing %s", got, want)
		}
	}
	if slices.ContainsFunc(got, func(a string) bool { return strings.HasPrefix(a, "nriImagePolicy.image.") }) {
		t.Errorf("args %v pin the disabled plugin image", got)
	}

	// A component the bundle does not name is denied on the node: refuse.
	volumed := []c8sComponent{{valuePrefix: "volumed.image", repository: "ghcr.io/confidential-dot-ai/volumed"}}
	if _, err := staticDigestArgs(nil, volumed, al, enabled); err == nil || !strings.Contains(err.Error(), "no entry in the bundle names image ghcr.io/confidential-dot-ai/volumed") {
		t.Errorf("staticDigestArgs(unlisted component) = %v, want a refusal naming the image", err)
	}

	// Two digests for one repository leave nothing to pick.
	two := *al
	two.Workloads = map[string]pkgallowlist.Workload{}
	for k, v := range al.Workloads {
		two.Workloads[k] = v
	}
	dup := al.Workloads["cds"]
	dup.Containers = []pkgallowlist.Container{{Digest: mustDigest(t, staticTenantDigest), Image: "ghcr.io/confidential-dot-ai/cds:other"}}
	two.Workloads["cds-other"] = dup
	if _, err := staticDigestArgs(nil, components[:1], &two, enabled); err == nil || !strings.Contains(err.Error(), "names 2 digests") {
		t.Errorf("staticDigestArgs(ambiguous) = %v, want a refusal", err)
	}
}

func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// The shared builder in static mode: no tags, the mode values, the bundle's
// digests and the measurements file all reach the values tree.
func TestBuildValueArgsStaticAllowlist(t *testing.T) {
	bundle, manifest, _ := writeStaticFixture(t)
	f := newFakeBin(t)
	f.tool(t, "helm", helmShowValuesBody)
	chart := writeChart(t, "nriImagePolicy:\n  enabled: true\ncds:\n  image:\n    repository: ghcr.io/confidential-dot-ai/cds\n")
	cmd := staticFlags(t, bundle, manifest)
	if err := staticInstallPreflight(cmd); err != nil {
		t.Fatal(err)
	}
	components := []c8sComponent{
		{valuePrefix: "cds.image", repository: "ghcr.io/confidential-dot-ai/cds"},
		{valuePrefix: "nriImagePolicy.image", repository: "ghcr.io/confidential-dot-ai/nri-image-policy", enabledPath: "nriImagePolicy.enabled"},
	}
	args, err := buildValueArgs(context.Background(), cmd, chart, components, "main", "rke2", appendResolvedDigestArgs)
	if err != nil {
		t.Fatalf("buildValueArgs: %v", err)
	}
	tree, err := valueArgsToTree(args)
	if err != nil {
		t.Fatalf("valueArgsToTree: %v", err)
	}
	image := treeAt(t, tree, "cds", "image").(map[string]any)
	if _, hasTag := image["tag"]; hasTag {
		t.Errorf("static values emit a tag beside the bundle digest: %#v", image)
	}
	if image["digest"] != staticCDSDigest {
		t.Errorf("cds.image.digest = %#v, want %s from the bundle", image["digest"], staticCDSDigest)
	}
	if got := treeAt(t, tree, "staticAllowlist", "enabled"); got != true {
		t.Errorf("staticAllowlist.enabled = %#v, want true", got)
	}
	if got := treeAt(t, tree, "nriImagePolicy", "enabled"); got != false {
		t.Errorf("nriImagePolicy.enabled = %#v, want false", got)
	}
	if got := treeAt(t, tree, "cds", "persistence", "enabled"); got != false {
		t.Errorf("cds.persistence.enabled = %#v, want false", got)
	}
	config, _ := treeAt(t, tree, "cds", "measurementsConfig").(string)
	set, err := measurements.Parse([]byte(config))
	if err != nil {
		t.Fatalf("cds.measurementsConfig does not parse: %v\n%s", err, config)
	}
	if _, err := set.StaticEntry(); err != nil {
		t.Errorf("cds.measurementsConfig is not a static entry: %v", err)
	}
	if _, pinned := treeAt(t, tree, "nriImagePolicy").(map[string]any)["image"]; pinned {
		t.Error("the disabled plugin image was pinned from the bundle")
	}
}

func nodeListFile(t *testing.T, nodes ...corev1.Node) string {
	t.Helper()
	data, err := json.Marshal(corev1.NodeList{Items: nodes})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nodes.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func node(name, ip string) corev1.Node {
	n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if ip != "" {
		n.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}}
	}
	return n
}

func TestPreflightStaticNodes(t *testing.T) {
	bundle, manifest, _ := writeStaticFixture(t)
	cmd := staticFlags(t, bundle, manifest)
	if err := staticInstallPreflight(cmd); err != nil {
		t.Fatal(err)
	}
	wantRTMR3 := staticState.bundle.RTMR3()

	type call struct {
		url   string
		rtmr3 [runtimemeasure.Size]byte
	}
	var calls []call
	verdicts := map[string]error{}
	prev := staticNodeVerifier
	staticNodeVerifier = func(_ context.Context, attestURL string, pins runtimemeasure.ImagePins, rtmr3 [runtimemeasure.Size]byte) error {
		calls = append(calls, call{attestURL, rtmr3})
		if hex.EncodeToString(pins.MRTD[:]) != strings.Repeat("1a", 48) {
			t.Errorf("verifier got MRTD %x, want the manifest's", pins.MRTD)
		}
		return verdicts[attestURL]
	}
	t.Cleanup(func() { staticNodeVerifier = prev })

	t.Run("every node attested at its InternalIP", func(t *testing.T) {
		calls = nil
		f := newFakeBin(t)
		f.tool(t, "kubectl", `/bin/cat "`+nodeListFile(t, node("a", "10.0.0.1"), node("b", "fd00::2"))+`"`)
		var out bytes.Buffer
		if err := preflightStaticNodes(context.Background(), &out, staticState); err != nil {
			t.Fatalf("preflightStaticNodes: %v", err)
		}
		mustContainLine(t, f.calls(t), "kubectl get nodes -o json")
		want := []string{"http://10.0.0.1:8400/attest", "http://[fd00::2]:8400/attest"}
		for i, c := range calls {
			if c.url != want[i] || c.rtmr3 != wantRTMR3 {
				t.Errorf("call %d = %s %x, want %s %x", i, c.url, c.rtmr3, want[i], wantRTMR3)
			}
		}
		if len(calls) != 2 {
			t.Fatalf("verifier called %d times, want once per node", len(calls))
		}
		if !strings.Contains(out.String(), "+ node a: static mode") || !strings.Contains(out.String(), "+ node b: static mode") {
			t.Errorf("progress = %q, want a line per node", out.String())
		}
	})

	t.Run("an unsealed node fails the install", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `/bin/cat "`+nodeListFile(t, node("a", "10.0.0.1"), node("b", "10.0.0.2"))+`"`)
		verdicts["http://10.0.0.2:8400/attest"] = context.DeadlineExceeded
		t.Cleanup(func() { delete(verdicts, "http://10.0.0.2:8400/attest") })
		err := preflightStaticNodes(context.Background(), &bytes.Buffer{}, staticState)
		if err == nil || !strings.Contains(err.Error(), "node b (10.0.0.2:8400) is not sealed to this bundle") {
			t.Fatalf("preflightStaticNodes = %v, want node b named", err)
		}
	})

	t.Run("a node without an address fails", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `/bin/cat "`+nodeListFile(t, node("a", ""))+`"`)
		err := preflightStaticNodes(context.Background(), &bytes.Buffer{}, staticState)
		if err == nil || !strings.Contains(err.Error(), "no InternalIP") {
			t.Fatalf("preflightStaticNodes = %v, want the missing address named", err)
		}
	})

	t.Run("an override replaces the InternalIP of the node it names", func(t *testing.T) {
		calls = nil
		f := newFakeBin(t)
		f.tool(t, "kubectl", `/bin/cat "`+nodeListFile(t, node("a", "10.0.2.2"), node("b", ""))+`"`)
		staticState.nodeAttest = map[string]string{"a": "203.0.113.9:8400", "b": "[fd00::9]:8401"}
		t.Cleanup(func() { staticState.nodeAttest = nil })
		var out bytes.Buffer
		if err := preflightStaticNodes(context.Background(), &out, staticState); err != nil {
			t.Fatalf("preflightStaticNodes: %v", err)
		}
		want := []string{"http://203.0.113.9:8400/attest", "http://[fd00::9]:8401/attest"}
		if len(calls) != 2 {
			t.Fatalf("verifier called %d times, want once per node", len(calls))
		}
		for i, c := range calls {
			if c.url != want[i] {
				t.Errorf("call %d = %s, want %s", i, c.url, want[i])
			}
		}
		if !strings.Contains(out.String(), "attested at 203.0.113.9:8400, --static-node-attest") {
			t.Errorf("progress = %q, want the override named", out.String())
		}
	})

	t.Run("an override naming an absent node fails before any attest", func(t *testing.T) {
		calls = nil
		f := newFakeBin(t)
		f.tool(t, "kubectl", `/bin/cat "`+nodeListFile(t, node("a", "10.0.0.1"))+`"`)
		staticState.nodeAttest = map[string]string{"c": "203.0.113.9:8400", "b": "203.0.113.8:8400"}
		t.Cleanup(func() { staticState.nodeAttest = nil })
		err := preflightStaticNodes(context.Background(), &bytes.Buffer{}, staticState)
		if err == nil || !strings.Contains(err.Error(), "nodes the cluster does not have: b, c") {
			t.Fatalf("preflightStaticNodes = %v, want the absent nodes named", err)
		}
		if len(calls) != 0 {
			t.Errorf("verifier called %d times, want none", len(calls))
		}
	})

	t.Run("no nodes fails", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `/bin/cat "`+nodeListFile(t)+`"`)
		if err := preflightStaticNodes(context.Background(), &bytes.Buffer{}, staticState); err == nil {
			t.Fatal("preflightStaticNodes(no nodes) = nil, want an error")
		}
	})
}

func TestUnlistedImages(t *testing.T) {
	_, _, al := writeStaticFixture(t)
	admitted := bundleDigests(al)
	status := func(image, id string) corev1.ContainerStatus {
		return corev1.ContainerStatus{Image: image, ImageID: id}
	}
	pod := func(ns, name string, phase corev1.PodPhase, statuses ...corev1.ContainerStatus) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Status:     corev1.PodStatus{Phase: phase, ContainerStatuses: statuses},
		}
	}
	got := unlistedImages([]corev1.Pod{
		pod("c8s-system", "cds", corev1.PodRunning, status("ghcr.io/confidential-dot-ai/cds:v1", "ghcr.io/confidential-dot-ai/cds@"+staticCDSDigest)),
		pod("default", "web", corev1.PodRunning, status("registry.example/web:1", "registry.example/web@"+staticTenantDigest)),
		pod("kube-system", "cilium", corev1.PodRunning, status("quay.io/cilium/cilium:v1", "quay.io/cilium/cilium@sha256:4444444444444444444444444444444444444444444444444444444444444444")),
		pod("kube-system", "cilium-2", corev1.PodRunning, status("quay.io/cilium/cilium:v1", "quay.io/cilium/cilium@sha256:4444444444444444444444444444444444444444444444444444444444444444")),
		pod("default", "done", corev1.PodSucceeded, status("busybox:1", "docker.io/library/busybox@sha256:5555555555555555555555555555555555555555555555555555555555555555")),
		pod("default", "pending", corev1.PodPending, status("busybox:1", "")),
	}, admitted)
	want := []string{"kube-system/cilium  quay.io/cilium/cilium@sha256:4444444444444444444444444444444444444444444444444444444444444444"}
	if !slices.Equal(got, want) {
		t.Errorf("unlistedImages() = %v, want %v", got, want)
	}
}

func TestPreflightStaticImages(t *testing.T) {
	_, _, al := writeStaticFixture(t)
	running := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "extra"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Image: "quay.io/x/extra:1", ImageID: "quay.io/x/extra@sha256:6666666666666666666666666666666666666666666666666666666666666666",
		}}},
	}
	t.Run("unlisted image refused", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `/bin/cat "`+podListFile(t, running)+`"`)
		_, err := preflightStaticImages(context.Background(), al, false)
		if err == nil || !strings.Contains(err.Error(), "kube-system/extra  quay.io/x/extra@sha256:6666") {
			t.Fatalf("preflightStaticImages = %v, want the unlisted image named", err)
		}
		mustContainLine(t, f.calls(t), "kubectl get pods --all-namespaces -o json")
	})
	t.Run("force warns", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `/bin/cat "`+podListFile(t, running)+`"`)
		warn, err := preflightStaticImages(context.Background(), al, true)
		if err != nil || !strings.Contains(warn, "1 running image(s)") {
			t.Fatalf("preflightStaticImages(force) = %q, %v; want a warning", warn, err)
		}
	})
	t.Run("all listed passes", func(t *testing.T) {
		f := newFakeBin(t)
		f.tool(t, "kubectl", `/bin/cat "`+podListFile(t)+`"`)
		if warn, err := preflightStaticImages(context.Background(), al, false); err != nil || warn != "" {
			t.Fatalf("preflightStaticImages(empty cluster) = %q, %v; want quiet", warn, err)
		}
	})
}

func TestPrintStaticVerifyHint(t *testing.T) {
	resetCLIState(t)
	installStaticAllowlist, installImageManifest = "bundle/", "manifest.json"
	var out bytes.Buffer
	printAttestVerifyHint(&out, true)
	if !strings.Contains(out.String(), "c8s verify https://<tls-lb> --kind lb --image-manifest manifest.json --static-allowlist bundle/ --workload <entry> --mesh-ca <ca.pem>") {
		t.Errorf("hint = %q, want the static verify command", out.String())
	}
}
