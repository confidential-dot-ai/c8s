// Chart test harness: TestMain copies the chart sources to a private tmpdir
// and materializes the vendored trees there (embed.go's Materialize, the
// Extract-time twin of sync.sh), so test binaries never race the repo's
// gitignored vendored dirs. helmTemplate renders a shape chart with the base
// values every render needs, and the helpers below decode the rendered
// multi-doc YAML into typed objects. Shape-agnostic behavior lives in
// shared_test.go (rendered against node-metal, the chart with the fullest
// default set); per-shape assertions live in pod_test.go, node_cloud_test.go,
// node_metal_test.go and node_image_test.go.
package helmchart

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigsyaml "sigs.k8s.io/yaml"
)

// The shape chart directories, one per install shape.
const (
	chartPod       = "pod"
	chartNodeCloud = "node-cloud"
	chartNodeMetal = "node-metal"
	chartNodeImage = "node-image"
)

var (
	// chartSrcDir is the package's source dir, captured before TestMain
	// chdirs into the private chart copy.
	chartSrcDir string
	// chartDirs lists every shape chart dir in stable order.
	chartDirs = []string{chartPod, chartNodeCloud, chartNodeMetal, chartNodeImage}
	// nodeChartDirs lists the node-as-CVM charts (host-side mesh, attestation,
	// and image policy).
	nodeChartDirs = []string{chartNodeCloud, chartNodeMetal, chartNodeImage}
)

func TestMain(m *testing.M) {
	// Work on a private copy of the chart sources: concurrent test binaries
	// and ad-hoc helm invocations must not race the vendored materialization.
	// Tests reference the charts by relative dir ("pod", ...), so chdir into
	// the copy after materializing it (the Materialize half of sync.sh).
	// Tests that reach repo files outside the chart tree (gen_schema.py,
	// kata-guest-base, node-guest-image) anchor on this absolute path — the
	// package dir — since the chdir below moves relative references.
	srcDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "getwd: %v\n", err)
		os.Exit(1)
	}
	chartSrcDir = srcDir

	tmp, err := os.MkdirTemp("", "c8s-chart-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mktemp: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)
	for _, dir := range append([]string{"lib", "crds", "scripts", "testdata"}, chartDirs...) {
		if err := copyDirNoVendored(dir, filepath.Join(tmp, dir)); err != nil {
			fmt.Fprintf(os.Stderr, "copy %s: %v\n", dir, err)
			os.Exit(1)
		}
	}
	for _, shape := range chartDirs {
		if err := Materialize(filepath.Join(tmp, shape), tmp, Shape(shape)); err != nil {
			fmt.Fprintf(os.Stderr, "materialize %s: %v\n", shape, err)
			os.Exit(1)
		}
	}
	if err := os.Chdir(tmp); err != nil {
		fmt.Fprintf(os.Stderr, "chdir: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// copyDirNoVendored copies a chart-source directory, skipping the vendored
// trees (charts/, crds/, files/) sync.sh produces inside the shape charts.
func copyDirNoVendored(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			// The shape charts carry gitignored vendored trees (charts/,
			// crds/, files/) produced by sync.sh; the crds/ source dir is
			// itself copied and has no such children.
			switch rel {
			case "charts", "files":
				return filepath.SkipDir
			case "crds":
				if filepath.Base(src) != "crds" {
					return filepath.SkipDir
				}
			}
			return os.MkdirAll(filepath.Join(dst, rel), info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, info.Mode())
	})
}

// testImageDigest is a syntactically valid digest for pod-chart renders: the
// guest admits only digest-pinned references, so the pod shape requires
// image.digest (kind=kata_image_digest).
const testImageDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// baseNRIDigest is the nri-image-policy image digest the shared harness pins
// and covers in the allowlist floor, so the default fail-closed render is valid.
const baseNRIDigest = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"

// helmTemplate renders the named shape chart with the base values every render
// of that shape needs, plus args. Base values pin every component image tag
// and, on the node charts, the fail-closed allowlist floor the
// uncovered_component_digest guard requires. Tests override a base value by
// repeating the key (last --set wins).
func helmTemplate(t *testing.T, chart string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	base := []string{
		"template", "c8s", chart,
		// Pin the simulated cluster version at the chart's kubeVersion floor
		// so the tests do not depend on the helm client's compiled default.
		"--kube-version", "1.30.0",
		"--namespace", "c8s-system",
		"--set", "image.tag=dev",
		"--set", "cds.image.tag=dev",
		"--set", "cds.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000001",
		// A c8s-<id> headless-Service address (what `c8s install --upstream`
		// derives) is the representative mesh-wrapped baseline. Tests for the
		// manual-upstream paths clear it via noUpstreamArgs.
		"--set-string", "tlsLb.upstream.address=c8s-infer.c8s-system.svc.cluster.local:8000",
	}
	if chart == chartPod {
		base = append(base, "--set-string", "image.digest="+testImageDigest)
	} else {
		base = append(base,
			"--set", "ratlsMesh.image.tag=dev",
			"--set", "nriImagePolicy.image.tag=dev",
			"--set", "nriImagePolicy.image.digest="+baseNRIDigest,
			"--set-string", "nriImagePolicy.bootstrapAllowlist.digests."+baseNRIDigest+"=ghcr.io/confidential-dot-ai/nri-image-policy@"+baseNRIDigest,
			// volumed is off by default, so its image is unused unless a test
			// enables it; set the tag here so those tests need not repeat it.
			"--set", "volumed.image.tag=dev",
		)
		if chart != chartNodeImage {
			base = append(base, "--set", "attestationApi.image.tag=dev")
		}
	}
	cmd := exec.Command("helm", append(base, args...)...)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// helmTemplateTLSLB renders only the tls-lb templates of the node-metal chart
// (the shape-agnostic front door), prefixing every caller --set/--set-string
// path with tlsLb. so tls-lb-relative test values (upstream.*, routes[*],
// nginx.*) read naturally. The upstream is the standalone fixture vllm:8000,
// secured (https + verify) as a manual address must be.
func helmTemplateTLSLB(t *testing.T, args ...string) (string, error) {
	t.Helper()
	lbArgs := []string{
		"--set-string", "tlsLb.upstream.address=vllm:8000",
		"--set", "tlsLb.upstream.protocol=https",
		"--set", "tlsLb.upstream.tls.verify=true",
		"--set", "tlsLb.nginx.image.tag=dev",
		"--show-only", "templates/tls-lb.yaml",
	}
	return helmTemplate(t, chartNodeMetal, append(lbArgs, prefixTLSLBSetArgs(args)...)...)
}

// prefixTLSLBSetArgs rewrites the value path of each --set/--set-string pair
// to live under the tlsLb key, leaving the value (right of '=') untouched.
func prefixTLSLBSetArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i+1 < len(out); i++ {
		if out[i] != "--set" && out[i] != "--set-string" {
			continue
		}
		out[i+1] = "tlsLb." + out[i+1]
		i++
	}
	return out
}

// noUpstreamArgs clears the mesh-wrapped upstream that helmTemplate pins by
// default, for tests exercising the manual tlsLb.upstream paths.
func noUpstreamArgs(args ...string) []string {
	return append([]string{"--set-string", "tlsLb.upstream.address="}, args...)
}

// helmFailMessage extracts the user-visible message from a `helm template`
// failure so tests can parse a typed value out of it instead of grepping
// the whole stderr blob.
var helmFailRE = regexp.MustCompile(`execution error at \([^)]+\): (.+?)\n`)

func helmFailMessage(t *testing.T, out string) string {
	t.Helper()
	m := helmFailRE.FindStringSubmatch(out)
	if len(m) < 2 {
		t.Fatalf("no helm fail message in output:\n%s", out)
	}
	return m[1]
}

func assertHelmFailMessage(t *testing.T, out, want string) {
	t.Helper()
	if got := helmFailMessage(t, out); got != want {
		t.Fatalf("helm fail message = %q, want %q\n%s", got, want, out)
	}
}

// preStopBoundFailure captures the structured shape of the daemonset
// preStop fail-checks so tests can assert on typed fields instead of
// substring-matching the rendered error.
type preStopBoundFailure struct {
	Cmp   string // "le" for "≤", "ge" for "≥"
	Bound int
	Got   int
}

var preStopBoundRE = regexp.MustCompile(`iptablesCleanup\.preStopSleepSeconds must be ([≤≥]) (-?\d+).*got (-?\d+)`)

func parsePreStopBoundFailure(t *testing.T, out string) preStopBoundFailure {
	t.Helper()
	msg := helmFailMessage(t, out)
	m := preStopBoundRE.FindStringSubmatch(msg)
	if len(m) != 4 {
		t.Fatalf("preStop bound regex did not match %q", msg)
	}
	cmp := "ge"
	if m[1] == "≤" {
		cmp = "le"
	}
	bound, err := strconv.Atoi(m[2])
	if err != nil {
		t.Fatalf("bound %q is not an int: %v", m[2], err)
	}
	got, err := strconv.Atoi(m[3])
	if err != nil {
		t.Fatalf("got %q is not an int: %v", m[3], err)
	}
	return preStopBoundFailure{Cmp: cmp, Bound: bound, Got: got}
}

// gracePeriodBudgetFailure: the durations the chart says don't leave a
// preStop window.
type gracePeriodBudgetFailure struct {
	GracePeriod string
	Drain       string
}

var gracePeriodBudgetRE = regexp.MustCompile(`terminationGracePeriod \(([^)]+)\) must exceed drainTimeout \(([^)]+)\)`)

func parseGracePeriodBudgetFailure(t *testing.T, out string) gracePeriodBudgetFailure {
	t.Helper()
	msg := helmFailMessage(t, out)
	m := gracePeriodBudgetRE.FindStringSubmatch(msg)
	if len(m) != 3 {
		t.Fatalf("grace-period budget regex did not match %q", msg)
	}
	return gracePeriodBudgetFailure{GracePeriod: m[1], Drain: m[2]}
}

// durationFormatFailure classifies the two distinct rejection paths in the
// duration helper so a future refactor that conflates them flags here.
type durationFormatFailure struct {
	Value  string
	Reason string // "no-unit" | "non-integer"
}

var (
	durationNoUnitRE     = regexp.MustCompile(`duration "([^"]+)" must end with h, m, or s`)
	durationNonIntegerRE = regexp.MustCompile(`duration "([^"]+)" must be a positive integer`)
)

func parseDurationFormatFailure(t *testing.T, out string) durationFormatFailure {
	t.Helper()
	msg := helmFailMessage(t, out)
	if m := durationNoUnitRE.FindStringSubmatch(msg); len(m) == 2 {
		return durationFormatFailure{Value: m[1], Reason: "no-unit"}
	}
	if m := durationNonIntegerRE.FindStringSubmatch(msg); len(m) == 2 {
		return durationFormatFailure{Value: m[1], Reason: "non-integer"}
	}
	t.Fatalf("duration-format regex did not match %q", msg)
	return durationFormatFailure{}
}

// parseValidationErrorKind extracts kind=<id> from helm's stderr when the
// chart's `fail` message starts with `VALIDATION_ERROR kind=<id>:`. Returns
// empty string if the marker is absent.
func parseValidationErrorKind(helmOutput string) string {
	re := regexp.MustCompile(`VALIDATION_ERROR kind=([a-z0-9_]+)`)
	m := re.FindStringSubmatch(helmOutput)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

type docMeta struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
}

// splitManifestDocs returns each non-empty doc in a multi-doc YAML stream as
// its own raw YAML chunk. helm template emits empty `---\n` separators that
// we silently drop.
func splitManifestDocs(manifest string) []string {
	var out []string
	for _, doc := range strings.Split(manifest, "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		out = append(out, doc)
	}
	return out
}

// iterateManifests calls fn for each non-nil YAML document in helmOut,
// using yaml.NewDecoder so a "---" inside a block scalar can't fool the
// split. The document is re-marshalled to YAML bytes so fn can pass it
// to sigsyaml.Unmarshal for typed decoding. fn returning true stops
// iteration.
func iterateManifests(t *testing.T, helmOut string, fn func(doc []byte) bool) {
	t.Helper()
	decoder := yaml.NewDecoder(strings.NewReader(helmOut))
	for {
		var raw any
		err := decoder.Decode(&raw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			t.Fatalf("decode helm output: %v", err)
		}
		if raw == nil {
			continue
		}
		b, err := yaml.Marshal(raw)
		if err != nil {
			t.Fatalf("re-marshal manifest: %v", err)
		}
		if fn(b) {
			return
		}
	}
}

// renderedKinds counts each manifest kind across a helm template output.
func renderedKinds(t *testing.T, helmOut string) map[string]int {
	t.Helper()
	out := map[string]int{}
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var head struct {
			Kind string `json:"kind"`
		}
		if err := sigsyaml.Unmarshal(doc, &head); err == nil && head.Kind != "" {
			out[head.Kind]++
		}
		return false
	})
	return out
}

// findDoc returns the first YAML doc matching kind (and name when non-empty),
// decoded into out via sigs.k8s.io/yaml. Returns false if no match.
func findDoc(t *testing.T, manifest, kind, name string, out any) bool {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil {
			continue
		}
		if meta.Kind != kind {
			continue
		}
		if name != "" && meta.Metadata.Name != name {
			continue
		}
		if err := sigsyaml.Unmarshal([]byte(doc), out); err != nil {
			t.Fatalf("decode %s/%s: %v\n%s", kind, name, err, doc)
		}
		return true
	}
	return false
}

func renderedManifestHasKind(t *testing.T, manifest, kind string) bool {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err == nil && meta.Kind == kind {
			return true
		}
	}
	return false
}

func renderedManifestHasNamedKind(t *testing.T, manifest, kind, name string) bool {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err == nil && meta.Kind == kind && meta.Metadata.Name == name {
			return true
		}
	}
	return false
}

// renderedManifestHasLabel reports whether any rendered doc carries the label,
// on its own metadata or its pod template.
func renderedManifestHasLabel(t *testing.T, manifest, key, value string) bool {
	t.Helper()
	found := false
	iterateManifests(t, manifest, func(doc []byte) bool {
		var obj struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				Template struct {
					Metadata struct {
						Labels map[string]string `json:"labels"`
					} `json:"metadata"`
				} `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			return false
		}
		if obj.Metadata.Labels[key] == value || obj.Spec.Template.Metadata.Labels[key] == value {
			found = true
			return true
		}
		return false
	})
	return found
}

func renderedMutatingWebhook(t *testing.T, manifest, name string) admissionregv1.MutatingWebhook {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "MutatingWebhookConfiguration" {
			continue
		}
		var cfg admissionregv1.MutatingWebhookConfiguration
		if err := sigsyaml.Unmarshal([]byte(doc), &cfg); err != nil {
			t.Fatalf("decode MutatingWebhookConfiguration: %v\n%s", err, doc)
		}
		for _, hook := range cfg.Webhooks {
			if hook.Name == name {
				return hook
			}
		}
	}
	t.Fatalf("rendered manifest missing MutatingWebhookConfiguration webhook %q\n%s", name, manifest)
	return admissionregv1.MutatingWebhook{}
}

func renderedMutatingWebhookNames(t *testing.T, manifest string) []string {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "MutatingWebhookConfiguration" {
			continue
		}
		var cfg admissionregv1.MutatingWebhookConfiguration
		if err := sigsyaml.Unmarshal([]byte(doc), &cfg); err != nil {
			t.Fatalf("decode MutatingWebhookConfiguration: %v\n%s", err, doc)
		}
		names := make([]string, 0, len(cfg.Webhooks))
		for _, hook := range cfg.Webhooks {
			names = append(names, hook.Name)
		}
		return names
	}
	t.Fatalf("rendered manifest missing MutatingWebhookConfiguration\n%s", manifest)
	return nil
}

func selectorExpressionValues(selector *metav1.LabelSelector, key string, op metav1.LabelSelectorOperator) []string {
	if selector == nil {
		return nil
	}
	for _, expression := range selector.MatchExpressions {
		if expression.Key == key && expression.Operator == op {
			return expression.Values
		}
	}
	return nil
}

func renderedOperatorArgs(t *testing.T, manifest string) []string {
	t.Helper()
	for _, doc := range splitManifestDocs(manifest) {
		var meta docMeta
		if err := sigsyaml.Unmarshal([]byte(doc), &meta); err != nil || meta.Kind != "Deployment" {
			continue
		}
		var dep appsv1.Deployment
		if err := sigsyaml.Unmarshal([]byte(doc), &dep); err != nil {
			t.Fatalf("decode Deployment %q: %v\n%s", meta.Metadata.Name, err, doc)
		}
		for _, container := range dep.Spec.Template.Spec.Containers {
			if container.Name == "operator" {
				return container.Args
			}
		}
	}
	t.Fatalf("rendered manifest missing operator container\n%s", manifest)
	return nil
}

type renderedWorkload struct {
	kind, name string
	spec       corev1.PodSpec
}

func renderedPodSpecs(t *testing.T, manifest string) []renderedWorkload {
	t.Helper()
	var out []renderedWorkload
	iterateManifests(t, manifest, func(doc []byte) bool {
		var obj struct {
			docMeta
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := sigsyaml.Unmarshal(doc, &obj); err != nil {
			return false
		}
		switch obj.Kind {
		case "Deployment", "DaemonSet", "StatefulSet", "Job":
			out = append(out, renderedWorkload{obj.Kind, obj.Metadata.Name, obj.Spec.Template.Spec})
		}
		return false
	})
	return out
}

// findKey returns a dotted path to the first occurrence of key anywhere in a
// decoded YAML tree, or "" if absent.
func findKey(node any, key string) string {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			if k == key {
				return k
			}
			if p := findKey(child, key); p != "" {
				return k + "." + p
			}
		}
	case []any:
		for i, child := range v {
			if p := findKey(child, key); p != "" {
				return fmt.Sprintf("[%d].%s", i, p)
			}
		}
	}
	return ""
}

func renderedDeployment(t *testing.T, manifest, name string) appsv1.Deployment {
	t.Helper()
	var dep appsv1.Deployment
	if !findDoc(t, manifest, "Deployment", name, &dep) {
		t.Fatalf("rendered manifest missing Deployment %q\n%s", name, manifest)
	}
	return dep
}

func renderedDaemonSet(t *testing.T, manifest, name string) appsv1.DaemonSet {
	t.Helper()
	var ds appsv1.DaemonSet
	if !findDoc(t, manifest, "DaemonSet", name, &ds) {
		t.Fatalf("rendered manifest missing DaemonSet %q\n%s", name, manifest)
	}
	return ds
}

func renderedConfigMap(t *testing.T, manifest, name string) corev1.ConfigMap {
	t.Helper()
	var cm corev1.ConfigMap
	if !findDoc(t, manifest, "ConfigMap", name, &cm) {
		t.Fatalf("rendered manifest missing ConfigMap %q\n%s", name, manifest)
	}
	return cm
}

func renderedService(t *testing.T, manifest, name string) corev1.Service {
	t.Helper()
	var svc corev1.Service
	if !findDoc(t, manifest, "Service", name, &svc) {
		t.Fatalf("rendered manifest missing Service %q\n%s", name, manifest)
	}
	return svc
}

func renderedDeploymentInitContainers(t *testing.T, manifest, name string) []corev1.Container {
	t.Helper()
	return renderedDeployment(t, manifest, name).Spec.Template.Spec.InitContainers
}

func renderedDeploymentContainer(t *testing.T, manifest, deploymentName, containerName string) corev1.Container {
	t.Helper()
	for _, container := range renderedDeployment(t, manifest, deploymentName).Spec.Template.Spec.Containers {
		if container.Name == containerName {
			return container
		}
	}
	t.Fatalf("rendered Deployment %q missing container %q\n%s", deploymentName, containerName, manifest)
	return corev1.Container{}
}

func renderedDaemonSetContainer(t *testing.T, manifest, daemonSetName, containerName string) corev1.Container {
	t.Helper()
	for _, container := range renderedDaemonSet(t, manifest, daemonSetName).Spec.Template.Spec.Containers {
		if container.Name == containerName {
			return container
		}
	}
	t.Fatalf("rendered DaemonSet %q missing container %q\n%s", daemonSetName, containerName, manifest)
	return corev1.Container{}
}

func findRATLSMeshDaemonSet(t *testing.T, helmOut string) *appsv1.DaemonSet {
	t.Helper()
	var ds *appsv1.DaemonSet
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var head struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := sigsyaml.Unmarshal(doc, &head); err != nil ||
			head.Kind != "DaemonSet" ||
			!strings.Contains(head.Metadata.Name, "ratls-mesh") {
			return false
		}
		var decoded appsv1.DaemonSet
		if err := sigsyaml.Unmarshal(doc, &decoded); err != nil {
			t.Fatalf("decode ratls-mesh DaemonSet: %v\n%s", err, doc)
		}
		ds = &decoded
		return true
	})
	if ds == nil {
		t.Fatalf("ratls-mesh DaemonSet not found in helm template output\n%s", helmOut)
	}
	return ds
}

// PrometheusRule's types live in a separate go module (prometheus-operator)
// the chart does not otherwise depend on; decoding into a local typed shim
// is enough to assert the rule contract without pulling that dep in just
// for tests.
type prometheusRule struct {
	Spec struct {
		Groups []struct {
			Name  string `json:"name"`
			Rules []struct {
				Alert       string            `json:"alert"`
				Expr        string            `json:"expr"`
				For         string            `json:"for"`
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
			} `json:"rules"`
		} `json:"groups"`
	} `json:"spec"`
}

func findRATLSMeshPrometheusRule(t *testing.T, helmOut string) prometheusRule {
	t.Helper()
	var found prometheusRule
	var ok bool
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var head struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := sigsyaml.Unmarshal(doc, &head); err != nil ||
			head.Kind != "PrometheusRule" ||
			!strings.Contains(head.Metadata.Name, "ratls-mesh") {
			return false
		}
		var rule prometheusRule
		if err := sigsyaml.Unmarshal(doc, &rule); err != nil {
			t.Fatalf("decode ratls-mesh PrometheusRule: %v\n%s", err, doc)
		}
		found = rule
		ok = true
		return true
	})
	if !ok {
		t.Fatalf("ratls-mesh PrometheusRule not found in helm template output\n%s", helmOut)
	}
	return found
}

// findContainer mirrors findEnv in internal/webhook/pod_mutator_test.go:
// return (value, ok) so callers decide how to report the miss.
func findContainer(containers []corev1.Container, name string) (corev1.Container, bool) {
	for _, c := range containers {
		if c.Name == name {
			return c, true
		}
	}
	return corev1.Container{}, false
}

func containerNames(containers []corev1.Container) []string {
	names := make([]string, 0, len(containers))
	for _, c := range containers {
		names = append(names, c.Name)
	}
	return names
}

// envValue returns the value of the named env var on a container, or "" if it
// is absent (or set via valueFrom rather than a literal value).
func envValue(env []corev1.EnvVar, name string) string {
	for _, e := range env {
		if e.Name == name {
			return e.Value
		}
	}
	return ""
}

// tlsLBGetCertContainer returns the named tls-lb get-cert init container
// (c8s-cert), failing if absent.
func tlsLBGetCertContainer(t *testing.T, manifest, name string) corev1.Container {
	t.Helper()
	init := renderedDeploymentInitContainers(t, manifest, "c8s-tls-lb")
	c, ok := findContainer(init, name)
	if !ok {
		t.Fatalf("tls-lb init container %q missing; have %v", name, containerNames(init))
	}
	return c
}

// containerArgs returns the args of the named container, searching main and
// init containers. Fails the test if no such container exists.
func containerArgs(t *testing.T, ds *appsv1.DaemonSet, name string) []string {
	t.Helper()
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == name {
			return c.Args
		}
	}
	for _, c := range ds.Spec.Template.Spec.InitContainers {
		if c.Name == name {
			return c.Args
		}
	}
	t.Fatalf("container %q not found in DaemonSet", name)
	return nil
}

// containerArgValue returns (value, true) for `--flag value`, or ("", false)
// if the flag isn't present.
func containerArgValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// argAfter returns the value following flag in an argv, or "" if absent.
func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// argvContainsFlagValue reports whether argv has `flag` immediately followed
// by `value`.
func argvContainsFlagValue(argv []string, flag, value string) bool {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) && argv[i+1] == value {
			return true
		}
	}
	return false
}

// assertContainerArgs fails unless every wanted arg is present on the container.
func assertContainerArgs(t *testing.T, c corev1.Container, want ...string) {
	t.Helper()
	for _, w := range want {
		assertContainerHasArg(t, c.Name, c.Args, w)
	}
}

func assertContainerHasArg(t *testing.T, container string, args []string, want string) {
	t.Helper()
	if !slices.Contains(args, want) {
		t.Fatalf("%s container missing arg %q\nargs: %v", container, want, args)
	}
}

func assertContainerNoArgPrefix(t *testing.T, container string, args []string, prefix string) {
	t.Helper()
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			t.Fatalf("%s container has unexpected arg with prefix %q: %q\nargs: %v", container, prefix, arg, args)
		}
	}
}

func assertContainerHasArgPrefix(t *testing.T, container string, args []string, prefix string) {
	t.Helper()
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return
		}
	}
	t.Fatalf("%s container missing arg with prefix %q\nargs: %v", container, prefix, args)
}

func namedContainerPort(c corev1.Container, portName string) (corev1.ContainerPort, bool) {
	for _, p := range c.Ports {
		if p.Name == portName {
			return p, true
		}
	}
	return corev1.ContainerPort{}, false
}

func containerHostPort(c corev1.Container, portName string) (int32, bool) {
	p, ok := namedContainerPort(c, portName)
	return p.HostPort, ok
}

func containersExposingHostPort(ds *appsv1.DaemonSet, port int32) []string {
	var hits []string
	for _, c := range allContainers(ds) {
		for _, p := range c.Ports {
			if p.HostPort == port {
				hits = append(hits, c.Name)
				break
			}
		}
	}
	return hits
}

func allContainers(ds *appsv1.DaemonSet) []corev1.Container {
	out := make([]corev1.Container, 0, len(ds.Spec.Template.Spec.InitContainers)+len(ds.Spec.Template.Spec.Containers))
	out = append(out, ds.Spec.Template.Spec.InitContainers...)
	out = append(out, ds.Spec.Template.Spec.Containers...)
	return out
}

func hasCapability(c corev1.Container, want corev1.Capability) bool {
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return false
	}
	for _, got := range c.SecurityContext.Capabilities.Add {
		if got == want {
			return true
		}
	}
	return false
}

func tolerates(tols []corev1.Toleration, key, value string) bool {
	for _, t := range tols {
		if t.Key == key && t.Value == value {
			return true
		}
	}
	return false
}

// durationArg extracts and parses the value of the first arg carrying prefix.
func durationArg(t *testing.T, args []string, prefix string) time.Duration {
	t.Helper()
	for _, a := range args {
		if raw, ok := strings.CutPrefix(a, prefix); ok {
			d, err := time.ParseDuration(raw)
			if err != nil {
				t.Fatalf("parse %s%s: %v", prefix, raw, err)
			}
			return d
		}
	}
	t.Fatalf("args missing %s\n%v", prefix, args)
	return 0
}

// hasNodeIPEnv reports whether the container carries a NODE_IP env var sourced
// from the status.hostIP downward-API field — the sandbox-digests callback
// address the installer writes down for the host-process plugin.
func hasNodeIPEnv(c corev1.Container) bool {
	for _, e := range c.Env {
		if e.Name == "NODE_IP" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil &&
			e.ValueFrom.FieldRef.FieldPath == "status.hostIP" {
			return true
		}
	}
	return false
}

// hasHostIPEnv reports whether the container carries a HOST_IP env var sourced
// from the status.hostIP downward-API field — the substitution source for the
// $(HOST_IP) placeholder in the node-mode attestation-api URL.
func hasHostIPEnv(c corev1.Container) bool {
	for _, e := range c.Env {
		if e.Name == "HOST_IP" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil &&
			e.ValueFrom.FieldRef.FieldPath == "status.hostIP" {
			return true
		}
	}
	return false
}

// containerVolumeMount returns the named volume mount from a container
// (read-only state checked separately by the caller).
func containerVolumeMount(c corev1.Container, name string) (corev1.VolumeMount, bool) {
	for _, m := range c.VolumeMounts {
		if m.Name == name {
			return m, true
		}
	}
	return corev1.VolumeMount{}, false
}

func podVolume(spec corev1.PodSpec, name string) (corev1.Volume, bool) {
	for _, v := range spec.Volumes {
		if v.Name == name {
			return v, true
		}
	}
	return corev1.Volume{}, false
}

func assertPodVolume(t *testing.T, spec *corev1.PodSpec, name string, ok func(corev1.Volume) bool) {
	t.Helper()
	for _, v := range spec.Volumes {
		if v.Name == name {
			if !ok(v) {
				t.Fatalf("volume %q has the wrong source: %+v", name, v.VolumeSource)
			}
			return
		}
	}
	t.Fatalf("pod spec missing volume %q; volumes %+v", name, spec.Volumes)
}

func assertContainerMount(t *testing.T, c corev1.Container, name, mountPath string) {
	t.Helper()
	for _, m := range c.VolumeMounts {
		if m.Name == name && m.MountPath == mountPath {
			return
		}
	}
	t.Fatalf("container %s missing mount of volume %q at %q; mounts %+v", c.Name, name, mountPath, c.VolumeMounts)
}

// hostPathVolume returns the hostPath of the named volume on a DaemonSet.
func hostPathVolume(t *testing.T, ds appsv1.DaemonSet, name string) string {
	t.Helper()
	for _, v := range ds.Spec.Template.Spec.Volumes {
		if v.Name == name {
			if v.HostPath == nil {
				t.Fatalf("DaemonSet volume %q is not a hostPath volume", name)
			}
			return v.HostPath.Path
		}
	}
	t.Fatalf("DaemonSet has no volume %q", name)
	return ""
}

// initContainerEnv returns the env name->value map of a DaemonSet init container.
func initContainerEnv(t *testing.T, ds appsv1.DaemonSet, name string) map[string]string {
	t.Helper()
	for _, c := range ds.Spec.Template.Spec.InitContainers {
		if c.Name != name {
			continue
		}
		env := make(map[string]string, len(c.Env))
		for _, e := range c.Env {
			env[e.Name] = e.Value
		}
		return env
	}
	t.Fatalf("DaemonSet has no init container %q", name)
	return nil
}

// nodeAffinityHasKey reports whether any required nodeAffinity matchExpression
// keys on the given label.
func nodeAffinityHasKey(ds appsv1.DaemonSet, key string) bool {
	aff := ds.Spec.Template.Spec.Affinity
	if aff == nil || aff.NodeAffinity == nil ||
		aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		return false
	}
	for _, term := range aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
		for _, expr := range term.MatchExpressions {
			if expr.Key == key {
				return true
			}
		}
	}
	return false
}

// assertNoLegacyAttestationStrings keeps the routable shapes the hardening
// removed out of every render: the old NodePort, a wildcard bind, and the
// deleted Service's DNS name.
func assertNoLegacyAttestationStrings(t *testing.T, manifest string) {
	t.Helper()
	for _, legacy := range []string{"30840", "0.0.0.0", "c8s-attestation-api.c8s-system.svc"} {
		if strings.Contains(manifest, legacy) {
			t.Fatalf("render must not contain legacy routable-attestation string %q", legacy)
		}
	}
}

type nriRuntimeConfig struct {
	Allowlist struct {
		Pull struct {
			URL               string   `yaml:"url"`
			Interval          string   `yaml:"interval"`
			Timeout           string   `yaml:"timeout"`
			AttestationApiURL string   `yaml:"attestation_api_url"`
			CDSMeasurements   []string `yaml:"cds_measurements"`
			CDSRTMRs          []string `yaml:"cds_rtmrs"`
		} `yaml:"pull"`
		Push struct {
			PersistPath string `yaml:"persist_path"`
		} `yaml:"push"`
	} `yaml:"allowlist"`
}

func renderedNRIBootConfig(t *testing.T, manifest, daemonSetName string) nriRuntimeConfig {
	t.Helper()
	ds := renderedDaemonSet(t, manifest, daemonSetName)
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	raw := extractHeredoc(t, script, "IMAGE_POLICY_EOF")
	var cfg nriRuntimeConfig
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("decode %s boot config: %v\n%s", daemonSetName, err, raw)
	}
	return cfg
}

func extractHeredoc(t *testing.T, script, marker string) string {
	t.Helper()
	startMarker := "<<'" + marker + "'\n"
	start := strings.Index(script, startMarker)
	if start < 0 {
		t.Fatalf("script missing heredoc start marker %q\n%s", marker, script)
	}
	bodyStart := start + len(startMarker)
	end := strings.Index(script[bodyStart:], "\n"+marker)
	if end < 0 {
		t.Fatalf("script missing heredoc end marker %q\n%s", marker, script)
	}
	return script[bodyStart : bodyStart+end]
}

// installerBootConfig is a typed view of the image-policy.yaml the installer
// writes. It mirrors the fields of the plugin's own config
// (internal/cmds/nri-image-policy/config.go, which is unexported) needed by the
// chart tests, so assertions are against typed fields rather than substrings.
type installerBootConfig struct {
	Allowlist struct {
		AlwaysAllow map[string]string `yaml:"always_allow"`
		Pull        struct {
			URL string `yaml:"url"`
		} `yaml:"pull"`
		Push struct {
			PersistPath string `yaml:"persist_path"`
		} `yaml:"push"`
	} `yaml:"allowlist"`
	Policy struct {
		Mode               string   `yaml:"mode"`
		ExemptNamespaces   []string `yaml:"exempt_namespaces"`
		ExemptSnapshotPath string   `yaml:"exempt_snapshot_path"`
	} `yaml:"policy"`
}

// bootConfigHeredocRE captures the image-policy.yaml body the installer writes
// via a `write_file ... <<'IMAGE_POLICY_EOF' ... IMAGE_POLICY_EOF` heredoc.
var bootConfigHeredocRE = regexp.MustCompile(`(?s)<<'IMAGE_POLICY_EOF'\n(.*?)\nIMAGE_POLICY_EOF`)

// bootConfigFromInstaller decodes the image-policy.yaml an installer DaemonSet
// writes into a typed installerBootConfig. It uses gopkg.in/yaml.v3 — the same
// library the plugin's loadConfig uses — which (unlike sigs.k8s.io/yaml's JSON
// path) rejects the duplicate mapping keys that would crash the plugin at
// startup. (KnownFields is intentionally NOT set: the goal is duplicate-key
// detection plus typed field access, not mirroring the plugin's full schema.)
func bootConfigFromInstaller(t *testing.T, manifest, dsName string) installerBootConfig {
	t.Helper()
	ds := renderedDaemonSet(t, manifest, dsName)
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	m := bootConfigHeredocRE.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("install script for %s has no IMAGE_POLICY_EOF heredoc\n%s", dsName, script)
	}
	var cfg installerBootConfig
	if err := yaml.Unmarshal([]byte(m[1]), &cfg); err != nil {
		t.Fatalf("plugin would reject its boot config for %s (yaml.v3): %v\n%s", dsName, err, m[1])
	}
	return cfg
}

// kataEnforcementExpressions returns the joined CEL validation expressions of
// the c8s-kata-enforcement policy; the runtime-class allowlist lives there.
func kataEnforcementExpressions(t *testing.T, manifest string) string {
	t.Helper()
	var policy admissionregv1.ValidatingAdmissionPolicy
	if !findDoc(t, manifest, "ValidatingAdmissionPolicy", "c8s-kata-enforcement", &policy) {
		t.Fatalf("missing c8s-kata-enforcement ValidatingAdmissionPolicy\n%s", manifest)
	}
	var sb strings.Builder
	for _, v := range policy.Spec.Validations {
		sb.WriteString(v.Expression)
		sb.WriteString("\n")
	}
	return sb.String()
}

// rcScheduling captures the scheduling block of a rendered RuntimeClass.
type rcScheduling struct {
	Scheduling struct {
		NodeSelector map[string]string `json:"nodeSelector"`
	} `json:"scheduling"`
}

// pullerDockercfgSecret returns the Secret name the kata-image-puller's
// dockercfg projected volume references, or "" when the volume is absent
// (anonymous oras pull). Fails the test if the puller DaemonSet is missing.
func pullerDockercfgSecret(t *testing.T, helmOut string) string {
	t.Helper()
	name := ""
	found := false
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var ds appsv1.DaemonSet
		if err := sigsyaml.Unmarshal(doc, &ds); err != nil || ds.Kind != "DaemonSet" || ds.Name != "c8s-kata-deploy-image-puller" {
			return false
		}
		found = true
		for _, v := range ds.Spec.Template.Spec.Volumes {
			if v.Name != "dockercfg" || v.Projected == nil {
				continue
			}
			for _, s := range v.Projected.Sources {
				if s.Secret != nil {
					name = s.Secret.Name
				}
			}
		}
		return true
	})
	if !found {
		t.Fatalf("kata-image-puller DaemonSet not found in helm template output\n%s", helmOut)
	}
	return name
}

// pullerEnv returns the value of the named env var on the kata-image-puller's
// container. Fails the test if the puller DaemonSet is missing.
func pullerEnv(t *testing.T, helmOut, name string) string {
	t.Helper()
	val := ""
	found := false
	iterateManifests(t, helmOut, func(doc []byte) bool {
		var ds appsv1.DaemonSet
		if err := sigsyaml.Unmarshal(doc, &ds); err != nil || ds.Kind != "DaemonSet" || ds.Name != "c8s-kata-deploy-image-puller" {
			return false
		}
		found = true
		for _, c := range ds.Spec.Template.Spec.Containers {
			for _, e := range c.Env {
				if e.Name == name {
					val = e.Value
				}
			}
		}
		return true
	})
	if !found {
		t.Fatalf("kata-image-puller DaemonSet not found in helm template output\n%s", helmOut)
	}
	return val
}

// --- install-time image pull secret (imagePullSecret, a Secret name) ---

// pullSecretNames flattens an imagePullSecrets list to the referenced names.
func pullSecretNames(refs []corev1.LocalObjectReference) []string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Name)
	}
	return names
}

func hasPullSecret(refs []corev1.LocalObjectReference, name string) bool {
	for _, r := range refs {
		if r.Name == name {
			return true
		}
	}
	return false
}

func renderedTLSLBNginxConf(t *testing.T, manifest string) string {
	t.Helper()
	cm := renderedConfigMap(t, manifest, "c8s-tls-lb-nginx")
	conf, ok := cm.Data["nginx.conf"]
	if !ok || conf == "" {
		t.Fatalf("tls-lb nginx ConfigMap missing nginx.conf\n%s", manifest)
	}
	return conf
}

type nginxConfig struct {
	upstreams map[string]*nginxBlock
	maps      map[nginxMapKey]*nginxBlock
	locations map[nginxLocationKey]*nginxBlock
	http      *nginxBlock
	servers   []*nginxBlock
	all       []*nginxBlock
}

type nginxMapKey struct {
	source string
	target string
}

type nginxLocationKey struct {
	match string
	path  string
}

type nginxBlock struct {
	directives map[string][][]string
}

func renderedTLSLBNginxConfig(t *testing.T, manifest string) nginxConfig {
	t.Helper()
	return parseNginxConfig(t, renderedTLSLBNginxConf(t, manifest))
}

func parseNginxConfig(t *testing.T, conf string) nginxConfig {
	t.Helper()
	cfg := nginxConfig{
		upstreams: make(map[string]*nginxBlock),
		maps:      make(map[nginxMapKey]*nginxBlock),
		locations: make(map[nginxLocationKey]*nginxBlock),
	}

	var stack []*nginxBlock
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, "{") {
			fields := strings.Fields(strings.TrimSpace(strings.TrimSuffix(trimmed, "{")))
			block := &nginxBlock{directives: make(map[string][][]string)}
			cfg.all = append(cfg.all, block)
			if len(fields) == 1 && fields[0] == "http" {
				cfg.http = block
			}
			if len(fields) == 1 && fields[0] == "server" {
				cfg.servers = append(cfg.servers, block)
			}
			if len(fields) == 2 && fields[0] == "upstream" {
				cfg.upstreams[fields[1]] = block
			}
			if len(fields) == 3 && fields[0] == "map" {
				cfg.maps[nginxMapKey{source: fields[1], target: fields[2]}] = block
			}
			if len(fields) >= 2 && fields[0] == "location" {
				key := nginxLocationKey{match: "prefix", path: fields[1]}
				if len(fields) == 3 && fields[1] == "=" {
					key = nginxLocationKey{match: "exact", path: fields[2]}
				}
				cfg.locations[key] = block
			}
			stack = append(stack, block)
			continue
		}
		if trimmed == "}" {
			if len(stack) == 0 {
				t.Fatalf("nginx config has unmatched closing brace")
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if len(stack) == 0 || !strings.HasSuffix(trimmed, ";") {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(trimmed, ";"))
		if len(fields) == 0 {
			continue
		}
		current := stack[len(stack)-1]
		current.directives[fields[0]] = append(current.directives[fields[0]], fields[1:])
	}
	if len(stack) != 0 {
		t.Fatalf("nginx config has %d unclosed block(s)", len(stack))
	}
	return cfg
}

func (cfg nginxConfig) upstream(t *testing.T, name string) *nginxBlock {
	t.Helper()
	upstream, ok := cfg.upstreams[name]
	if !ok {
		t.Fatalf("nginx config missing upstream %q; got %v", name, cfg.upstreams)
	}
	return upstream
}

func (cfg nginxConfig) location(t *testing.T, match, path string) *nginxBlock {
	t.Helper()
	key := nginxLocationKey{match: match, path: path}
	location, ok := cfg.locations[key]
	if !ok {
		t.Fatalf("nginx config missing location %#v; got %v", key, cfg.locations)
	}
	return location
}

func (cfg nginxConfig) server(t *testing.T) *nginxBlock {
	t.Helper()
	if len(cfg.servers) != 1 {
		t.Fatalf("nginx config has %d server blocks, want 1", len(cfg.servers))
	}
	return cfg.servers[0]
}

// assertNoDirectivePrefix fails if any block in the config carries a directive
// whose name starts with prefix.
func (cfg nginxConfig) assertNoDirectivePrefix(t *testing.T, prefix string) {
	t.Helper()
	for _, block := range cfg.all {
		for name, args := range block.directives {
			if strings.HasPrefix(name, prefix) {
				t.Fatalf("nginx directive %s %v present, want no %s* directives", name, args, prefix)
			}
		}
	}
}

func (cfg nginxConfig) mapBlock(t *testing.T, source, target string) *nginxBlock {
	t.Helper()
	key := nginxMapKey{source: source, target: target}
	block, ok := cfg.maps[key]
	if !ok {
		t.Fatalf("nginx config missing map %#v; got %v", key, cfg.maps)
	}
	return block
}

func (block *nginxBlock) assertServer(t *testing.T, server string) {
	t.Helper()
	block.assertDirective(t, "server", server)
}

func (block *nginxBlock) assertDirective(t *testing.T, name string, args ...string) {
	t.Helper()
	for _, got := range block.directives[name] {
		if slices.Equal(got, args) {
			return
		}
	}
	t.Fatalf("nginx directive %q args %v not found; got %v", name, args, block.directives[name])
}

func (block *nginxBlock) assertNoDirective(t *testing.T, name string) {
	t.Helper()
	if got := block.directives[name]; len(got) > 0 {
		t.Fatalf("nginx directive %q = %v, want absent", name, got)
	}
}

func assertNoTLSLBMeshCAVolume(t *testing.T, manifest string) {
	t.Helper()
	dep := renderedDeployment(t, manifest, "c8s-tls-lb")
	for _, volume := range dep.Spec.Template.Spec.Volumes {
		if volume.Name == "mesh-ca" {
			t.Fatalf("Deployment/tls-lb has mesh-ca volume, want absent: %#v", volume)
		}
	}
}

// tlsLbUpstreamAddress returns the catch-all upstream address from the
// rendered tls-lb nginx config: the `upstream catch_all` block's server for a
// static dial, or the `set $backend_addr <addr>;` directive for the
// mesh-wrapped shape that is re-resolved per request.
func tlsLbUpstreamAddress(t *testing.T, manifest string) string {
	t.Helper()
	cfg := renderedTLSLBNginxConfig(t, manifest)
	if block, ok := cfg.upstreams["catch_all"]; ok {
		servers := block.directives["server"]
		if len(servers) != 1 || len(servers[0]) != 1 {
			t.Fatalf("upstream catch_all must carry exactly one server; got %v", servers)
		}
		return servers[0][0]
	}
	sets := cfg.location(t, "prefix", "/").directives["set"]
	for _, args := range sets {
		if len(args) == 2 && args[0] == "$backend_addr" {
			return args[1]
		}
	}
	t.Fatalf("catch-all has neither an `upstream catch_all` block nor a `set $backend_addr <addr>;` directive; got %v", sets)
	return ""
}
