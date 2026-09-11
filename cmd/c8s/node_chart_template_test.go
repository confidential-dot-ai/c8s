//go:build !c8s_node

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
)

// update regenerates the golden c8s-chart.<platform>.yaml.in files instead of
// checking them, mirroring pkg/overenc's -update convention. Run:
//
//	go test ./cmd/c8s/ -run TestNodeChartGoldenFiles -update
var update = flag.Bool("update", false, "regenerate node-guest-image/c8s/c8s-chart.<platform>.yaml.in")

// nodeChartDefaultValues reads and parses the embedded chart's values.yaml —
// no `helm show values` shell-out, since this test's whole point is to
// generate a template file without a chart render (chartComponents, by
// contrast, is the runtime path and legitimately shells to helm to see the
// operator's -f overlays too).
func nodeChartDefaultValues(t *testing.T) map[string]any {
	t.Helper()
	raw, err := helmchart.ChartFS.ReadFile(helmchart.ChartRoot + "/values.yaml")
	if err != nil {
		t.Fatalf("read embedded chart values.yaml: %v", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("parse embedded chart values.yaml: %v", err)
	}
	return tree
}

// nodeChartComponents reads the c8sComponents declarations out of the
// decoded chart defaults (see nodeChartDefaultValues).
func nodeChartComponents(t *testing.T, tree map[string]any) []c8sComponent {
	t.Helper()
	list, ok := tree["c8sComponents"].([]any)
	if !ok || len(list) == 0 {
		t.Fatalf("chart declares no c8sComponents")
	}
	comps := make([]c8sComponent, 0, len(list))
	for _, entry := range list {
		m, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("c8sComponents entry is not a mapping: %T", entry)
		}
		valuePath, ok := m["valuePath"].(string)
		if !ok {
			t.Fatalf("c8sComponents entry missing string valuePath: %v", m)
		}
		repo, err := stringAtPath(tree, valuePath+".repository")
		if err != nil {
			t.Fatalf("component %q: %v", valuePath, err)
		}
		enabledPath, _ := m["enabledPath"].(string)
		comps = append(comps, c8sComponent{valuePrefix: valuePath, repository: repo, enabledPath: enabledPath})
	}
	return comps
}

// digestToken names the @TOKEN@ mkosi.sync substitutes with a resolved
// digest for this component, derived from its values path — the fixed
// mapping node-guest-image/c8s/mkosi.sync's render_chart_helmchart sed
// expects. Kept as an explicit table (not a mechanical uppercasing of the
// path) so a values-path rename doesn't silently rename the baked token
// too — mkosi.sync's own @TOKEN@s are load-bearing, cross-file spelling.
func digestToken(valuePrefix string) string {
	switch valuePrefix {
	case "image":
		return "@IMAGE_DIGEST@"
	case "cds.image":
		return "@CDS_DIGEST@"
	case "ratlsMesh.image":
		return "@RATLS_MESH_DIGEST@"
	case "nriImagePolicy.image":
		return "@NRI_IMAGE_POLICY_DIGEST@"
	default:
		return ""
	}
}

// nodeChartTemplatePath returns node-guest-image/c8s/c8s-chart.<platform>.yaml.in.
func nodeChartTemplatePath(t *testing.T, platform string) string {
	t.Helper()
	suffix := platform
	if platform == "sev-snp" {
		suffix = "snp"
	}
	return filepath.Join("..", "..", "node-guest-image", "c8s", "c8s-chart."+suffix+".yaml.in")
}

// buildNodeChartValues computes the values tree a live `c8s install
// --cvm-mode=node --hardware-platform=<platform> --single-node --distro
// rke2` would send to helm, for the components node mode enables — the same
// composition buildValueArgs uses for those four calls, kept narrow here
// (rather than calling buildValueArgs itself) so this generator has no
// dependency on cluster-derived inputs (workload adoptions, resolved
// inventory CIDRs, ...) that a live install also folds in but a baked node
// never has. Component digests are left as @TOKEN@ placeholders:
// node-guest-image/c8s/mkosi.sync substitutes them at build time from the
// C8S_REF this sync resolves, not from a registry this test can reach.
func buildNodeChartValues(t *testing.T, platform string) map[string]any {
	t.Helper()
	prevAttest := installAttestEnabled
	installAttestEnabled = true
	t.Cleanup(func() { installAttestEnabled = prevAttest })

	args, err := appendCvmModeInstallArgs(nil, "node", platform)
	if err != nil {
		t.Fatalf("appendCvmModeInstallArgs: %v", err)
	}
	args = appendSingleNodeInstallArgs(args, true)
	args = appendDistroInstallArgs(args, "rke2")

	// Component enabledPath is evaluated against the chart defaults
	// overlaid with the node-mode args built above (mirrors
	// componentEnabledPredicate/effectiveValues, minus the -f files a live
	// install may also have — this generator has none): attestationApi.image
	// must be excluded even though attestationApi.enabled defaults to true,
	// because node mode's own --set turns it off.
	defaults := nodeChartDefaultValues(t)
	effective, err := valueArgsToTree(args)
	if err != nil {
		t.Fatalf("valueArgsToTree: %v", err)
	}
	helmchart.MergeValues(defaults, effective)
	for _, c := range nodeChartComponents(t, defaults) {
		if c.enabledPath != "" && !boolAtPath(defaults, c.enabledPath) {
			continue
		}
		token := digestToken(c.valuePrefix)
		if token == "" {
			continue
		}
		args = append(args,
			"--set-string", c.valuePrefix+".repository="+c.repository,
			"--set-string", c.valuePrefix+".digest="+token,
		)
	}
	// buildDigestArgs's own trailing --set: resolving the component digests
	// above is exactly when the NRI allowlist should derive from them (off by
	// default in the chart).
	args = append(args, "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true")

	final, err := valueArgsToTree(args)
	if err != nil {
		t.Fatalf("valueArgsToTree: %v", err)
	}
	return final
}

// renderNodeChartTemplate marshals values (from buildNodeChartValues) as
// YAML and wraps it in the baked HelmChart's fixed header — name, namespace,
// the baked-chart label, and spec fields the invariants script also checks.
func renderNodeChartTemplate(t *testing.T, values map[string]any) string {
	t.Helper()
	valuesYAML, err := yaml.Marshal(values)
	if err != nil {
		t.Fatalf("marshal values: %v", err)
	}
	var indented strings.Builder
	for _, line := range strings.Split(strings.TrimRight(string(valuesYAML), "\n"), "\n") {
		if line == "" {
			indented.WriteString("\n")
			continue
		}
		fmt.Fprintf(&indented, "    %s\n", line)
	}
	return `apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: c8s
  namespace: kube-system
  labels:
    confidential.ai/baked: "true"
spec:
  chart: https://%{KUBERNETES_API}%/static/charts/c8s.tgz
  targetNamespace: c8s-system
  createNamespace: false
  valuesContent: |
` + indented.String()
}

// nodeChartHeader is the hand-authored prose this generator prepends to
// every golden file — the mechanism explanation belongs at the top of a
// template a human reads before mkosi.sync ever touches it, not embedded in
// the generator that produces the copy below it.
const nodeChartHeader = `# Baked c8s chart install — GENERATED by TestNodeChartGoldenFiles
# (cmd/c8s/node_chart_template_test.go -update). Do not hand-edit: a manual
# edit is caught by that test (it re-derives valuesContent from
# appendCvmModeInstallArgs/appendSingleNodeInstallArgs/appendDistroInstallArgs
# — the same composition a live 'c8s install --cvm-mode=node --single-node'
# uses — and fails if this file differs from what it computes).
#
# mkosi.sync's render_chart_helmchart substitutes only the @*_DIGEST@ tokens
# below (resolved per build from C8S_REF) and copies the result to
# var/lib/rancher/rke2/server/manifests/c8s-chart.yaml. The chart tree itself
# is staged separately, to server/static/charts/c8s.tgz — spec.chart below
# just points at it, the same way RKE2's own bundled AddOns (rke2-coredns.yaml
# etc.) serve their charts, and never passes through sed's argv (which has no
# room for a ~166 KB base64 chart tarball — Linux's MAX_ARG_STRLEN).
#
# RKE2's supervisor applies manifests under server/manifests/ as HelmChart
# AddOns (helm-controller reconciles a helm-install-c8s Job from this CRD;
# see local-path-storage.yaml and rke2-cilium-config.yaml for the same
# mechanism). Deploying the chart this way, from the measured root, means the
# node's launch measurement covers exactly which chart version and which
# component images install, so the credential 'c8s cred-release' hands an
# operator no longer needs the RBAC breadth a live 'c8s install' requires to
# do the same job (see the node-image credential-release design).
#
# valuesContent omits the values only a running boot knows (cds.operatorKeys,
# cds.measurements/rtmrs, ratlsMesh.measurements/rtmrs);
# c8s-chart-values.service layers those on top at boot via a
# HelmChartConfig, which RKE2 merges into this HelmChart's spec without
# touching the measured copy here.
#
# c8s install refuses to run against a cluster carrying the
# confidential.ai/baked label below (see preflightNotBakedNode in
# cmd/c8s/install.go) — a live install would fight the AddOn controller's own
# reconciliation of this release and cannot supply the boot-only values
# above.
`

// TestNodeChartGoldenFiles asserts node-guest-image/c8s/c8s-chart.tdx.yaml.in
// and c8s-chart.snp.yaml.in equal what this test computes from the shared
// install-arg builders, for both hardware platforms — the same guarantee the
// old hand-written single template's TestNodeChartTemplateMatchesInstallNodeMode
// gave, but as a golden-file compare instead of a value-path diff, so any
// drift (including cosmetic YAML shape) is caught, not just missing paths.
//
// With -update it (re)writes both files; without it, it fails if either
// differs from what this test would generate — node-guest-image-lint.yml
// runs it in check mode as part of its normal `go test`.
func TestNodeChartGoldenFiles(t *testing.T) {
	for _, platform := range []string{"tdx", "sev-snp"} {
		t.Run(platform, func(t *testing.T) {
			values := buildNodeChartValues(t, platform)
			got := nodeChartHeader + renderNodeChartTemplate(t, values)
			path := nodeChartTemplatePath(t, platform)

			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatalf("write %s: %v", path, err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v (run with -update to create it)", path, err)
			}
			if got != string(want) {
				t.Errorf("%s is out of date with the install-arg builders — re-run:\n  go test ./cmd/c8s/ -run TestNodeChartGoldenFiles -update", path)
			}
		})
	}
}

// TestNodeChartTemplateSubstitutesCleanly renders each golden file the same
// way mkosi.sync's render_chart_helmchart does (digest tokens only) and
// checks nothing @TOKEN@-shaped survives, then parses the result as the
// HelmChart mkosi.sync writes to server/manifests/.
func TestNodeChartTemplateSubstitutesCleanly(t *testing.T) {
	for _, tc := range []struct {
		platform string
		tokens   map[string]string
	}{
		{platform: "tdx", tokens: map[string]string{
			"@IMAGE_DIGEST@":            "sha256:" + strings.Repeat("aa", 32),
			"@CDS_DIGEST@":              "sha256:" + strings.Repeat("bb", 32),
			"@RATLS_MESH_DIGEST@":       "sha256:" + strings.Repeat("cc", 32),
			"@NRI_IMAGE_POLICY_DIGEST@": "sha256:" + strings.Repeat("dd", 32),
		}},
		{platform: "sev-snp", tokens: map[string]string{
			"@IMAGE_DIGEST@":            "sha256:" + strings.Repeat("aa", 32),
			"@CDS_DIGEST@":              "sha256:" + strings.Repeat("bb", 32),
			"@RATLS_MESH_DIGEST@":       "sha256:" + strings.Repeat("cc", 32),
			"@NRI_IMAGE_POLICY_DIGEST@": "sha256:" + strings.Repeat("dd", 32),
		}},
	} {
		t.Run(tc.platform, func(t *testing.T) {
			path := nodeChartTemplatePath(t, tc.platform)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			out := string(raw)
			for token, val := range tc.tokens {
				out = strings.ReplaceAll(out, token, val)
			}

			var doc struct {
				Spec struct {
					Chart         string `yaml:"chart"`
					ValuesContent string `yaml:"valuesContent"`
					TargetNS      string `yaml:"targetNamespace"`
					CreateNS      *bool  `yaml:"createNamespace"`
				} `yaml:"spec"`
				Metadata struct {
					Name      string            `yaml:"name"`
					Namespace string            `yaml:"namespace"`
					Labels    map[string]string `yaml:"labels"`
				} `yaml:"metadata"`
			}
			if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatalf("parse rendered HelmChart: %v\n%s", err, out)
			}
			// Scoped to valuesContent alone (not the whole file): the header
			// comment prose above names the substitution tokens in
			// backticks-free text (e.g. "the @*_DIGEST@ tokens"), and
			// spec.chart carries RKE2's own %{KUBERNETES_API}% token — neither
			// is one of mkosi.sync's @TOKEN@s to resolve.
			if i := strings.IndexByte(doc.Spec.ValuesContent, '@'); i >= 0 {
				t.Fatalf("rendered valuesContent still carries an unresolved @TOKEN@ at byte %d:\n%s", i, doc.Spec.ValuesContent)
			}
			if doc.Metadata.Name != "c8s" || doc.Metadata.Namespace != "kube-system" {
				t.Fatalf("HelmChart metadata = %+v, want name=c8s namespace=kube-system", doc.Metadata)
			}
			if doc.Metadata.Labels["confidential.ai/baked"] != "true" {
				t.Fatalf("HelmChart missing label confidential.ai/baked=true (labels: %v)", doc.Metadata.Labels)
			}
			if doc.Spec.Chart != "https://%{KUBERNETES_API}%/static/charts/c8s.tgz" {
				t.Fatalf("spec.chart = %q, want the RKE2 static-chart URL", doc.Spec.Chart)
			}
			if doc.Spec.TargetNS != "c8s-system" {
				t.Fatalf("spec.targetNamespace = %q, want c8s-system", doc.Spec.TargetNS)
			}
			if doc.Spec.CreateNS == nil || *doc.Spec.CreateNS != false {
				t.Fatalf("spec.createNamespace = %v, want false", doc.Spec.CreateNS)
			}
			var values map[string]any
			if err := yaml.Unmarshal([]byte(doc.Spec.ValuesContent), &values); err != nil {
				t.Fatalf("parse valuesContent: %v\n%s", err, doc.Spec.ValuesContent)
			}
		})
	}
}
