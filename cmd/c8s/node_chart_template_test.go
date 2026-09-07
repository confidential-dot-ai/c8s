//go:build !c8s_node

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// unresolvedTokenPattern matches an @UPPER_SNAKE@ mkosi.sync token left
// unsubstituted (e.g. a template edit that adds a new @TOKEN@ this test's
// fixture map does not yet know about).
var unresolvedTokenPattern = regexp.MustCompile(`@[A-Z][A-Z0-9_]*@`)

// nodeChartTemplatePath is node-guest-image/c8s/c8s-chart.yaml.in, the
// baked HelmChart mkosi.sync renders at build time (see its render_chart_helmchart).
// Reached relative to this package directory — cmd/c8s is two levels under
// the repo root.
func nodeChartTemplatePath(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "node-guest-image", "c8s", "c8s-chart.yaml.in")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("locate %s: %v", path, err)
	}
	return path
}

// renderChartTemplate substitutes the @TOKEN@ placeholders mkosi.sync's
// render_chart_helmchart fills in, for one hardware platform, with
// recognizable placeholder values (so a diff against the wrong token is
// obvious) and parses the result as YAML.
func renderChartTemplate(t *testing.T, hardwarePlatform string) map[string]any {
	t.Helper()
	tmplPath := nodeChartTemplatePath(t)
	raw, err := os.ReadFile(tmplPath)
	if err != nil {
		t.Fatalf("read %s: %v", tmplPath, err)
	}
	tokens := map[string]string{
		"@CHART_CONTENT@":           "PLACEHOLDER_CHART_CONTENT",
		"@IMAGE_DIGEST@":            "sha256:" + strings.Repeat("aa", 32),
		"@CDS_DIGEST@":              "sha256:" + strings.Repeat("bb", 32),
		"@RATLS_MESH_DIGEST@":       "sha256:" + strings.Repeat("cc", 32),
		"@NRI_IMAGE_POLICY_DIGEST@": "sha256:" + strings.Repeat("dd", 32),
		"@PLATFORM@":                hardwarePlatform,
	}
	switch hardwarePlatform {
	case "tdx":
		tokens["@RATLS_PLATFORM@"] = "tdx"
		tokens["@RATLS_MESH_PLATFORM@"] = "tdx"
		tokens["@TEE_SEV_GUEST@"] = "false"
		tokens["@TEE_TDX_GUEST@"] = "true"
		tokens["@TLS_LB_ATTEST_PLATFORM@"] = "tdx"
		tokens["@TLS_LB_ATTEST_GENERATION@"] = ""
	case "sev-snp":
		tokens["@RATLS_PLATFORM@"] = "snp"
		tokens["@RATLS_MESH_PLATFORM@"] = "sev-snp"
		tokens["@TEE_SEV_GUEST@"] = "true"
		tokens["@TEE_TDX_GUEST@"] = "false"
		tokens["@TLS_LB_ATTEST_PLATFORM@"] = "snp"
		tokens["@TLS_LB_ATTEST_GENERATION@"] = "genoa"
	default:
		t.Fatalf("unknown hardwarePlatform %q", hardwarePlatform)
	}
	out := string(raw)
	for token, val := range tokens {
		out = strings.ReplaceAll(out, token, val)
	}
	// Only the spec block can carry a real @TOKEN@ placeholder — the header
	// comment prose above it names the substitution tokens in backticks-free
	// text (e.g. "@*_DIGEST@ tokens"), which is not itself a token to
	// resolve. Scope the leftover-token check to the YAML document.
	specStart := strings.Index(out, "\napiVersion:")
	if specStart < 0 {
		t.Fatalf("rendered template has no apiVersion: line:\n%s", out)
	}
	if unresolvedTokenPattern.MatchString(out[specStart:]) {
		t.Fatalf("rendered template still carries an unresolved @TOKEN@ in its spec:\n%s", out)
	}

	var doc struct {
		Spec struct {
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
	if doc.Metadata.Name != "c8s" || doc.Metadata.Namespace != "kube-system" {
		t.Fatalf("HelmChart metadata = %+v, want name=c8s namespace=kube-system", doc.Metadata)
	}
	if doc.Metadata.Labels["confidential.ai/baked"] != "true" {
		t.Fatalf("HelmChart missing label confidential.ai/baked=true (labels: %v)", doc.Metadata.Labels)
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
	return values
}

// flattenPaths walks a decoded YAML tree and returns every leaf's dotted
// path (e.g. "cds.image.repository"), ignoring list contents (none of the
// keys under comparison here are lists — cds.node.selector/tolerations
// render as scalar null).
func flattenPaths(tree map[string]any, prefix string) []string {
	var out []string
	for k, v := range tree {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		if m, ok := v.(map[string]any); ok {
			out = append(out, flattenPaths(m, path)...)
			continue
		}
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// flattenSetArgs turns the --set/--set-string argv appendCvmModeInstallArgs
// (plus the node-mode-enabled component set appendResolvedDigestArgs would
// resolve) produces into the same dotted-path leaf set flattenPaths reads
// off the template, so the two are comparable independent of the concrete
// values (one side is CLI-computed at install time, the other is
// build-time tokens — the PATHS must still agree, or the baked chart is not
// rendering the values a live `c8s install --cvm-mode=node` would).
func flattenSetArgs(args []string) []string {
	seen := map[string]bool{}
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "--set" && args[i] != "--set-string" {
			continue
		}
		kv := args[i+1]
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		path := kv[:eq]
		// Index syntax (cds.measurements[0]) has no template-side counterpart
		// (those are boot-time-only keys layered on by
		// c8s-chart-values.service, not this template) — drop the index.
		if br := strings.IndexByte(path, '['); br >= 0 {
			path = path[:br]
		}
		seen[path] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestNodeChartTemplateMatchesInstallNodeMode asserts that every component
// image value path (repository/digest, plus the node-mode static toggles:
// attestationApi.enabled, attestationApi.cvmMode, nriImagePolicy.baked,
// cds.node.selector/tolerations) that a live `c8s install --cvm-mode=node
// --single-node --hardware-platform=<platform>` computes also appears in
// node-guest-image/c8s/c8s-chart.yaml.in's valuesContent — for both
// hardware platforms. The values that only a running boot can supply
// (cds.measurements/rtmrs, ratlsMesh.measurements/rtmrs, cds.operatorKeys)
// are deliberately excluded on both sides: c8s-chart-values.service layers
// those on top of this template at boot (see its own tests).
func TestNodeChartTemplateMatchesInstallNodeMode(t *testing.T) {
	prevAttest := installAttestEnabled
	installAttestEnabled = true
	t.Cleanup(func() { installAttestEnabled = prevAttest })

	for _, platform := range []string{"tdx", "sev-snp"} {
		t.Run(platform, func(t *testing.T) {
			installArgs, err := appendCvmModeInstallArgs([]string{"upgrade"}, "node", platform)
			if err != nil {
				t.Fatalf("appendCvmModeInstallArgs: %v", err)
			}
			installArgs = appendSingleNodeInstallArgs(installArgs, true)
			wantPaths := flattenSetArgs(installArgs)

			// appendCvmModeInstallArgs alone does not resolve component
			// digests (that's appendResolvedDigestArgs, which needs a
			// registry) — but it does tell us exactly which components
			// node mode enables, since it disables attestationApi. The
			// template pins operator/cds/ratls-mesh/nri-image-policy
			// repository+digest for the same enabled set
			// buildDigestArgs would resolve (see c8sComponents in
			// internal/helmchart/c8s/values.yaml: attestationApi and
			// volumed are the only entries with an enabledPath, and node
			// mode leaves both off).
			for _, comp := range []string{"image", "cds.image", "ratlsMesh.image", "nriImagePolicy.image"} {
				wantPaths = append(wantPaths, comp+".repository", comp+".digest")
			}
			sort.Strings(wantPaths)

			values := renderChartTemplate(t, platform)
			gotPaths := flattenPaths(values, "")

			missing := diffStrings(wantPaths, gotPaths)
			if len(missing) > 0 {
				t.Errorf("c8s-chart.yaml.in is missing value paths a node-mode `c8s install` computes: %v\ngot paths: %v", missing, gotPaths)
			}

			// Static booleans/strings the template hardcodes must match
			// what appendCvmModeInstallArgs set for this platform exactly
			// (not just the path) — these are NOT boot-time values, so
			// there is no excuse for the template to drift from them.
			wantStatic := map[string]string{}
			for i := 0; i+1 < len(installArgs); i++ {
				kv := installArgs[i+1]
				eq := strings.IndexByte(kv, '=')
				if eq < 0 {
					continue
				}
				path, val := kv[:eq], kv[eq+1:]
				switch path {
				case "attestationApi.enabled", "attestationApi.teeDevices.sevGuest", "attestationApi.teeDevices.tdxGuest", "attestationApi.teeDevices.tpm",
					"cds.ratlsPlatform", "ratlsMesh.platform", "nriImagePolicy.baked",
					"tlsLb.attest.platform", "tlsLb.attest.generation":
					wantStatic[path] = val
				}
			}
			// attestationApi.cvmMode is --set-string attestationApi.cvmMode=node — always node here.
			wantStatic["attestationApi.cvmMode"] = "node"
			for path, want := range wantStatic {
				got := valueAtDottedPath(t, values, path)
				if got != want {
					t.Errorf("template %s = %q, want %q (from a live node-mode install)", path, got, want)
				}
			}
		})
	}
}

// diffStrings returns the entries of want not present in got (both sorted).
func diffStrings(want, got []string) []string {
	gotSet := make(map[string]bool, len(got))
	for _, g := range got {
		gotSet[g] = true
	}
	var missing []string
	for _, w := range want {
		if !gotSet[w] {
			missing = append(missing, w)
		}
	}
	return missing
}

// valueAtDottedPath reads a scalar at a dotted path out of a decoded YAML
// tree, stringifying bools the way helm --set/--set-string argv spells them.
func valueAtDottedPath(t *testing.T, tree map[string]any, path string) string {
	t.Helper()
	segs := strings.Split(path, ".")
	var cur any = tree
	for _, seg := range segs {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %q: not a map at %q (tree: %#v)", path, seg, tree)
		}
		cur = m[seg]
	}
	switch v := cur.(type) {
	case bool:
		if v {
			return "true"
		}
		return "false"
	case string:
		return v
	default:
		t.Fatalf("path %q: unexpected type %T (%v)", path, cur, cur)
		return ""
	}
}
