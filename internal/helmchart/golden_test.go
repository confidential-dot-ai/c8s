// Golden-equivalence regression net. testdata/golden holds helm template
// renders of the pre-split monolith chart for every shape/platform combo
// (plus their Kind/Name fingerprints). Each case renders the matching shape
// chart with the same logical inputs and asserts:
//
//  1. the resource SET (Kind/Name) matches the fingerprint exactly;
//  2. every rendered document deep-equals its golden counterpart, modulo the
//     intended diffs of the split:
//     - the checksum/nginx-config pod-template annotation (its input is the
//     whole ConfigMap template, which moved templates — whitespace only);
//     - node-image's RKE2-native resolver and NRI restart command (the old
//     chart's node shape defaulted to the k8s layout);
//     - the containerd-prep script's self-path comment, which names the
//     script's new home (c8s/files/scripts/ -> scripts/).
package helmchart

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// goldenDigest is the image digest the golden renders pinned for CDS and the
// NRI plugin.
const goldenDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// goldenCase maps a golden file to the shape chart and values that render the
// same logical install.
type goldenCase struct {
	name  string
	chart string
	args  []string
}

func goldenCases() []goldenCase {
	// Common values of the golden generation: component tags "gold", CDS and
	// NRI digests pinned at goldenDigest, the representative mesh-wrapped
	// upstream. The NRI floor entry names the CDS ref deliberately: the
	// plugin matches the floor by digest, and the monolith's seed carried the
	// CDS self-entry for that shared digest.
	common := []string{
		"--set", "image.tag=gold",
		"--set", "cds.image.tag=gold",
		"--set", "cds.image.digest=" + goldenDigest,
		"--set-string", "tlsLb.upstream.address=c8s-infer.c8s-system.svc.cluster.local:8000",
	}
	node := append(slices.Clone(common),
		"--set", "ratlsMesh.image.tag=gold",
		"--set", "nriImagePolicy.image.tag=gold",
		"--set", "nriImagePolicy.image.digest="+goldenDigest,
		"--set-string", "nriImagePolicy.bootstrapAllowlist.digests."+goldenDigest+"=ghcr.io/confidential-dot-ai/cds@"+goldenDigest,
		"--set", "volumed.image.tag=gold",
	)
	attestAPI := []string{"--set", "attestationApi.image.tag=gold"}
	pod := append(slices.Clone(common),
		"--set", "image.digest="+goldenDigest,
		"--set", "kata.guestImage.tag=gold",
	)
	return []goldenCase{
		{"node-snp", chartNodeImage, node},
		{"node-tdx", chartNodeImage, append(slices.Clone(node), "--set", "platform=tdx")},
		{"node-snp-vol", chartNodeImage, append(slices.Clone(node), "--set", "volumed.enabled=true")},
		{"metal-snp", chartNodeMetal, append(slices.Clone(node), attestAPI...)},
		{"gke-snp", chartNodeCloud, append(slices.Clone(node), attestAPI...)},
		{"aks-snp", chartNodeCloud, append(slices.Clone(node), append(attestAPI, "--set", "platform=az-snp")...)},
		{"aks-tdx", chartNodeCloud, append(slices.Clone(node), append(attestAPI, "--set", "platform=az-tdx")...)},
		{"pod-snp", chartPod, pod},
		{"pod-snp-single", chartPod, append(slices.Clone(pod), "--set", "cds.node.selector=null", "--set", "cds.node.tolerations=null")},
		{"pod-tdx", chartPod, append(slices.Clone(pod), "--set", "platform=tdx")},
	}
}

// goldenDoc is one rendered manifest keyed by Kind/Name.
type goldenDoc struct {
	kind, name string
	doc        map[string]any
}

// parseGoldenDocs decodes a multi-doc YAML stream into Kind/Name-keyed docs.
func parseGoldenDocs(t *testing.T, manifest string) map[string]goldenDoc {
	t.Helper()
	out := map[string]goldenDoc{}
	dec := yaml.NewDecoder(strings.NewReader(manifest))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if doc == nil {
			continue
		}
		kind, _ := doc["kind"].(string)
		meta, _ := doc["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		if kind == "" || name == "" {
			continue
		}
		out[kind+"/"+name] = goldenDoc{kind, name, doc}
	}
	return out
}

// normalizeGoldenDoc rewrites the documented intended diffs of the split to a
// canonical form, on both sides of the comparison, so anything ELSE that
// drifts still fails.
func normalizeGoldenDoc(t *testing.T, chart string, docs map[string]goldenDoc) {
	t.Helper()
	// The checksum hashes the whole ConfigMap template; the template moved
	// (monolith -> c8s-lib) with whitespace-only differences.
	if d, ok := docs["Deployment/c8s-tls-lb"]; ok {
		tmpl, _ := d.doc["spec"].(map[string]any)["template"].(map[string]any)
		if meta, _ := tmpl["metadata"].(map[string]any); meta != nil {
			if ann, _ := meta["annotations"].(map[string]any); ann != nil {
				delete(ann, "checksum/nginx-config")
			}
		}
	}
	// The containerd-prep script comment names its own path, which moved
	// with the split.
	for _, d := range docs {
		replaceInStrings(t, d.doc,
			"See internal/helmchart/c8s/files/scripts/containerd-prep.sh",
			"See internal/helmchart/<script-path-normalized>/containerd-prep.sh")
		replaceInStrings(t, d.doc,
			"See internal/helmchart/scripts/containerd-prep.sh",
			"See internal/helmchart/<script-path-normalized>/containerd-prep.sh")
	}
	// nginx.conf directives are behavior; its comments are prose. Compare the
	// directives, so a comment edit never registers as drift.
	if d, ok := docs["ConfigMap/c8s-tls-lb-nginx"]; ok {
		data, _ := d.doc["data"].(map[string]any)
		if conf, _ := data["nginx.conf"].(string); conf != "" {
			kept := []string{}
			for _, line := range strings.Split(conf, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue
				}
				kept = append(kept, line)
			}
			data["nginx.conf"] = strings.Join(kept, "\n")
		}
	}
	if chart != chartNodeImage {
		return
	}
	// node-image is RKE2-native (no distro value); the monolith's node shape
	// rendered the k8s resolver and a plain containerd restart.
	if d, ok := docs["ConfigMap/c8s-tls-lb-nginx"]; ok {
		data, _ := d.doc["data"].(map[string]any)
		if conf, _ := data["nginx.conf"].(string); conf != "" {
			for _, resolver := range []string{
				"resolver kube-dns.kube-system.svc.cluster.local;",
				"resolver rke2-coredns-rke2-coredns.kube-system.svc.cluster.local;",
			} {
				conf = strings.ReplaceAll(conf, resolver, "resolver <rke2-native-normalized>;")
			}
			data["nginx.conf"] = conf
		}
	}
	if d, ok := docs["DaemonSet/c8s-nri-image-policy-worker"]; ok {
		for _, restart := range []string{
			`RESTART_COMMAND="systemctl restart containerd"`,
			`RESTART_COMMAND="if systemctl is-active --quiet rke2-server; then systemctl restart rke2-server; else systemctl restart rke2-agent; fi"`,
		} {
			replaceInStrings(t, d.doc, restart, `RESTART_COMMAND="<rke2-native-normalized>"`)
		}
	}
}

// replaceInStrings rewrites every occurrence of old in every string leaf of
// the decoded document.
func replaceInStrings(t *testing.T, node any, old, new string) {
	t.Helper()
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			if s, ok := child.(string); ok {
				v[k] = strings.ReplaceAll(s, old, new)
			} else {
				replaceInStrings(t, child, old, new)
			}
		}
	case []any:
		for i, child := range v {
			if s, ok := child.(string); ok {
				v[i] = strings.ReplaceAll(s, old, new)
			} else {
				replaceInStrings(t, child, old, new)
			}
		}
	}
}

func TestGoldenEquivalence(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			goldenRaw, err := os.ReadFile(filepath.Join("testdata", "golden", tc.name+".golden.yaml"))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			fingerprintRaw, err := os.ReadFile(filepath.Join("testdata", "golden", tc.name+".fingerprint.txt"))
			if err != nil {
				t.Fatalf("read fingerprint: %v", err)
			}

			args := append([]string{
				"template", "c8s", tc.chart,
				"--kube-version", "1.30.0",
				"--namespace", "c8s-system",
			}, tc.args...)
			cmd := exec.Command("helm", args...)
			cmd.Dir = "."
			rendered, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, rendered)
			}

			golden := parseGoldenDocs(t, string(goldenRaw))
			fresh := parseGoldenDocs(t, string(rendered))

			// The fingerprint pins the resource set; compare it both against
			// its own golden (sanity) and against the fresh render.
			fingerprint := strings.Split(strings.TrimSpace(string(fingerprintRaw)), "\n")
			slices.Sort(fingerprint)
			goldenSet := slices.Sorted(maps.Keys(golden))
			if !slices.Equal(fingerprint, goldenSet) {
				t.Fatalf("fingerprint does not match its own golden render:\nfingerprint: %v\ngolden: %v", fingerprint, goldenSet)
			}
			freshSet := slices.Sorted(maps.Keys(fresh))
			if !slices.Equal(fingerprint, freshSet) {
				missing, extra := []string{}, []string{}
				for _, k := range fingerprint {
					if _, ok := fresh[k]; !ok {
						missing = append(missing, k)
					}
				}
				for _, k := range freshSet {
					if _, ok := golden[k]; !ok {
						extra = append(extra, k)
					}
				}
				t.Fatalf("resource set drifted from the monolith golden:\nmissing from %s: %v\nunexpected: %v", tc.chart, missing, extra)
			}

			normalizeGoldenDoc(t, tc.chart, golden)
			normalizeGoldenDoc(t, tc.chart, fresh)
			for key, g := range golden {
				f := fresh[key]
				if !reflect.DeepEqual(g.doc, f.doc) {
					t.Errorf("%s %s differs from the monolith golden (beyond the documented intended diffs)\ngolden: %v\nfresh:   %v", g.kind, g.name, g.doc, f.doc)
				}
			}
		})
	}
}
