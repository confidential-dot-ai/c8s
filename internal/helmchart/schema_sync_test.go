// Schema guards: gen_schema.py generates each chart's sealed
// values.schema.json from its values.yaml. These tests pin the sync, the
// sealed-tree behavior (unknown keys refused, stale monolith values refused,
// enums enforced), and the values<->schema lockstep walk.
package helmchart

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The checked-in schemas must match regeneration from the values files.
func TestValuesSchemaInSync(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}
	// Run against the source tree, not the TestMain copy: this is the
	// checked-in-sync assertion.
	cmd := exec.Command(python, "gen_schema.py", "--check")
	cmd.Dir = chartSrcDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gen_schema.py --check: %v\n%s\nrun `python3 internal/helmchart/gen_schema.py` to regenerate", err, out)
	}
}

// Helm accepts values a chart never reads, so a misspelled key under a
// documented path is applied, silently dropped at render, and shows up only
// as whatever the un-applied value was protecting against. The sealed schema
// turns that into a render-time error naming the key.
func TestChartValuesSchemaRejectsUnknownKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  string
	}{
		// The singular of the key whose loss bricked a cluster.
		{"nriImagePolicy.policy", "nriImagePolicy.policy.exemptNamespace=kube-system"},
		{"nriImagePolicy top level", "nriImagePolicy.exemptNamespaces=kube-system"},
		{"tlsLb.hostPort", "tlsLb.hostPort.enable=false"},
		{"cds.persistence", "cds.persistence.enable=true"},
		{"volumed", "volumed.enable=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, _, _ := strings.Cut(tc.set, "=")
			out, err := helmTemplate(t, chartNodeMetal, "--set", tc.set)
			if err == nil {
				t.Fatalf("helm template accepted the unknown key %s\n%s", key, out)
			}
			// Helm's wording for the same rejection differs by version
			// ("Additional property X is not allowed" vs "additional
			// properties 'X' not allowed"), so match on the shared stem.
			unknown := key[strings.LastIndexByte(key, '.')+1:]
			if !strings.Contains(strings.ToLower(out), "additional propert") || !strings.Contains(out, unknown) {
				t.Errorf("render failure does not name the unknown key %q:\n%s", unknown, out)
			}
		})
	}
}

// The root key set is closed, so a values file carried over from an older
// release — or one with a typo above the sealed subtrees — is refused instead
// of being silently dropped.
func TestChartValuesSchemaRejectsUnknownRootKeys(t *testing.T) {
	for _, chart := range chartDirs {
		for _, key := range []string{"webhookk", "clusterName", "nriImagePolicyy"} {
			t.Run(chart+"/"+key, func(t *testing.T) {
				out, err := helmTemplate(t, chart, "--set", key+".enabled=true")
				if err == nil {
					t.Fatalf("helm template accepted unknown root key %q\n%s", key, out)
				}
				// Wording differs across helm versions; match the shared stem.
				if lower := strings.ToLower(out); !strings.Contains(lower, "additional propert") ||
					!strings.Contains(lower, strings.ToLower(key)) {
					t.Errorf("failure does not name %q as an unknown key:\n%s", key, out)
				}
			})
		}
	}
}

// The monolith chart's shape flags are gone: the chart itself is the shape
// now. A values file carried over from a monolith release (cvmMode,
// teeDevices, the per-component enabled flags, baked, the per-component
// distro/platform mirrors) must fail the render — the sealed schema refuses
// every one — rather than being silently inert.
func TestChartValuesSchemaRejectsStaleMonolithValues(t *testing.T) {
	stale := []string{
		"attestationApi.cvmMode=node",
		"attestationApi.enabled=false",
		"attestationApi.teeDevices.sevGuest=true",
		"attestationApi.platforms[0]=snp",
		"kata.enabled=true",
		"kata.distro=rke2",
		"ratlsMesh.enabled=false",
		"ratlsMesh.platform=tdx",
		"nriImagePolicy.enabled=false",
		"nriImagePolicy.baked=true",
		"nriImagePolicy.distro=rke2",
		"nriImagePolicy.hostPaths.runtimeDir=/var/run/x",
		"cds.ratlsPlatform=tdx",
		"tlsLb.attest.platform=tdx",
		"teeProxy.hostPort.enabled=true",
	}
	for _, chart := range chartDirs {
		for _, set := range stale {
			t.Run(chart+"/"+set, func(t *testing.T) {
				out, err := helmTemplate(t, chart, "--set", set)
				if err == nil {
					t.Fatalf("helm template accepted stale monolith value %q\n%s", set, out)
				}
				if !strings.Contains(strings.ToLower(out), "additional propert") {
					t.Errorf("stale value %q was not refused by the values schema:\n%s", set, out)
				}
			})
		}
	}
}

// The schema is only as good as its coverage: a key added to values.yaml but
// not to the schema makes every render of the chart fail on its own default.
// This is the lockstep guard, checked per chart against the chart's own
// values.
func TestChartValuesSchemaCoversValuesYAML(t *testing.T) {
	for _, chart := range chartDirs {
		t.Run(chart, func(t *testing.T) {
			values := readChartValues(t, chart)
			var schema struct {
				Properties map[string]any `yaml:"properties"`
			}
			readChartSchema(t, chart, &schema)
			for top, node := range schema.Properties {
				if top == "c8s-lib" {
					continue // vendored library values, open by design
				}
				assertSchemaCovers(t, values[top], node, top)
			}
		})
	}
}

// readChartSchema decodes a shape chart's values.schema.json (JSON is a
// subset of YAML, so one decoder serves both files).
func readChartSchema(t *testing.T, chart string, into any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(chart, "values.schema.json"))
	if err != nil {
		t.Fatalf("read %s/values.schema.json: %v", chart, err)
	}
	if err := yaml.Unmarshal(data, into); err != nil {
		t.Fatalf("decode %s/values.schema.json: %v", chart, err)
	}
}

// assertSchemaCovers walks a values subtree against its schema node: every key
// of a sealed object (one carrying "properties") must be declared, and the
// walk continues into each. A node with no "properties" is deliberately open —
// a label map, a digest map, a resources block — and ends the walk.
func assertSchemaCovers(t *testing.T, values, node any, path string) {
	t.Helper()
	schema, ok := node.(map[string]any)
	if !ok {
		t.Errorf("%s: schema node is not an object (%T)", path, node)
		return
	}
	props, sealed := schema["properties"].(map[string]any)
	if !sealed {
		return
	}
	if blocked, ok := schema["additionalProperties"].(bool); !ok || blocked {
		t.Errorf("%s: declares properties but does not set additionalProperties: false, so a typo still passes", path)
	}
	m, ok := values.(map[string]any)
	if !ok {
		return
	}
	for k, v := range m {
		child, ok := props[k]
		if !ok {
			t.Errorf("values.yaml sets %s.%s but values.schema.json does not declare it; every render would fail", path, k)
			continue
		}
		assertSchemaCovers(t, v, child, path+"."+k)
	}
}

// The generated schema constrains the enumerated values: a mistyped platform,
// distro, policy mode, or cert mode is refused at render instead of surfacing
// when the component rejects its config.
func TestChartValuesSchemaConstrainsTheEnums(t *testing.T) {
	for _, tc := range []struct {
		name   string
		charts []string
		set    string
	}{
		{"unknown platform", chartDirs, "platform=baremetal"},
		{"unknown distro", []string{chartPod, chartNodeCloud, chartNodeMetal}, "distro=openshift"},
		{"unknown policy mode", []string{chartNodeCloud, chartNodeMetal}, "nriImagePolicy.policy.mode=failclosed"},
		{"unknown cert mode", nodeChartDirs, "ratlsMesh.certMode=vault"},
	} {
		for _, chart := range tc.charts {
			t.Run(chart+"/"+tc.name, func(t *testing.T) {
				if out, err := helmTemplate(t, chart, "--set", tc.set); err == nil {
					t.Fatalf("helm template accepted --set %s\n%s", tc.set, out)
				}
			})
		}
	}

	// The valid values still render.
	for _, tc := range []struct {
		chart string
		args  []string
	}{
		{chartNodeMetal, []string{"--set", "platform=tdx", "--set-string", "nriImagePolicy.policy.mode=audit", "--set-string", "ratlsMesh.certMode=self-signed"}},
		{chartPod, []string{"--set", "platform=tdx", "--set-string", "distro=rke2"}},
	} {
		if out, err := helmTemplate(t, tc.chart, tc.args...); err != nil {
			t.Errorf("%s: valid enum values were refused: %v\n%s", tc.chart, err, out)
		}
	}
}
