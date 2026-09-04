// The four shape charts share large values subtrees (the split replaced one
// values.yaml with four). This file is the consistency guarantee: every
// section that is not shape-defining must be byte-identical across the
// charts that carry it, modulo the explicit per-shape allowlist below. An
// edit that must apply everywhere (a cds knob, a tls-lb default) is made in
// one chart and forgotten in the others without this net.
package helmchart

import (
	"reflect"
	"slices"
	"testing"
)

// valuesSection returns the named top-level section of a chart's values.
func valuesSection(t *testing.T, chart, section string) any {
	t.Helper()
	values := readChartValues(t, chart)
	v, ok := values[section]
	if !ok {
		t.Fatalf("%s values.yaml: section %q missing", chart, section)
	}
	return v
}

// withoutKey returns a copy of the section map minus the named key.
func withoutKey(t *testing.T, section any, key string) any {
	t.Helper()
	m, ok := section.(map[string]any)
	if !ok {
		t.Fatalf("section is not a map: %T", section)
	}
	out := map[string]any{}
	for k, v := range m {
		if k != key {
			out[k] = v
		}
	}
	return out
}

// identicalEverywhere lists the values sections that must be deep-equal in
// every one of the four shape charts. Shape-defining sections (kata,
// attestationApi, ratlsMesh, volumed, nriImagePolicy, cds.service, distro)
// are covered separately below.
var identicalEverywhere = []string{
	"image",
	"operator",
	"imagePullSecrets",
	"imagePullSecret",
	"certProvisioning",
	"serviceAccount",
	"statusMirror",
	"hostNamespacePolicy",
	"attestation",
	"runtimeDir",
	"webhook",
	"tlsLb",
	"podSecurityContext",
}

func TestValuesSharedSectionsIdentical(t *testing.T) {
	for _, section := range identicalEverywhere {
		t.Run(section, func(t *testing.T) {
			want := valuesSection(t, chartPod, section)
			for _, chart := range chartDirs[1:] {
				if got := valuesSection(t, chart, section); !reflect.DeepEqual(want, got) {
					t.Errorf("%s: section %q drifted from pod's\nwant: %v\ngot:  %v", chart, section, want, got)
				}
			}
		})
	}
}

func TestValuesCdsIdenticalModuloService(t *testing.T) {
	// cds is identical across all four charts except cds.service: the pod
	// chart's in-guest CDS is reached over the cluster Service, the node
	// charts expose the node-local NodePort the host plugin pulls from.
	want := withoutKey(t, valuesSection(t, chartPod, "cds"), "service")
	for _, chart := range nodeChartDirs {
		if got := withoutKey(t, valuesSection(t, chart, "cds"), "service"); !reflect.DeepEqual(want, got) {
			t.Errorf("%s: cds (minus service) drifted from pod's\nwant: %v\ngot:  %v", chart, want, got)
		}
	}
	svc := valuesSection(t, chartNodeCloud, "cds").(map[string]any)["service"]
	for _, chart := range []string{chartNodeMetal, chartNodeImage} {
		if got := valuesSection(t, chart, "cds").(map[string]any)["service"]; !reflect.DeepEqual(svc, got) {
			t.Errorf("%s: cds.service drifted from node-cloud's\nwant: %v\ngot:  %v", chart, svc, got)
		}
	}
}

// ratlsMesh and volumed exist on every node chart with identical knobs.
func TestValuesNodeSectionsIdentical(t *testing.T) {
	for _, section := range []string{"ratlsMesh", "volumed"} {
		t.Run(section, func(t *testing.T) {
			want := valuesSection(t, chartNodeCloud, section)
			for _, chart := range []string{chartNodeMetal, chartNodeImage} {
				if got := valuesSection(t, chart, section); !reflect.DeepEqual(want, got) {
					t.Errorf("%s: section %q drifted from node-cloud's\nwant: %v\ngot:  %v", chart, section, want, got)
				}
			}
		})
	}
}

// attestationApi exists on node-cloud and node-metal only, with identical
// knobs.
func TestValuesAttestationApiIdentical(t *testing.T) {
	want := valuesSection(t, chartNodeCloud, "attestationApi")
	if got := valuesSection(t, chartNodeMetal, "attestationApi"); !reflect.DeepEqual(want, got) {
		t.Errorf("attestationApi drifted between node-cloud and node-metal\ncloud: %v\nmetal: %v", want, got)
	}
}

// nriImagePolicy is identical between node-cloud and node-metal except
// policy.exemptNamespaces ([kube-system] on the hosted lane, [] on
// bare metal), and its bootstrapAllowlist floor is identical in all four
// charts. node-image's pins form is a different shape by design.
func TestValuesNriImagePolicyIdenticalModuloExemptNamespaces(t *testing.T) {
	cloud := valuesSection(t, chartNodeCloud, "nriImagePolicy")
	metal := valuesSection(t, chartNodeMetal, "nriImagePolicy")
	strip := func(s any) any {
		policy := withoutKey(t, s.(map[string]any)["policy"], "exemptNamespaces")
		out := map[string]any{}
		for k, v := range s.(map[string]any) {
			out[k] = v
		}
		out["policy"] = policy
		return out
	}
	if !reflect.DeepEqual(strip(cloud), strip(metal)) {
		t.Errorf("nriImagePolicy (minus policy.exemptNamespaces) drifted between node-cloud and node-metal\ncloud: %v\nmetal: %v", strip(cloud), strip(metal))
	}

	floor := valuesSection(t, chartPod, "nriImagePolicy").(map[string]any)["bootstrapAllowlist"]
	for _, chart := range nodeChartDirs {
		if got := valuesSection(t, chart, "nriImagePolicy").(map[string]any)["bootstrapAllowlist"]; !reflect.DeepEqual(floor, got) {
			t.Errorf("%s: nriImagePolicy.bootstrapAllowlist drifted from pod's\nwant: %v\ngot:  %v", chart, floor, got)
		}
	}
}

// Section presence IS the shape: kata only in pod, attestationApi only in
// node-cloud/node-metal, ratlsMesh and volumed only in the node charts,
// cds.service only in the node charts, distro everywhere but node-image
// (RKE2 implied there).
func TestValuesShapeSectionPresence(t *testing.T) {
	for _, tc := range []struct {
		section string
		present []string
	}{
		{"kata", []string{chartPod}},
		{"attestationApi", []string{chartNodeCloud, chartNodeMetal}},
		{"ratlsMesh", nodeChartDirs},
		{"volumed", nodeChartDirs},
		{"distro", []string{chartPod, chartNodeCloud, chartNodeMetal}},
	} {
		t.Run(tc.section, func(t *testing.T) {
			for _, chart := range chartDirs {
				values := readChartValues(t, chart)
				_, ok := values[tc.section]
				want := slices.Contains(tc.present, chart)
				if ok != want {
					t.Errorf("%s values.yaml: section %q present=%v, want %v", chart, tc.section, ok, want)
				}
			}
		})
	}
	// cds.service only in the node charts.
	for _, chart := range chartDirs {
		cds := valuesSection(t, chart, "cds").(map[string]any)
		_, ok := cds["service"]
		want := slices.Contains(nodeChartDirs, chart)
		if ok != want {
			t.Errorf("%s values.yaml: cds.service present=%v, want %v", chart, ok, want)
		}
	}
}

// distro defaults: k8s on pod/node-cloud, rke2 on node-metal, absent on
// node-image (its distro is RKE2 by construction).
func TestValuesDistroDefaults(t *testing.T) {
	for chart, want := range map[string]string{
		chartPod:       "k8s",
		chartNodeCloud: "k8s",
		chartNodeMetal: "rke2",
	} {
		if got := readChartValues(t, chart)["distro"]; got != want {
			t.Errorf("%s: distro default = %v, want %q", chart, got, want)
		}
	}
}

// c8sComponents enumerates exactly the images the shape deploys, in stable
// order; `c8s install` resolves digests from this list.
func TestValuesComponentListsMatchShape(t *testing.T) {
	valuePaths := func(t *testing.T, chart string) []string {
		t.Helper()
		components, ok := readChartValues(t, chart)["c8sComponents"].([]any)
		if !ok {
			t.Fatalf("%s values.yaml: c8sComponents missing", chart)
		}
		var out []string
		for _, c := range components {
			out = append(out, c.(map[string]any)["valuePath"].(string))
		}
		return out
	}
	for chart, want := range map[string][]string{
		chartPod:       {"image", "cds.image"},
		chartNodeCloud: {"image", "cds.image", "attestationApi.image", "ratlsMesh.image", "nriImagePolicy.image", "volumed.image"},
		chartNodeMetal: {"image", "cds.image", "attestationApi.image", "ratlsMesh.image", "nriImagePolicy.image", "volumed.image"},
		chartNodeImage: {"image", "cds.image", "ratlsMesh.image", "nriImagePolicy.image", "volumed.image"},
	} {
		if got := valuePaths(t, chart); !slices.Equal(got, want) {
			t.Errorf("%s: c8sComponents valuePaths = %v, want %v", chart, got, want)
		}
	}
}
