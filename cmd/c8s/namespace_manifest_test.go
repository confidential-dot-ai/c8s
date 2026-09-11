//go:build !c8s_node

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// bakedNamespacePath returns
// node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/c8s-namespace.yaml,
// the namespace RKE2 auto-applies at boot ahead of the baked HelmChart c8s
// (createNamespace: false — see node_chart_template_test.go).
func bakedNamespacePath() string {
	return filepath.Join("..", "..", "node-guest-image", "c8s", "mkosi.extra",
		"var", "lib", "rancher", "rke2", "server", "manifests", "c8s-namespace.yaml")
}

// TestBakedNamespaceMatchesNamespaceManifest asserts the baked
// c8s-namespace.yaml is exactly namespaceManifest("c8s-system") modulo
// comments and YAML-vs-JSON formatting: both must carry the same
// apiVersion/kind/name and the same three privileged PodSecurity labels a
// live `c8s install` applies to its release namespace, so the chart's own
// privileged pods (nri-image-policy's baked installer pins, attestation-api,
// ratls-mesh) admit on first boot the same way they do on a hosted install.
func TestBakedNamespaceMatchesNamespaceManifest(t *testing.T) {
	want, err := namespaceManifest("c8s-system")
	if err != nil {
		t.Fatalf("namespaceManifest: %v", err)
	}
	var wantNS corev1.Namespace
	if err := json.Unmarshal(want, &wantNS); err != nil {
		t.Fatalf("parse namespaceManifest output: %v", err)
	}

	path := bakedNamespacePath()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var gotNS corev1.Namespace
	if err := yaml.Unmarshal(raw, &gotNS); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	if gotNS.APIVersion != wantNS.APIVersion || gotNS.Kind != wantNS.Kind {
		t.Errorf("%s: apiVersion/kind = %s/%s, want %s/%s", path, gotNS.APIVersion, gotNS.Kind, wantNS.APIVersion, wantNS.Kind)
	}
	if gotNS.Name != wantNS.Name {
		t.Errorf("%s: metadata.name = %q, want %q", path, gotNS.Name, wantNS.Name)
	}
	if len(gotNS.Labels) != len(wantNS.Labels) {
		t.Errorf("%s: labels = %v, want exactly %v (no extra labels)", path, gotNS.Labels, wantNS.Labels)
	}
	for k, v := range wantNS.Labels {
		if gotNS.Labels[k] != v {
			t.Errorf("%s: label %s = %q, want %q", path, k, gotNS.Labels[k], v)
		}
	}
}
