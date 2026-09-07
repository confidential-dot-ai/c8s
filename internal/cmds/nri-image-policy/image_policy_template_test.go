package nriimagepolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The node image's baked boot config is the plugin's other config schema
// consumer: mkosi.sync renders image-policy.yaml.in by placeholder
// substitution, so nothing type-checks it against this package's config
// struct. Load the rendered form here so a drift fails in `go test`, not at
// node boot.
const nodeImagePolicyTemplate = "../../../node-guest-image/c8s/image-policy.yaml.in"

func renderNodeImagePolicy(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(nodeImagePolicyTemplate))
	if err != nil {
		t.Fatalf("read node-image policy template: %v", err)
	}
	digest := func(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }
	repl := map[string]string{
		"@CDS_DIGEST@": digest('b'),
		"@CDS_IMAGE@":  "ghcr.io/confidential-dot-ai/cds@" + digest('b'),
		"@PLATFORM@":   "snp",
	}
	out := string(body)
	for k, v := range repl {
		out = strings.ReplaceAll(out, k, v)
	}
	if ph := regexp.MustCompile(`@[A-Z_]+@`).FindString(out); ph != "" {
		t.Fatalf("unsubstituted placeholder %s left in rendered template", ph)
	}
	return out
}

func TestNodeImageBootConfig_LoadsAndFloorsSystemImages(t *testing.T) {
	rendered := renderNodeImagePolicy(t)
	if strings.Contains(rendered, "exempt_namespaces") {
		t.Fatal("exempt_namespaces must not return: admission keys on the digest floor alone")
	}

	path := filepath.Join(t.TempDir(), "image-policy.yaml")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("the rendered node-image boot config does not load: %v", err)
	}

	// The full RKE2 system floor: every digest systemfloor derives from the
	// pinned airgap bundles and baked manifests. A regen for an RKE2 pin bump
	// rewrites these — update the pins with it. Pinning the whole set, not a
	// boot-critical subset, makes a dropped or corrupted entry fail here
	// instead of at node boot. The local-path helper's busybox is NOT here:
	// systemfloor drops it (-exclude-ref) and the chart seeds it argv-pinned.
	floor := map[string]string{
		"sha256:8026310fc44d985bf7c02434ad11d5f826a1aa1567606eea121b24ba9b3b0590": "docker.io/rancher/hardened-addon-resizer:1.8.23-build20260819",
		"sha256:c9b9b027e4d2cf1731311f9714f4aa633d37d7b0a72c9d3e6fc7a0594350d27c": "docker.io/rancher/hardened-cluster-autoscaler:v1.10.3-build20260819",
		"sha256:0d26512c90d935db3180f47a7a716e3dfac0847ec29076fb5487e535125a86a8": "docker.io/rancher/hardened-cni-plugins:v1.9.1-build20260717",
		"sha256:e9435ef6526a98e8d01d98a85d23770859ca49028ebd282912ae5e76f92c0166": "docker.io/rancher/hardened-coredns:v1.14.7-build20260819",
		"sha256:54a53cb983d47579a8e7cdcd9ae38bc58ff85c28c63fd26de02ce332d5f988ee": "docker.io/rancher/hardened-dns-node-cache:1.26.8-build20260819",
		"sha256:4f7ffbb3399c9f8137f5d0dd3ca0eddc7909e5d0155b35f1b0449baf96d61bfa": "docker.io/rancher/hardened-etcd:v3.6.14-k3s1-build20260819",
		"sha256:4935e86e846d75591113f64ad4e0402718a1eda08f6900a9325d54f1df64945c": "docker.io/rancher/hardened-k8s-metrics-server:v0.9.0-build20260819",
		"sha256:c8e5263407ac439de1dcdde98c7623efb9e17050715a80259d8bd5e81b5a9289": "docker.io/rancher/hardened-kubernetes:v1.36.4-rke2r1-build20260821",
		"sha256:8d5872d767f93393273cb1ecad81e4bc08af65311d206bc31ee8f48bc58e51c4": "docker.io/rancher/hardened-snapshot-controller:v8.6.0-build20260819",
		"sha256:dff360a22c8a28c2af3e78b2b4cf09a6c8edc199e27eb9f7c417bfc1ac41078e": "docker.io/rancher/hardened-traefik:v3.7.11-build20260819",
		"sha256:ba922718d919920b6b6168e3f55f8effa85032a38bf44d8cc5f4df79a2fe405d": "docker.io/rancher/klipper-helm:v0.13.3-build20260820",
		"sha256:910944bb0bd94f060a82a56ca1ea1c577d3e49b3473a093a47a985f32e92d94a": "docker.io/rancher/klipper-lb:v0.4.17",
		"sha256:30df3131622e08f3051b171af68cd7997609aa19f7bd692b70b5b6bd6fcd659e": "docker.io/rancher/mirrored-cilium-certgen:v0.4.6",
		"sha256:5f804f48df0c42c66aeff3252f36277ecbfd4e968bf3ec81b0717323355e7add": "docker.io/rancher/mirrored-cilium-cilium-envoy:v1.36.9-1782267392-edeb3f2af56c37c407efa1f63f0b32f595399bbc",
		"sha256:134ab48d00e67bed72fa43e0492adf2f0c78383e21da7ee1aeb5b7aa8ef2e7ee": "docker.io/rancher/mirrored-cilium-cilium:v1.19.6",
		"sha256:59ab31ea62509b1596e1dfd436e781f5e7549a15aea82aab05e29657ac099f43": "docker.io/rancher/mirrored-cilium-clustermesh-apiserver:v1.19.6",
		"sha256:1d3cd7f07e11e451683002b925a25ccba74d9aed2fc2e454a7173d260a2d11bd": "docker.io/rancher/mirrored-cilium-hubble-relay:v1.19.6",
		"sha256:26446592541d6e37333850b37bd59cccec69f6f2f02fd50a8588d3f1a136717f": "docker.io/rancher/mirrored-cilium-hubble-ui-backend:v0.13.5",
		"sha256:9906c0b60c9d65c467ccc541154728ad00886a3f8012fe7b53e88404f06babaa": "docker.io/rancher/mirrored-cilium-hubble-ui:v0.13.5",
		"sha256:2f28e344b83ac28bf9a561b666dd3e935c7238d8d4be4d2c840053e178718945": "docker.io/rancher/mirrored-cilium-operator-aws:v1.19.6",
		"sha256:10b602130d98d8de3c40213f938430a962b14ccf4b405cdbcb2af62ba52dd0e6": "docker.io/rancher/mirrored-cilium-operator-azure:v1.19.6",
		"sha256:aadc3b1a2b8b682f5b4f7b01e182eeeac16f1177af0561b07825abab1d654b2b": "docker.io/rancher/mirrored-cilium-operator-generic:v1.19.6",
		"sha256:f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4": "docker.io/rancher/mirrored-pause:3.10.2",
		"sha256:95a33533d97b10502be19e4f3e60e7ce9c30f4879084709af96259a01253f044": "docker.io/rancher/rke2-cloud-provider:v1.36.4-0.20260817193921-a2fc9574e060-build20260820",
		"sha256:7956a28b1ebd803f58341ba88fed4c8bc878ec13226c2e55959ba5a88c21341e": "docker.io/rancher/rke2-runtime:v1.36.4-rke2r1",
		"sha256:25cc340fe6fd53c101e16fc452f503e7a92c219c64a80ed5381784b522dbbf77": "nvcr.io/nvidia/k8s-device-plugin:v0.19.3@sha256:25cc340fe6fd53c101e16fc452f503e7a92c219c64a80ed5381784b522dbbf77",
		"sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f": "rancher/local-path-provisioner:v0.0.36@sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f",
	}
	for digest, ref := range floor {
		if _, ok := cfg.Allowlist.AlwaysAllow[digest]; !ok {
			t.Errorf("%s (%s) missing from the baked floor — the node cannot boot its system components", ref, digest)
		}
	}

	// always_allow is the generated floor plus the rendered CDS token, so the
	// exact count catches an entry a regen adds or drops. The installer image
	// is not self-allowed: it runs shell scripts, so it is admitted
	// argv-pinned by the served document, never by digest alone.
	if want := len(floor) + 1; len(cfg.Allowlist.AlwaysAllow) != want {
		t.Errorf("baked floor has %d always_allow entries, want %d (%d system floor + cds)",
			len(cfg.Allowlist.AlwaysAllow), want, len(floor))
	}
	for digest := range cfg.Allowlist.AlwaysAllow {
		if strings.Contains(cfg.Allowlist.AlwaysAllow[digest], "busybox") {
			t.Errorf("busybox %s must not return to the digest-only floor; it is seeded argv-pinned", digest)
		}
	}

	// Every floor key must be a digest the store admits as-is.
	store := newPolicyStore(cfg.Allowlist.AlwaysAllow)
	for d := range cfg.Allowlist.AlwaysAllow {
		if !store.alwaysAllows(d) {
			t.Errorf("floor key %q is not an admissible digest", d)
		}
	}
}
