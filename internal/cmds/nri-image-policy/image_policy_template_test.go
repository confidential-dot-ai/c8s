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
		"@NRI_DIGEST@": digest('a'),
		"@NRI_IMAGE@":  "ghcr.io/confidential-dot-ai/nri-image-policy@" + digest('a'),
		"@CDS_DIGEST@": digest('b'),
		"@CDS_IMAGE@":  "ghcr.io/confidential-dot-ai/cds@" + digest('b'),
		"@PLATFORM@":   "snp",
		// Unsealed build: no baked policy, pull from the node-local CDS.
		"@STATIC_ALLOWLIST_PATH@": "",
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
	// instead of at node boot.
	floor := map[string]string{
		"sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d": "busybox:1.38.0@sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d",
		"sha256:2c0491ce30c82a6b480741f209f12f7c7e6de872c02385946c4a9ec875e679dc": "docker.io/rancher/hardened-addon-resizer:1.8.23-build20260206",
		"sha256:12160ac4f0c2b72fe56933e387669aacba1d060184f90bd63b91b7fddc745e02": "docker.io/rancher/hardened-cluster-autoscaler:v1.10.3-build20260206",
		"sha256:35d7cef6c1b8f8ddeec45213cc6ecfa5815f08859df9438e245675674d077294": "docker.io/rancher/hardened-cni-plugins:v1.9.0-build20260206",
		"sha256:2cd608bfb6ca1ee3b6239bba98537514f7cd57dc59a0b0d83bfdcf75400dee15": "docker.io/rancher/hardened-coredns:v1.14.1-build20260206",
		"sha256:40ff78301bf77af7a03f6d6ddd6f423c75f8e3e32a3de77dda7e170fe12ccff6": "docker.io/rancher/hardened-dns-node-cache:1.26.7-build20260206",
		"sha256:9e73bd45266f4410c532258eb7a108a34990307ebe9a476b8220ab035cfc6603": "docker.io/rancher/hardened-etcd:v3.6.7-k3s1-build20260227",
		"sha256:98bf2e59d5b9052f8905ff123494457d052c9909d11eb10ae64feffe28bdffed": "docker.io/rancher/hardened-k8s-metrics-server:v0.8.1-build20260206",
		"sha256:7d4e658ad73aca6a80ab26d392395e9958f03105df5541d7552f70451ac0267d": "docker.io/rancher/hardened-kubernetes:v1.34.5-rke2r1-build20260227",
		"sha256:7975b56b85df5ae6aa8588333423561b37dcd62b9144263d8df62d5de7eaec6d": "docker.io/rancher/hardened-snapshot-controller:v8.4.0-build20260205",
		"sha256:4e0ed1340f5589b5c486f0ee7c54b1622d5bc94174ea1bf132b9bea506e5e589": "docker.io/rancher/klipper-helm:v0.9.14-build20260210",
		"sha256:25733202e90e2f6a86cd22d3833443e5469e09c78c9852aa7a21c8d902c4a292": "docker.io/rancher/klipper-lb:v0.4.14",
		"sha256:e8e4f7834f15f4c8a3255808a0df8f407ba860a56091ca22b946d3282f3f6585": "docker.io/rancher/mirrored-cilium-certgen:v0.3.2",
		"sha256:891f732be1cbe09f47ac9d722717a49850678747c6c21b7e94f39c310798f330": "docker.io/rancher/mirrored-cilium-cilium-envoy:v1.35.9-1770979049-232ed4a26881e4ab4f766f251f258ed424fff663",
		"sha256:b9a7bc9cdb24a36894769c427d93b4fcf28d03a93c1638de7e4debc80f6cd9a3": "docker.io/rancher/mirrored-cilium-cilium:v1.19.1",
		"sha256:a175248d4b61bcde9cbc31d02cfa52b34db44db0093f383c9ff1193002d94ea8": "docker.io/rancher/mirrored-cilium-clustermesh-apiserver:v1.19.1",
		"sha256:28d5509fc5e394643604afac2aaa2288c1faba9434013dabd29dd902c443710b": "docker.io/rancher/mirrored-cilium-hubble-relay:v1.19.1",
		"sha256:8b5758a10a31a21dd70145bee3ee48f46147fb7fe5d209305461f6aa18bbe6d5": "docker.io/rancher/mirrored-cilium-hubble-ui-backend:v0.13.3",
		"sha256:867c82633de1f2b48ea6227902861f7119bd41d46362e503068d6cd2525eeb74": "docker.io/rancher/mirrored-cilium-hubble-ui:v0.13.3",
		"sha256:09af2b5afbccde507fb9e05250b81cacd54ea3bdd71cd08efa453bc775ade0f4": "docker.io/rancher/mirrored-cilium-operator-aws:v1.19.1",
		"sha256:3a9859ed15a5c601510946c0e4c5806c2344ddcb194a697554de377af6f26134": "docker.io/rancher/mirrored-cilium-operator-azure:v1.19.1",
		"sha256:c042b8091d611188cbdba24ec1c0b78343745b68df7f5dfc12858e4ecd1000f9": "docker.io/rancher/mirrored-cilium-operator-generic:v1.19.1",
		"sha256:c28cee6d72f9a1f356367d4b2f77342212da5e807b11ea58844013b63e063e95": "docker.io/rancher/mirrored-ingress-nginx-kube-webhook-certgen:v1.6.7",
		"sha256:16974531848218d24822bf606be022d030ab8c9b05b2ecf11076c4c1c6885c95": "docker.io/rancher/mirrored-pause:3.6",
		"sha256:17b8023c43ab607143e6e32006258ff4771deb9d2bfe830352ac8ee876253e28": "docker.io/rancher/nginx-ingress-controller:v1.14.3-hardened3",
		"sha256:d6483cd07dc5660adac889895f053d63915a54e0b0cbb1b51a7db1e0c566985f": "docker.io/rancher/rke2-cloud-provider:v1.34.4-0.20260211145917-c6017918a65c-build20260211",
		"sha256:4f502170a33ec2b687e1b703abe31b1e290ff17cd45fba45b138c73689d3b02c": "docker.io/rancher/rke2-runtime:v1.34.5-rke2r1",
		"sha256:25cc340fe6fd53c101e16fc452f503e7a92c219c64a80ed5381784b522dbbf77": "nvcr.io/nvidia/k8s-device-plugin:v0.19.3@sha256:25cc340fe6fd53c101e16fc452f503e7a92c219c64a80ed5381784b522dbbf77",
		"sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f": "rancher/local-path-provisioner:v0.0.36@sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f",
	}
	for digest, ref := range floor {
		if _, ok := cfg.Allowlist.AlwaysAllow[digest]; !ok {
			t.Errorf("%s (%s) missing from the baked floor — the node cannot boot its system components", ref, digest)
		}
	}

	// always_allow is the generated floor plus the two rendered tokens (the
	// nri plugin self-allow and cds), so the exact count catches an entry a
	// regen adds or drops.
	if want := len(floor) + 2; len(cfg.Allowlist.AlwaysAllow) != want {
		t.Errorf("baked floor has %d always_allow entries, want %d (%d system floor + nri + cds)",
			len(cfg.Allowlist.AlwaysAllow), want, len(floor))
	}

	// Every floor key must be a digest the index admits as-is.
	idx := alwaysAllowAllowlist(cfg.Allowlist.AlwaysAllow).BuildIndex()
	for d := range cfg.Allowlist.AlwaysAllow {
		if !idx.AdmitsDigest(d) {
			t.Errorf("floor key %q is not an admissible digest", d)
		}
	}
}

// A sealed build renders the same template with the policy path set and the
// pull URL blanked; that shape must load, be static, and pull nothing.
func TestNodeImageBootConfig_SealedShapeIsStatic(t *testing.T) {
	tmpl, err := os.ReadFile("../../../node-guest-image/c8s/image-policy.yaml.in")
	if err != nil {
		t.Fatal(err)
	}
	dg := func(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }
	out := string(tmpl)
	for k, v := range map[string]string{
		"@NRI_DIGEST@":            dg('a'),
		"@NRI_IMAGE@":             "ghcr.io/confidential-dot-ai/nri-image-policy@" + dg('a'),
		"@CDS_DIGEST@":            dg('b'),
		"@CDS_IMAGE@":             "ghcr.io/confidential-dot-ai/cds@" + dg('b'),
		"@PLATFORM@":              "tdx",
		"@STATIC_ALLOWLIST_PATH@": "/etc/c8s/static-allowlist.json",
		// mkosi.sync blanks the pull URL on a sealed build.
		`url: "https://127.0.0.1:30808"`: `url: ""`,
	} {
		out = strings.ReplaceAll(out, k, v)
	}
	cfg, err := parseConfig([]byte(out))
	if err != nil {
		t.Fatalf("sealed boot config does not load: %v", err)
	}
	if !cfg.StaticEnabled() || cfg.PullEnabled() {
		t.Fatalf("sealed shape: static=%v pull=%v, want static and no pull", cfg.StaticEnabled(), cfg.PullEnabled())
	}
	if cfg.Allowlist.Pull.AttestationApiURL == "" {
		t.Fatal("the inventory endpoint still needs attestation_api_url on a sealed node")
	}
}
