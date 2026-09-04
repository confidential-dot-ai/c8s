// Node-image shape (c8s-node-image): nodes booted from the c8s
// node-guest-image, which bakes the attestation-api and the NRI plugin. The
// chart renders no attestation-api DaemonSet (consumers dial the baked host
// service via $(HOST_IP)) and a pins-only NRI installer (the image owns the
// plugin binary, its containerd registration, and the boot config).
package helmchart

import (
	"slices"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// TestImageAttestationURLUsesHostIP proves the pod-netns components (cds,
// tls-lb's cert sidecar, ratls-mesh) dial the node-baked host attestation-api
// via the $(HOST_IP) downward-API env var: there is no in-cluster Service and
// pods cannot reach host loopback. The operator is the exception: it forwards
// its --attestation-api-url verbatim into the tenant get-cert sidecars it
// injects, so the placeholder must stay UNEXPANDED there — the operator
// container deliberately omits HOST_IP so each tenant pod expands it against
// its own node.
func TestImageAttestationURLUsesHostIP(t *testing.T) {
	const hostIPURL = "--attestation-api-url=http://$(HOST_IP):8400"
	out, err := helmTemplate(t, chartNodeImage)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	// No chart-managed evidence source renders in this shape at all.
	if renderedManifestHasNamedKind(t, out, "Service", "c8s-attestation-api") ||
		renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-attestation-api") {
		t.Fatalf("node-image renders no attestation-api Service or DaemonSet\n%s", out)
	}

	// cds: pod-netns, dials the host attestation-api via $(HOST_IP).
	cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
	assertContainerArgs(t, cds, hostIPURL)
	if !hasHostIPEnv(cds) {
		t.Errorf("cds container missing HOST_IP downward-API env; have %+v", cds.Env)
	}

	// tls-lb c8s-cert sidecar (via c8s.getCertContainers).
	cert := tlsLBGetCertContainer(t, out, "c8s-cert")
	assertContainerArgs(t, cert, hostIPURL)
	if !hasHostIPEnv(cert) {
		t.Errorf("tls-lb c8s-cert missing HOST_IP downward-API env; have %+v", cert.Env)
	}

	// tls-lb cds-attest sidecar.
	attest := renderedDeploymentContainer(t, out, "c8s-tls-lb", "cds-attest")
	assertContainerArgs(t, attest, hostIPURL)
	if !hasHostIPEnv(attest) {
		t.Errorf("tls-lb cds-attest missing HOST_IP downward-API env; have %+v", attest.Env)
	}

	// tls-lb allowlist proxy: pod-netns, uses the same verifier endpoint for
	// the RA-TLS hop to CDS.
	allowlistProxy := renderedDeploymentContainer(t, out, "c8s-tls-lb", "allowlist-proxy")
	assertContainerArgs(t, allowlistProxy, hostIPURL)
	if !hasHostIPEnv(allowlistProxy) {
		t.Errorf("tls-lb allowlist-proxy missing HOST_IP downward-API env; have %+v", allowlistProxy.Env)
	}

	// ratls-mesh: hostNetwork, so $(HOST_IP) is its own node IP. Two-arg form.
	mesh := renderedDaemonSetContainer(t, out, "c8s-ratls-mesh", "ratls-mesh")
	if !slices.Contains(mesh.Args, "http://$(HOST_IP):8400") {
		t.Errorf("ratls-mesh missing http://$(HOST_IP):8400 arg; have %v", mesh.Args)
	}
	if !hasHostIPEnv(mesh) {
		t.Errorf("ratls-mesh missing HOST_IP downward-API env; have %+v", mesh.Env)
	}

	// operator: forwards the string verbatim; the placeholder must NOT be
	// expanded here, so the container must NOT define HOST_IP.
	if !slices.Contains(renderedOperatorArgs(t, out), hostIPURL) {
		t.Errorf("operator missing verbatim %q\n%v", hostIPURL, renderedOperatorArgs(t, out))
	}
	op := renderedDeploymentContainer(t, out, "c8s-operator", "operator")
	if hasHostIPEnv(op) {
		t.Errorf("operator MUST NOT define HOST_IP (it forwards $(HOST_IP) verbatim to tenant sidecars); env %+v", op.Env)
	}
}

// The image bakes the attestation-api: none of its chart-managed pieces
// (DaemonSet, Service, ConfigMap, NetworkPolicy) may render.
func TestImageRendersNoAttestationApiStack(t *testing.T) {
	out, err := helmTemplate(t, chartNodeImage)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, doc := range []struct{ kind, name string }{
		{"DaemonSet", "c8s-attestation-api"},
		{"Service", "c8s-attestation-api"},
		{"ConfigMap", "c8s-attestation-api"},
		{"NetworkPolicy", "c8s-attestation-api"},
	} {
		if renderedManifestHasNamedKind(t, out, doc.kind, doc.name) {
			t.Errorf("node-image renders %s %q — the attestation-api is baked into the node image", doc.kind, doc.name)
		}
	}
}

// TestImagePinsCDSIntoBakedNRIConfig guards the node-as-CVM pin path. The
// node image bakes the plugin with empty cds_measurements, and the chart is
// the only thing that knows this release's pins — so an install that does not
// carry them into the baked config leaves the component deciding which images
// may run on the node willing to take its allowlist from ANY RA-TLS-attested
// CDS, and its sandbox-digests endpoint willing to answer any of them.
// Regression for a bare-metal run that found exactly that (2026-08-26).
func TestImagePinsCDSIntoBakedNRIConfig(t *testing.T) {
	const (
		pinM = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
		pinR = "1=bbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aa"
	)
	const pinsImageDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000d1"
	out, err := helmTemplate(t, chartNodeImage,
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set-string", "nriImagePolicy.image.digest="+pinsImageDigest,
		"--set-string", "cds.measurements[0]="+pinM,
		"--set-string", "cds.rtmrs[0]="+pinR,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	for _, want := range []string{
		"set-cds-pins",
		"--cds-measurements \"" + pinM + "\"",
		"--cds-rtmrs \"" + pinR + "\"",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("pins installer script missing %q\n%s", want, script)
		}
	}

	// The baked config carries the image floor whose RKE2 system digests only
	// the image build resolves, so the installer must patch it, never rewrite
	// it — and must leave the binary and the containerd registration alone.
	for _, forbidden := range []string{"IMAGE_POLICY_EOF", "install_file", "render_nri_toml"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("pins installer script must not run %q — it would replace what the node image measured\n%s", forbidden, script)
		}
	}
	for _, c := range ds.Spec.Template.Spec.InitContainers {
		if c.Name == "containerd-prep" {
			t.Errorf("pins installer renders containerd-prep; the node image owns the containerd NRI registration")
		}
	}

	// The installer image is a chart image, not a baked one, so the node admits
	// it only through the seed CDS serves.
	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse: %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	if got := seed.Digests[pinsImageDigest]; got != "ghcr.io/confidential-dot-ai/nri-image-policy@"+pinsImageDigest {
		t.Errorf("seed[%s] = %q, want the pins installer image; the baked plugin would deny it", pinsImageDigest, got)
	}
}

// TestImageServesAllowlistSeed guards the node-as-CVM seed path: the chart's
// nriImagePolicy is the pins-only installer (the node image bakes the
// plugin), yet the baked plugin still pulls the live allowlist from CDS. If
// the seed is not served, CDS starts empty and every un-baked component
// (operator, ratls-mesh, tls-lb's nginx) is denied until an operator
// hand-runs `c8s allowlist add`. Regression for that deadlock: the seed
// ConfigMap must render, be mounted, and carry the deployed digests.
func TestImageServesAllowlistSeed(t *testing.T) {
	const (
		opD = "sha256:00000000000000000000000000000000000000000000000000000000000000c1"
		rmD = "sha256:00000000000000000000000000000000000000000000000000000000000000c2"
	)
	out, err := helmTemplate(t, chartNodeImage,
		"--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true",
		"--set-string", "image.digest="+opD,
		"--set-string", "ratlsMesh.image.digest="+rmD,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
	seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
	if err != nil {
		t.Fatalf("seed JSON does not parse (CDS would start empty): %v\n%s", err, cm.Data["allowlist-seed.json"])
	}
	// The un-baked components denied in the un-seeded case: operator, ratls-mesh,
	// and tls-lb's nginx (default digest from values.yaml).
	if got := seed.Digests[opD]; got != "ghcr.io/confidential-dot-ai/c8s-operator@"+opD {
		t.Errorf("seed missing operator entry; got %q\nseed: %v", got, seed.Digests)
	}
	if got := seed.Digests[rmD]; got != "ghcr.io/confidential-dot-ai/ratls-mesh@"+rmD {
		t.Errorf("seed missing ratls-mesh entry; got %q\nseed: %v", got, seed.Digests)
	}
	const nginxD = "sha256:11f3f6249b4ae3d7a4ec2a51797060107b88ead52b33b6ed3c6c33f55ca96200"
	if _, ok := seed.Digests[nginxD]; !ok {
		t.Errorf("seed missing tls-lb nginx self-entry\nseed: %v", seed.Digests)
	}
	// The flag/mount must be present so CDS actually loads the seed.
	cds := renderedDeploymentContainer(t, out, "c8s-cds", "cds")
	if !slices.Contains(cds.Args, "--allowlist-seed=/etc/cds/allowlist-seed.json") {
		t.Errorf("CDS missing --allowlist-seed flag; seed rendered but not loaded\nargs: %v", cds.Args)
	}
}

// node-image is RKE2-native by construction (the node image is an RKE2
// image): the tls-lb resolver is RKE2's CoreDNS Service and the pins
// installer restarts rke2-server/agent — with no distro value to set.
func TestImageIsRke2Native(t *testing.T) {
	out, err := helmTemplate(t, chartNodeImage)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	renderedTLSLBNginxConfig(t, out).http.assertDirective(t, "resolver", "rke2-coredns-rke2-coredns.kube-system.svc.cluster.local")

	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	if !strings.Contains(script, `RESTART_COMMAND="if systemctl is-active --quiet rke2-server; then systemctl restart rke2-server; else systemctl restart rke2-agent; fi"`) {
		t.Errorf("pins installer must restart rke2-server/agent, got:\n%s", script)
	}

	// There is no distro value on this chart; the schema refuses it.
	out, err = helmTemplate(t, chartNodeImage, "--set-string", "distro=k8s")
	if err == nil {
		t.Fatalf("helm template accepted a distro value on node-image\n%s", out)
	}
}

// The image owns the plugin's containerd registration, so the chart renders
// no uninstall hook for it (node-cloud/node-metal carry one).
func TestImageRendersNoNriUninstallHook(t *testing.T) {
	out, err := helmTemplate(t, chartNodeImage)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if renderedManifestHasNamedKind(t, out, "DaemonSet", "c8s-nri-image-policy-uninstall") {
		t.Errorf("node-image renders an NRI uninstall hook; the node image owns the containerd registration")
	}
}
