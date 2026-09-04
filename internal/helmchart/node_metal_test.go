// Node-metal shape (c8s-node-metal): self-managed bare-metal CVM nodes. The
// chart defaults to distro=rke2 (the bare-metal fleet's distro) and mounts
// the native TEE device.
package helmchart

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The node-metal default render carries the full host-side stack: operator,
// webhook, CDS, tls-lb, attestation-api, ratls-mesh and the NRI installer.
func TestMetalRendersFullStack(t *testing.T) {
	out, err := helmTemplate(t, chartNodeMetal)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !renderedManifestHasKind(t, out, "MutatingWebhookConfiguration") {
		t.Errorf("missing MutatingWebhookConfiguration")
	}
	for _, doc := range []struct{ kind, name string }{
		{"Deployment", "c8s-operator"},
		{"Deployment", "c8s-cds"},
		{"Deployment", "c8s-tls-lb"},
		{"DaemonSet", "c8s-attestation-api"},
		{"DaemonSet", "c8s-ratls-mesh"},
		{"DaemonSet", "c8s-nri-image-policy-worker"},
	} {
		if !renderedManifestHasNamedKind(t, out, doc.kind, doc.name) {
			t.Errorf("default node-metal render missing %s %q", doc.kind, doc.name)
		}
	}
}

// node-metal defaults to distro=rke2: the tls-lb resolver is RKE2's CoreDNS
// Service, and the NRI installer targets the RKE2 containerd layout — the
// containerd-prep init container wiring the drop-in import, and the
// rke2-server/agent restart command.
func TestMetalDistroDefaultsToRke2(t *testing.T) {
	out, err := helmTemplate(t, chartNodeMetal)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	renderedTLSLBNginxConfig(t, out).http.assertDirective(t, "resolver", "rke2-coredns-rke2-coredns.kube-system.svc.cluster.local")

	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	if _, ok := findContainer(ds.Spec.Template.Spec.InitContainers, "containerd-prep"); !ok {
		t.Errorf("default (rke2): nri installer must carry the containerd-prep initContainer")
	}
	if got := hostPathVolume(t, ds, "host-containerd-config"); got != "/var/lib/rancher/rke2/agent/etc/containerd" {
		t.Errorf("host-containerd-config hostPath = %q, want the rke2 containerd dir", got)
	}
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	for _, want := range []string{
		`CONTAINERD_CONFIG_MODE="dropin"`,
		`RESTART_COMMAND="if systemctl is-active --quiet rke2-server; then systemctl restart rke2-server; else systemctl restart rke2-agent; fi"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install script missing %q", want)
		}
	}
}

// The mesh's --measurements-config path must name a key the measurements
// ConfigMap actually mounts; a mismatch starts the mesh against a missing
// file (peer pins silently absent).
func TestMeshMeasurementsConfigPathMatchesMountedKey(t *testing.T) {
	cfg := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"n","measurement":"` + strings.Repeat("ab", 48) + `"}]}`
	f := filepath.Join(t.TempDir(), "mc.json")
	if err := os.WriteFile(f, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplate(t, chartNodeMetal,
		"--set-file", "cds.measurementsConfig="+f,
		"--set-file", "ratlsMesh.measurementsConfig="+f,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-ratls-mesh")
	args := strings.Join(containerArgs(t, &ds, "ratls-mesh"), "\n")
	if !strings.Contains(args, "/etc/c8s-measurements/ratls-mesh.json") {
		t.Errorf("mesh --measurements-config must point at the mounted ratls-mesh.json key; args=%s", args)
	}
	cm := renderedConfigMap(t, out, "c8s-measurements")
	if _, ok := cm.Data["ratls-mesh.json"]; !ok {
		t.Errorf("measurements ConfigMap missing the ratls-mesh.json key; keys=%v", maps.Keys(cm.Data))
	}
}
