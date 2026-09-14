package workloadclaims

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestMountEvidenceAffectsContainerKey(t *testing.T) {
	base := SandboxContainer{Digest: "sha256:" + strings.Repeat("a", 64), Argv: []string{"/app"}}
	observedEmpty := base
	observedEmpty.MountsObserved = true
	if base.Key() == observedEmpty.Key() {
		t.Fatal("missing mount evidence collapsed into observed empty")
	}
	withMount := observedEmpty
	withMount.Mounts = []allowlist.ObservedMount{{Destination: "/config", Class: allowlist.MountData, Storage: allowlist.MountMemory}}
	if observedEmpty.Key() == withMount.Key() {
		t.Fatal("a mount was erased from the inventory key")
	}
	onDisk := withMount
	onDisk.Mounts = []allowlist.ObservedMount{{Destination: "/config", Class: allowlist.MountData, Storage: allowlist.MountUnknown}}
	if withMount.Key() == onDisk.Key() {
		t.Fatal("mount storage was erased from the inventory key")
	}
}

func TestMountSourceStaysNodeLocal(t *testing.T) {
	c := SandboxContainer{MountsObserved: true, Mounts: []allowlist.ObservedMount{{Destination: "/config", Source: "/var/lib/kubelet/pods/private", Class: allowlist.MountData, Storage: allowlist.MountMemory}}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "/var/lib/kubelet") {
		t.Fatalf("node source escaped in inventory: %s", b)
	}
}
