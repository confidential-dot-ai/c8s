//go:build linux

package policymonitor

import (
	"slices"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	pmDigestApp     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pmDigestSidecar = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	pmSandboxID     = "8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f"
)

// The workload claim excludes injected sidecars at query time (they are
// recorded, matching the node-CVM inventory), while the sandbox inventory
// includes them.
func TestKataInventoryClaimExcludesInjectedInventoryIncludes(t *testing.T) {
	b := newAdmissionInventory()
	b.recordSandboxID(pmSandboxID)
	b.record("cid-app", "app", pmDigestApp)
	b.record("cid-cert", "c8s-cert", pmDigestSidecar)

	containers, err := b.ContainersForPeer(workloadclaims.PeerForPID(0))
	if err != nil {
		t.Fatal(err)
	}
	if len(containers) != 1 || containers[0].Digest != pmDigestApp {
		t.Fatalf("claim containers = %v, want only the app", containers)
	}

	digests, known, err := b.DigestsForSandbox(pmSandboxID)
	if err != nil || !known {
		t.Fatalf("known=%v err=%v", known, err)
	}
	want := []string{pmDigestSidecar, pmDigestApp}
	slices.Sort(want)
	if !slices.Equal(digests, want) {
		t.Fatalf("inventory = %v, want %v (sidecar included)", digests, want)
	}
}

// The guest holds one pod: only its own sandbox ID is known, the first
// observed ID wins, and a token request before any container is observed
// fails closed.
func TestKataInventorySandboxIdentity(t *testing.T) {
	b := newAdmissionInventory()

	if _, err := b.SandboxForPeer(workloadclaims.PeerForPID(0)); err == nil {
		t.Fatal("sandbox resolved before any container was observed")
	}
	if _, known, _ := b.DigestsForSandbox(pmSandboxID); known {
		t.Fatal("sandbox known before any container was observed")
	}

	b.recordSandboxID(pmSandboxID)
	b.recordSandboxID("some-other-id") // can't happen in a one-pod guest; first wins
	got, err := b.SandboxForPeer(workloadclaims.PeerForPID(0))
	if err != nil || got != pmSandboxID {
		t.Fatalf("sandbox = %q, %v; want %q", got, err, pmSandboxID)
	}
	if _, known, _ := b.DigestsForSandbox("some-other-id"); known {
		t.Fatal("foreign sandbox ID answered")
	}
	if digests, known, err := b.DigestsForSandbox(pmSandboxID); err != nil || !known || len(digests) != 0 {
		t.Fatalf("own sandbox: digests=%v known=%v err=%v, want empty inventory", digests, known, err)
	}
}

func TestSandboxIDFromAnnotations(t *testing.T) {
	if got := sandboxIDFromAnnotations(map[string]string{"io.kubernetes.cri.sandbox-id": pmSandboxID}); got != pmSandboxID {
		t.Fatalf("containerd key: got %q", got)
	}
	if got := sandboxIDFromAnnotations(map[string]string{"io.kubernetes.cri-o.SandboxID": pmSandboxID}); got != pmSandboxID {
		t.Fatalf("cri-o key: got %q", got)
	}
	if got := sandboxIDFromAnnotations(map[string]string{}); got != "" {
		t.Fatalf("no key: got %q", got)
	}
}
