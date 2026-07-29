package nriimagepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// sandboxDigestsFor walks the production path CDS drives: bind the caller by
// kernel credentials to its sandbox, then list what that sandbox runs.
func sandboxDigestsFor(b *admissionInventory, pid int) ([]string, error) {
	id, err := b.SandboxForPeer(workloadclaims.PeerForPID(pid))
	if err != nil {
		return nil, err
	}
	digests, known, err := b.DigestsForSandbox(id)
	if err != nil {
		return nil, err
	}
	if !known {
		return nil, fmt.Errorf("sandbox %s unknown", id)
	}
	return digests, nil
}

const (
	digestApp   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestApp2  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	digestOther = "sha256:3333333333333333333333333333333333333333333333333333333333333333"

	// CRI container IDs are 64-hex (what the cgroup path carries).
	cidGetCert = "1111111111111111111111111111111111111111111111111111111111111111"
	cidApp1    = "aaaa111111111111111111111111111111111111111111111111111111111111"
	cidApp2    = "bbbb222222222222222222222222222222222222222222222222222222222222"
	cidOther   = "cccc333333333333333333333333333333333333333333333333333333333333"
)

// writeCgroup creates <procRoot>/<pid>/cgroup naming containerID.
func writeCgroup(t *testing.T, procRoot string, pid int, containerID string) {
	t.Helper()
	dir := filepath.Join(procRoot, itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "0::/kubepods.slice/.../cri-containerd-" + containerID + ".scope\n"
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// A get-cert caller in pod P resolves to P's sandbox, whose inventory is P's
// containers — the injected sidecar included, and never another pod's.
func TestInventoryResolvesPodAndIsolatesOtherPods(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)

	const (
		pod1 = "sandbox-1"
		pod2 = "sandbox-2"
	)
	// pod1: get-cert sidecar + two app containers.
	b.record(cidGetCert, pod1, "c8s-cert", digestOther)
	b.record(cidApp1, pod1, "app", digestApp)
	b.record(cidApp2, pod1, "worker", digestApp2)
	// pod2: a different app; must never appear in pod1's answer.
	b.record(cidOther, pod2, "app", digestOther)

	// The caller is the get-cert process in pod1.
	writeCgroup(t, procRoot, 4242, cidGetCert)

	got, err := sandboxDigestsFor(b, 4242)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{digestOther, digestApp, digestApp2}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("digests = %v, want %v (pod1's containers incl. sidecar, no pod2)", got, want)
	}
}

func TestInventoryRejectsUntrackedAndZeroPID(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)
	b.record(cidApp1, "sandbox-1", "app", digestApp)

	if _, err := sandboxDigestsFor(b, 0); err == nil {
		t.Fatal("peer pid 0 accepted (node-CVM must bind the caller)")
	}
	writeCgroup(t, procRoot, 55, cidOther)
	if _, err := sandboxDigestsFor(b, 55); err == nil {
		t.Fatal("untracked caller container accepted")
	}
}

// The nesting attack (review finding #1): a caller in pod2 creates a child
// cgroup named with pod1's app container ID. The inventory must resolve the
// shallowest tracked container (pod2's own get-cert), NOT the nested pod1 ID,
// so it returns pod2's digests — never pod1's.
func TestInventoryRejectsNestedVictimCgroup(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)

	const pod1, pod2 = "sandbox-1", "sandbox-2"
	b.record(cidApp1, pod1, "app", digestApp) // victim's app in pod1
	b.record(cidGetCert, pod2, "c8s-cert", digestOther)
	b.record(cidApp2, pod2, "app", digestApp2) // attacker's own app in pod2

	// Attacker's process: its real scope is cidGetCert (pod2), with a nested
	// child cgroup named cidApp1 (pod1's container).
	dir := filepath.Join(procRoot, "999")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "0::/kubepods/.../cri-containerd-" + cidGetCert + ".scope/" + cidApp1 + "\n"
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := sandboxDigestsFor(b, 999)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(got, digestApp) {
		t.Fatalf("nested victim cgroup leaked pod1's digest: %v", got)
	}
	if !slices.Contains(got, digestApp2) {
		t.Fatalf("attacker's own pod2 digests missing: %v", got)
	}
}

// An unresolved digest must fail the whole answer: serving the siblings that
// did resolve would pass a subset off as the sandbox's whole image set.
func TestInventoryRefusesUnresolvedDigest(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)

	const pod1 = "sandbox-1"
	b.record(cidGetCert, pod1, "c8s-cert", digestOther)
	b.record(cidApp1, pod1, "app", digestApp)
	b.record(cidApp2, pod1, "worker", "") // resolve failed at admission
	writeCgroup(t, procRoot, 4242, cidGetCert)

	if _, err := sandboxDigestsFor(b, 4242); err == nil {
		t.Fatal("served a subset of the sandbox's images as if it were the whole set")
	}
}

func TestInventoryEvicts(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)
	b.record(cidGetCert, "sandbox-1", "c8s-cert", digestOther)
	b.record(cidApp1, "sandbox-1", "app", digestApp)
	writeCgroup(t, procRoot, 77, cidGetCert)

	b.remove(cidApp1)
	got, err := sandboxDigestsFor(b, 77)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{digestOther}) {
		t.Fatalf("digests = %v, want only the surviving sidecar", got)
	}
}

// SandboxForPeer binds the caller by kernel PID → cgroup → tracked container
// → its sandbox. An untracked caller fails.
func TestInventorySandboxForPeer(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)
	b.record(cidGetCert, "sandbox-1", "c8s-cert", digestOther)
	writeCgroup(t, procRoot, 4242, cidGetCert)

	got, err := b.SandboxForPeer(workloadclaims.PeerForPID(4242))
	if err != nil {
		t.Fatal(err)
	}
	if got != "sandbox-1" {
		t.Fatalf("sandbox = %q, want sandbox-1", got)
	}

	writeCgroup(t, procRoot, 55, cidOther)
	if _, err := b.SandboxForPeer(workloadclaims.PeerForPID(55)); err == nil {
		t.Fatal("untracked caller resolved to a sandbox")
	}
	if _, err := b.SandboxForPeer(workloadclaims.PeerForPID(0)); err == nil {
		t.Fatal("peer pid 0 accepted")
	}
}

func TestInventoryDigestsForSandbox(t *testing.T) {
	b := newAdmissionInventory(t.TempDir())

	if _, known, err := b.DigestsForSandbox("nope"); err != nil || known {
		t.Fatalf("unknown sandbox: known=%v err=%v, want known=false", known, err)
	}

	// A known sandbox with no containers answers an empty inventory.
	b.recordSandbox("sandbox-empty")
	got, known, err := b.DigestsForSandbox("sandbox-empty")
	if err != nil || !known {
		t.Fatalf("empty sandbox: known=%v err=%v", known, err)
	}
	if len(got) != 0 {
		t.Fatalf("digests = %v, want none", got)
	}

	// The inventory includes injected containers, deduplicates, and sorts.
	b.record(cidGetCert, "sandbox-1", "c8s-cert", digestOther)
	b.record(cidApp1, "sandbox-1", "app", digestApp)
	b.record(cidApp2, "sandbox-1", "worker", digestApp)
	b.record(cidOther, "sandbox-2", "app", digestApp2)
	got, known, err = b.DigestsForSandbox("sandbox-1")
	if err != nil || !known {
		t.Fatalf("known=%v err=%v", known, err)
	}
	if want := []string{digestOther, digestApp}; !slices.Equal(got, slicesSorted(want)) {
		t.Fatalf("digests = %v, want %v (sorted, deduped, sidecar included, no sandbox-2)", got, slicesSorted(want))
	}
}

func slicesSorted(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// An unresolved digest fails the whole inventory rather than serve a subset:
// the inventory covers every running container, injected ones included.
func TestInventoryDigestsForSandboxRefusesUnresolved(t *testing.T) {
	b := newAdmissionInventory(t.TempDir())
	b.record(cidGetCert, "sandbox-1", "c8s-cert", "")
	b.record(cidApp1, "sandbox-1", "app", digestApp)

	if _, _, err := b.DigestsForSandbox("sandbox-1"); err == nil {
		t.Fatal("served a subset of the sandbox inventory")
	}
}

// removeSandbox evicts the sandbox and its containers; recording a container
// alone (no pod event) still makes its sandbox known.
func TestInventorySandboxLifecycle(t *testing.T) {
	b := newAdmissionInventory(t.TempDir())

	b.record(cidApp1, "sandbox-1", "app", digestApp)
	if _, known, _ := b.DigestsForSandbox("sandbox-1"); !known {
		t.Fatal("recorded container did not imply its sandbox")
	}

	b.record(cidOther, "sandbox-2", "app", digestApp2)
	b.removeSandbox("sandbox-1")
	if _, known, _ := b.DigestsForSandbox("sandbox-1"); known {
		t.Fatal("removed sandbox still known")
	}
	got, known, err := b.DigestsForSandbox("sandbox-2")
	if err != nil || !known || !slices.Equal(got, []string{digestApp2}) {
		t.Fatalf("sandbox-2 after removing sandbox-1: %v %v %v", got, known, err)
	}
	// sandbox-1's containers went with it.
	if len(b.containers) != 1 {
		t.Fatalf("containers = %v, want only sandbox-2's", b.containers)
	}
}
