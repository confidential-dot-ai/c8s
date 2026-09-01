package nriimagepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
	"github.com/containerd/nri/pkg/api"
)

// sandboxDigestsFor walks the production path CDS drives: bind the caller by
// kernel credentials to its sandbox, then list what that sandbox runs.
func sandboxDigestsFor(b *admissionInventory, pid int) ([]string, error) {
	id, err := b.SandboxForPeer(workloadclaims.PeerForPID(pid))
	if err != nil {
		return nil, err
	}
	digests, _, known, err := b.DigestsForSandbox(id)
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
	b.record(cidGetCert, pod1, "c8s-cert", digestOther, nil)
	b.record(cidApp1, pod1, "app", digestApp, nil)
	b.record(cidApp2, pod1, "worker", digestApp2, nil)
	// pod2: a different app; must never appear in pod1's answer.
	b.record(cidOther, pod2, "app", digestOther, nil)

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
	b.record(cidApp1, "sandbox-1", "app", digestApp, nil)

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
	b.record(cidApp1, pod1, "app", digestApp, nil) // victim's app in pod1
	b.record(cidGetCert, pod2, "c8s-cert", digestOther, nil)
	b.record(cidApp2, pod2, "app", digestApp2, nil) // attacker's own app in pod2

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
	b.record(cidGetCert, pod1, "c8s-cert", digestOther, nil)
	b.record(cidApp1, pod1, "app", digestApp, nil)
	b.record(cidApp2, pod1, "worker", "", nil) // resolve failed at admission
	writeCgroup(t, procRoot, 4242, cidGetCert)

	if _, err := sandboxDigestsFor(b, 4242); err == nil {
		t.Fatal("served a subset of the sandbox's images as if it were the whole set")
	}
}

// A removed container leaves caller resolution but stays in the sandbox's
// admission record. Dropping it would let a pod hide a container by arranging
// for it to be absent when asked — kubelet removes and recreates a container
// across a CrashLoopBackOff, so that window is free (docs/secrets.md).
func TestInventoryRemoveKeepsAdmissionRecord(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)
	b.record(cidGetCert, "sandbox-1", "c8s-cert", digestOther, nil)
	b.record(cidApp1, "sandbox-1", "app", digestApp, nil)
	writeCgroup(t, procRoot, 77, cidGetCert)

	b.remove(cidApp1)
	got, err := sandboxDigestsFor(b, 77)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, slicesSorted([]string{digestOther, digestApp})) {
		t.Fatalf("digests = %v, want the removed container still recorded", got)
	}

	// It is gone for caller resolution, though: a stopped container must not
	// bind a caller.
	writeCgroup(t, procRoot, 78, cidApp1)
	if _, err := sandboxDigestsFor(b, 78); err == nil {
		t.Fatal("a removed container still resolved a caller")
	}

	// Tearing the sandbox down does clear it.
	b.removeSandbox("sandbox-1")
	if _, _, known, _ := b.DigestsForSandbox("sandbox-1"); known {
		t.Fatal("removed sandbox still known")
	}
}

// SandboxForPeer binds the caller by kernel PID → cgroup → tracked container
// → its sandbox. An untracked caller fails.
func TestInventorySandboxForPeer(t *testing.T) {
	procRoot := t.TempDir()
	b := newAdmissionInventory(procRoot)
	b.record(cidGetCert, "sandbox-1", "c8s-cert", digestOther, nil)
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

	if _, _, known, err := b.DigestsForSandbox("nope"); err != nil || known {
		t.Fatalf("unknown sandbox: known=%v err=%v, want known=false", known, err)
	}

	// A known sandbox with no containers answers an empty inventory.
	b.recordSandbox("sandbox-empty")
	got, _, known, err := b.DigestsForSandbox("sandbox-empty")
	if err != nil || !known {
		t.Fatalf("empty sandbox: known=%v err=%v", known, err)
	}
	if len(got) != 0 {
		t.Fatalf("digests = %v, want none", got)
	}

	// The inventory includes injected containers, deduplicates, and sorts.
	b.record(cidGetCert, "sandbox-1", "c8s-cert", digestOther, nil)
	b.record(cidApp1, "sandbox-1", "app", digestApp, nil)
	b.record(cidApp2, "sandbox-1", "worker", digestApp, nil)
	b.record(cidOther, "sandbox-2", "app", digestApp2, nil)
	got, _, known, err = b.DigestsForSandbox("sandbox-1")
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
	b.record(cidGetCert, "sandbox-1", "c8s-cert", "", nil)
	b.record(cidApp1, "sandbox-1", "app", digestApp, nil)

	if _, _, _, err := b.DigestsForSandbox("sandbox-1"); err == nil {
		t.Fatal("served a subset of the sandbox inventory")
	}
}

// removeSandbox evicts the sandbox and its containers; recording a container
// alone (no pod event) still makes its sandbox known.
func TestInventorySandboxLifecycle(t *testing.T) {
	b := newAdmissionInventory(t.TempDir())

	b.record(cidApp1, "sandbox-1", "app", digestApp, nil)
	if _, _, known, _ := b.DigestsForSandbox("sandbox-1"); !known {
		t.Fatal("recorded container did not imply its sandbox")
	}

	b.record(cidOther, "sandbox-2", "app", digestApp2, nil)
	b.removeSandbox("sandbox-1")
	if _, _, known, _ := b.DigestsForSandbox("sandbox-1"); known {
		t.Fatal("removed sandbox still known")
	}
	got, _, known, err := b.DigestsForSandbox("sandbox-2")
	if err != nil || !known || !slices.Equal(got, []string{digestApp2}) {
		t.Fatalf("sandbox-2 after removing sandbox-1: %v %v %v", got, known, err)
	}
	// sandbox-1's containers went with it.
	if len(b.containers) != 1 {
		t.Fatalf("containers = %v, want only sandbox-2's", b.containers)
	}
}

// Two admissions whose argv differ only in how a separator byte falls must both
// survive in the high-water mark. Under a separator argv can carry, the second
// record overwrote the first — and it vanished from the digests view too, so
// CDS's cross-check between the two views still agreed and the sandbox stayed
// eligible to be named for a workload it had not run.
func TestInventoryArgvSeparatorDoesNotEraseAdmissions(t *testing.T) {
	b := newAdmissionInventory(t.TempDir())
	const sandbox = "sandbox-1"

	b.record(cidApp1, sandbox, "app", digestApp, []string{"/app\x1f--serve"})
	b.record(cidApp2, sandbox, "app", digestApp, []string{"/app", "--serve"})

	_, containers, known, err := b.DigestsForSandbox(sandbox)
	if err != nil || !known {
		t.Fatalf("known=%v err=%v", known, err)
	}
	if len(containers) != 2 {
		t.Fatalf("containers = %+v, want both admissions recorded", containers)
	}
	for _, want := range [][]string{{"/app\x1f--serve"}, {"/app", "--serve"}} {
		if !slices.ContainsFunc(containers, func(c workloadclaims.SandboxContainer) bool {
			return slices.Equal(c.Argv, want)
		}) {
			t.Fatalf("argv %q was erased from the high-water mark: %+v", want, containers)
		}
	}
}

func TestInventoryPreservesObservedMountAndEnvPolicyWithoutValues(t *testing.T) {
	b := newAdmissionInventory(t.TempDir())
	obs := containerObservation{bindMounts: []string{"/config"}, envNames: []string{"PATH", "TOKEN"}}
	b.record(cidApp1, "sandbox-1", "app", digestApp, []string{"/app"}, obs)

	_, containers, known, err := b.DigestsForSandbox("sandbox-1")
	if err != nil || !known || len(containers) != 1 {
		t.Fatalf("inventory: known=%v containers=%v err=%v", known, containers, err)
	}
	got := containers[0]
	if !got.MountsObserved || !got.EnvObserved {
		t.Fatal("inventory dropped observation state")
	}
	if !slices.Equal(got.BindMounts, []string{"/config"}) || !slices.Equal(got.EnvNames, []string{"PATH", "TOKEN"}) {
		t.Fatalf("inventory runtime policy = mounts %v env %v", got.BindMounts, got.EnvNames)
	}
}

func TestRuntimeInventoryIsLiveOnlyAndBindsPolicyAndPodIdentity(t *testing.T) {
	policy := newPolicyStore(floorAllowlist(map[string]string{digestApp: "bootstrap"}))
	steady := floorAllowlist(map[string]string{digestApp2: "steady"})
	if !policy.apply(steady, 9) {
		t.Fatal("apply steady policy")
	}
	b := newAdmissionInventory(t.TempDir(), policy)
	b.recordPod(&api.PodSandbox{Id: "sandbox-1", Name: "worker-0", Namespace: "inference", Uid: "pod-uid"})
	b.record(cidApp1, "sandbox-1", "worker", digestApp2, []string{"/worker", "--serve"}, containerObservation{
		bindMounts: []string{"/models"}, envNames: []string{"PATH"},
	})

	got, err := b.RuntimeInventory()
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != workloadclaims.RuntimeInventorySchema || got.PolicyVersion != 9 || got.PolicySHA256 != allowlistDigest(steady) {
		t.Fatalf("policy identity = schema %q version %d digest %q", got.Schema, got.PolicyVersion, got.PolicySHA256)
	}
	if len(got.Containers) != 1 {
		t.Fatalf("containers = %+v", got.Containers)
	}
	c := got.Containers[0]
	if c.Namespace != "inference" || c.PodName != "worker-0" || c.PodUID != "pod-uid" || c.ContainerName != "worker" || c.ContainerID != cidApp1 {
		t.Fatalf("runtime identity = %+v", c)
	}
	if !c.MountsObserved || !c.EnvObserved || !slices.Equal(c.BindMounts, []string{"/models"}) || !slices.Equal(c.EnvNames, []string{"PATH"}) {
		t.Fatalf("runtime observations = %+v", c)
	}
	beforeRemove := got.Generation
	b.remove(cidApp1)
	got, err = b.RuntimeInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Containers) != 0 || got.Generation <= beforeRemove {
		t.Fatalf("stopped container remained in live inventory: %+v", got)
	}
	if _, highWater, known, err := b.DigestsForSandbox("sandbox-1"); err != nil || !known || len(highWater) != 1 {
		t.Fatalf("secret-release high-water mark was lost: known=%v err=%v containers=%+v", known, err, highWater)
	}
}

func TestEveryNodeInventoryReportsExactCDSCanonicalPolicyDigestAfterTransition(t *testing.T) {
	active, err := allowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"c8s-system":{"containers":[{"digest":"` + digestApp2 + `","command":{"policy":"exact","argv":["/system"]},"args":{"policy":"deny"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	canonicalDigest := allowlistDigest(active)
	if canonicalDigest == "" {
		t.Fatal("empty canonical digest")
	}

	for _, node := range []string{"node-a", "node-b", "node-c"} {
		t.Run(node, func(t *testing.T) {
			store := newPolicyStore(floorAllowlist(map[string]string{digestApp: "local-cold-boot-only"}))
			inventory := newAdmissionInventory(t.TempDir(), store)
			store.setTransitionGuard(inventory.admitsLiveRuntime)
			inventory.recordPod(&api.PodSandbox{Id: "system-sandbox", Name: "c8s-system", Namespace: "c8s-system", Uid: node + "-uid"})
			inventory.record("system-container", "system-sandbox", "c8s", digestApp2, []string{"/system"})
			if applied, err := store.applyChecked(active, 17); err != nil || !applied {
				t.Fatalf("apply active policy: applied=%v err=%v", applied, err)
			}
			got, err := inventory.RuntimeInventory()
			if err != nil {
				t.Fatal(err)
			}
			if got.PolicyVersion != 17 || got.PolicySHA256 != canonicalDigest {
				t.Fatalf("node policy identity = version %d digest %q, want 17 / %q", got.PolicyVersion, got.PolicySHA256, canonicalDigest)
			}
			if store.current().index.AdmitsDigest(digestApp) {
				t.Fatal("local cold-boot floor survived the authenticated transition")
			}
		})
	}
}

func TestRuntimeInventoryCannotExposeNewRoleWithOldPolicyIdentity(t *testing.T) {
	store := newPolicyStore(floorAllowlist(map[string]string{digestApp: "floor"}))
	inventory := newAdmissionInventory(t.TempDir(), store)
	inventory.recordPod(&api.PodSandbox{Id: "sandbox", Name: "system", Namespace: "c8s-system", Uid: "uid"})
	inventory.record("container", "sandbox", "system", digestApp, []string{"/system"}, containerObservation{})
	active, err := allowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"system":{"containers":[
		{"name":"system","digest":"` + digestApp + `","command":{"policy":"exact","argv":["/system"]},"args":{"policy":"deny"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	rolesChanged := make(chan struct{})
	release := make(chan struct{})
	store.setTransitionGuard(func(policy *allowlist.Allowlist, index *allowlist.Index) error {
		if err := inventory.admitsLiveRuntime(policy, index); err != nil {
			return err
		}
		close(rolesChanged)
		<-release
		return nil
	})
	applyDone := make(chan error, 1)
	go func() {
		_, err := store.applyChecked(active, 5)
		applyDone <- err
	}()
	<-rolesChanged
	readDone := make(chan workloadclaims.RuntimeInventory, 1)
	go func() {
		got, _ := inventory.RuntimeInventory()
		readDone <- got
	}()
	select {
	case got := <-readDone:
		t.Fatalf("inventory crossed an in-progress policy activation: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-applyDone; err != nil {
		t.Fatal(err)
	}
	got := <-readDone
	if got.PolicyVersion != 5 || got.PolicySHA256 != allowlistDigest(active) || len(got.Containers) != 1 || got.Containers[0].ContainerRole != allowlist.ContainerRoleMain {
		t.Fatalf("inventory policy/role snapshot = %+v", got)
	}
}

func TestRuntimeInventoryFailsClosedOnUnresolvedLiveDigest(t *testing.T) {
	b := newAdmissionInventory(t.TempDir())
	b.record(cidApp1, "sandbox-1", "worker", "", []string{"/worker"})
	if _, err := b.RuntimeInventory(); err == nil {
		t.Fatal("runtime inventory served a subset while a live digest was unresolved")
	}
}

func TestNodeInventoryMarksStoppedMainWithoutLosingHistory(t *testing.T) {
	b := newAdmissionInventory(t.TempDir())
	b.record("ctr", "sandbox", "app", digestApp, []string{"/app"}, containerObservation{role: allowlist.ContainerRoleMain})
	b.remove("ctr")
	_, containers, known, err := b.DigestsForSandbox("sandbox")
	if err != nil || !known || len(containers) != 1 || !containers[0].Stopped {
		t.Fatalf("stopped high-water record = known %v err %v containers %+v", known, err, containers)
	}
	w := allowlist.Workload{Containers: []allowlist.Container{{
		Name: "app", Digest: mustDigest(t, digestApp),
		Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/app"}},
		Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyDeny},
	}}}
	if w.Diff([]allowlist.RunningContainer{{
		Name: containers[0].Name, Role: containers[0].Role, Stopped: containers[0].Stopped,
		Digest: containers[0].Digest, Argv: containers[0].Argv,
	}}).Describes() {
		t.Fatal("stopped node main satisfied a complete-set match")
	}
}

func TestPolicyTransitionRequiresCoverageOfLiveRuntime(t *testing.T) {
	store := newPolicyStore(floorAllowlist(map[string]string{pushDigestA: "bootstrap"}))
	inventory := newAdmissionInventory("/proc", store)
	store.setTransitionGuard(inventory.admitsLiveRuntime)
	inventory.record("ctr", "sandbox", "system", pushDigestA, []string{"/c8s", "serve"}, containerObservation{
		bindMounts:     []string{"/run/state"},
		bindMountKinds: map[string]string{"/run/state": "empty-dir"},
		envNames:       []string{"PATH"},
	})

	before := store.current()
	uncovered := floorAllowlist(map[string]string{pushDigestB: "application"})
	if applied, err := store.applyChecked(uncovered, 1); err == nil || applied {
		t.Fatalf("uncovered live runtime applied=%v err=%v", applied, err)
	}
	if store.current() != before {
		t.Fatal("a rejected policy changed the active snapshot")
	}

	digestOnly := floorAllowlist(map[string]string{pushDigestA: "system-bytes-only"})
	if applied, err := store.applyChecked(digestOnly, 1); err == nil || applied {
		t.Fatalf("digest-only policy crossed the bootstrap barrier: applied=%v err=%v", applied, err)
	}
	if store.current() != before {
		t.Fatal("a digest-only policy changed the active snapshot")
	}

	covered := &allowlist.Allowlist{
		Schema: allowlist.Schema,
		Workloads: map[string]allowlist.Workload{
			"c8s-system": {
				Containers: []allowlist.Container{{
					Digest:  mustDigest(t, pushDigestA),
					Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/c8s"}},
					Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"serve"}},
					Mounts: allowlist.MountPolicy{Policy: allowlist.PolicyExact, Destinations: []string{"/run/state"},
						Kinds: map[string]string{"/run/state": "empty-dir"}},
					Env: allowlist.EnvPolicy{Policy: allowlist.PolicyExact, Names: []string{"PATH"}},
				}},
			},
		},
	}
	if applied, err := store.applyChecked(covered, 1); err != nil || !applied {
		t.Fatalf("covered live runtime applied=%v err=%v", applied, err)
	}
	if store.current() == before {
		t.Fatal("covered policy did not replace the bootstrap snapshot")
	}
}

// A container recorded without a digest closes its sandbox's answer; a later
// record that resolves that same container reopens it.
func TestInventory_UnresolvedClearsWhenTheContainerResolves(t *testing.T) {
	inv := newAdmissionInventory(t.TempDir())
	inv.record("ctr-1", "sbx-1", "app", "", nil)
	inv.record("ctr-2", "sbx-1", "side", pushDigestA, nil)

	if _, _, _, err := inv.DigestsForSandbox("sbx-1"); err == nil {
		t.Fatal("an unresolved container must fail the whole answer")
	}

	inv.record("ctr-3", "sbx-1", "other", "", nil)
	inv.record("ctr-1", "sbx-1", "app", pushDigestB, nil)
	if _, _, _, err := inv.DigestsForSandbox("sbx-1"); err == nil {
		t.Fatal("a second unresolved container must keep the answer closed")
	}

	inv.record("ctr-3", "sbx-1", "other", pushDigestC, nil)
	digests, _, _, err := inv.DigestsForSandbox("sbx-1")
	if err != nil {
		t.Fatalf("resolving every container must reopen the answer: %v", err)
	}
	for _, want := range []string{pushDigestA, pushDigestB, pushDigestC} {
		if !slices.Contains(digests, want) {
			t.Fatalf("digests %v missing %s", digests, want)
		}
	}
}

// unresolved is keyed on the runtime-assigned container ID: two containers in a
// sandbox can share a name, and one resolving must not clear the other.
func TestInventory_UnresolvedIsKeyedOnContainerID(t *testing.T) {
	inv := newAdmissionInventory(t.TempDir())
	inv.record("ctr-1", "sbx-1", "app", "", nil)
	inv.record("ctr-2", "sbx-1", "app", pushDigestA, nil)

	if _, _, _, err := inv.DigestsForSandbox("sbx-1"); err == nil {
		t.Fatal("a namesake container cleared another container's unresolved marker")
	}

	inv.record("ctr-1", "sbx-1", "app", pushDigestB, nil)
	if _, _, _, err := inv.DigestsForSandbox("sbx-1"); err != nil {
		t.Fatalf("resolving the container itself must reopen the answer: %v", err)
	}
}
