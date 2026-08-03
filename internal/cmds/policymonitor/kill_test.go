//go:build linux

package policymonitor

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeKiller records every cgroup termination and lets the test assert on it. The
// mutex makes it safe to share between the inotify dispatch goroutine
// and the test's polling loop in monitor_test.go.
type fakeKiller struct {
	mu           sync.Mutex
	calls        []string
	ok           bool
	err          error
	selfTestErr  error
	selfTestSeen bool
}

func (k *fakeKiller) kill(containerID string) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, containerID)
	return k.ok, k.err
}

func (k *fakeKiller) selfTest() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.selfTestSeen = true
	return k.selfTestErr
}

// snapshot returns a copy of the recorded calls so tests can assert
// without holding the lock.
func (k *fakeKiller) snapshot() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]string, len(k.calls))
	copy(out, k.calls)
	return out
}

func TestFindCgroupDir_FoundAtRoot(t *testing.T) {
	root := t.TempDir()
	cid := "abc123"
	if err := os.MkdirAll(filepath.Join(root, cid), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := findCgroupDir(root, cid)
	if err != nil {
		t.Fatalf("findCgroupDir: %v", err)
	}
	if got == "" {
		t.Fatal("expected non-empty path")
	}
	if filepath.Base(got) != cid {
		t.Errorf("basename = %q, want %q", filepath.Base(got), cid)
	}
}

func TestFindCgroupDir_NestedUnderSlice(t *testing.T) {
	root := t.TempDir()
	cid := "deadbeef"
	nested := filepath.Join(root, "system.slice", "kata-shim-foo.scope", cid)
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := findCgroupDir(root, cid)
	if err != nil {
		t.Fatalf("findCgroupDir: %v", err)
	}
	if got != nested {
		t.Errorf("got %q, want %q", got, nested)
	}
}

// TestFindCgroupDir_SystemdScope covers the real-world layout a systemd-PID-1
// kata guest produces: the container's cgroup is a systemd scope
// (cri-containerd-<cid>.scope) nested under the pod's kubepods*.slice, not a
// bare <cid> directory. Matching only the bare basename was a silent
// enforcement hole — a denied container's SIGKILL never landed.
func TestFindCgroupDir_SystemdScope(t *testing.T) {
	root := t.TempDir()
	cid := "b790433fdb4f223a51940bae06c1cd54d73377fc3ea45c4fa5c7ea3bd4b6c829"
	scope := filepath.Join(root, "kubepods.slice", "kubepods-besteffort.slice",
		"kubepods-besteffort-podabc.slice", "cri-containerd-"+cid+".scope")
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := findCgroupDir(root, cid)
	if err != nil {
		t.Fatalf("findCgroupDir: %v", err)
	}
	if got != scope {
		t.Errorf("got %q, want %q", got, scope)
	}
}

func TestCgroupDirMatchesCID(t *testing.T) {
	cid := "b790433fdb4f223a51940bae06c1cd54d73377fc3ea45c4fa5c7ea3bd4b6c829"
	for _, tc := range []struct {
		name string
		want bool
	}{
		{cid, true},            // flat fs driver
		{cid + ".scope", true}, // bare systemd scope
		{"cri-containerd-" + cid + ".scope", true},  // containerd systemd driver
		{"crio-" + cid + ".scope", true},            // CRI-O systemd driver
		{"kubepods-besteffort-podabc.slice", false}, // a pod slice, not the container
		{"other-" + cid[:20], false},                // partial id must not match
		{"deadbeef", false},
		{"", false},
		// An arbitrary vendor prefix must NOT match: the old suffix rule
		// (HasSuffix(name, "-"+cid)) accepted these, letting an unrelated cgroup
		// redirect the kill (H-02).
		{"evil-" + cid + ".scope", false},
		{"foo-" + cid, false},
	} {
		if got := cgroupDirMatchesCID(tc.name, cid); got != tc.want {
			t.Errorf("cgroupDirMatchesCID(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFindCgroupDir_AmbiguousMatchRejected(t *testing.T) {
	// A running container owns exactly one cgroup, so two matches mean the id
	// collides with an unrelated cgroup. findCgroupDir must refuse rather than
	// SIGKILL whichever it hits first (H-02).
	root := t.TempDir()
	cid := "b790433fdb4f223a51940bae06c1cd54d73377fc3ea45c4fa5c7ea3bd4b6c829"
	flat := filepath.Join(root, cid)
	scope := filepath.Join(root, "system.slice", "cri-containerd-"+cid+".scope")
	for _, d := range []string{flat, scope} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got, err := findCgroupDir(root, cid)
	if err == nil {
		t.Fatalf("findCgroupDir returned %q with nil error; want an ambiguity error", got)
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("error = %v, want it to mention ambiguity", err)
	}
}

func TestFindCgroupDir_NotFound(t *testing.T) {
	root := t.TempDir()
	got, err := findCgroupDir(root, "missing")
	if err != nil {
		t.Fatalf("findCgroupDir: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestCgroupKiller_WaitsForCgroupToAppear(t *testing.T) {
	root := t.TempDir()
	cid := "feedface"
	killer := &cgroupKiller{
		cgroupRoot:   root,
		waitTimeout:  500 * time.Millisecond,
		pollInterval: 20 * time.Millisecond,
	}
	// Drop the cgroup in after a short delay; the killer should
	// re-scan and find it.
	go func() {
		time.Sleep(75 * time.Millisecond)
		dir := filepath.Join(root, cid)
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("4242\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "cgroup.kill"), nil, 0o644)
	}()
	ok, err := killer.kill(cid)
	if err != nil {
		t.Fatalf("kill: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
}

func TestCgroupKiller_WaitsForProcsToPopulateAndKillsGroup(t *testing.T) {
	root := t.TempDir()
	cid := "b790433fdb4f223a51940bae06c1cd54d73377fc3ea45c4fa5c7ea3bd4b6c829"
	scope := filepath.Join(root, "kubepods.slice", "cri-containerd-"+cid+".scope")
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	procs := filepath.Join(scope, "cgroup.procs")
	// cgroup exists but procs is empty — the init hasn't been forked in yet.
	if err := os.WriteFile(procs, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scope, "cgroup.kill"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	killer := &cgroupKiller{
		cgroupRoot:   root,
		waitTimeout:  1 * time.Second,
		pollInterval: 20 * time.Millisecond,
	}
	go func() {
		time.Sleep(75 * time.Millisecond)
		_ = os.WriteFile(procs, []byte("4242\n1234\n"), 0o644)
	}()
	ok, err := killer.kill(cid)
	if err != nil {
		t.Fatalf("kill: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true — killer must wait for cgroup.procs to populate")
	}
	contents, err := os.ReadFile(filepath.Join(scope, "cgroup.kill"))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "1" {
		t.Errorf("cgroup.kill = %q, want 1", contents)
	}
}

// TestCgroupKiller_EmptyProcsTimesOut confirms a cgroup that stays empty
// (a container that genuinely exited before we looked) times out to a
// harmless no-op rather than blocking or erroring.
func TestCgroupKiller_EmptyProcsTimesOut(t *testing.T) {
	root := t.TempDir()
	cid := "cafef00d"
	scope := filepath.Join(root, "cri-containerd-"+cid+".scope")
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scope, "cgroup.procs"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scope, "cgroup.kill"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	killer := &cgroupKiller{
		cgroupRoot:   root,
		waitTimeout:  60 * time.Millisecond,
		pollInterval: 20 * time.Millisecond,
	}
	ok, err := killer.kill(cid)
	if err != nil {
		t.Fatalf("kill: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false when cgroup.procs never populates")
	}
}

func TestCgroupKiller_Timeout(t *testing.T) {
	root := t.TempDir()
	killer := &cgroupKiller{
		cgroupRoot:   root,
		waitTimeout:  50 * time.Millisecond,
		pollInterval: 20 * time.Millisecond,
	}
	ok, err := killer.kill("never-appears")
	if err != nil {
		t.Fatalf("kill: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false")
	}
}

func TestCgroupKiller_PropagatesMalformedProcs(t *testing.T) {
	root := t.TempDir()
	cid := "malformed"
	dir := filepath.Join(root, cid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("not-a-pid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.kill"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	killer := &cgroupKiller{cgroupRoot: root, waitTimeout: time.Second, pollInterval: time.Millisecond}
	if ok, err := killer.kill(cid); err == nil || ok {
		t.Fatalf("kill = (%v, %v), want permanent parse error", ok, err)
	}
}

// testOwnCgroup is the guest-realistic own-cgroup path the self-test fixtures
// nest the probe under.
const testOwnCgroup = "/system.slice/policy-monitor.service"

// fakeProcSelfCgroup writes a /proc/self/cgroup stand-in naming own, so the
// self-test fixtures don't depend on where the test binary's cgroup happens
// to be.
func fakeProcSelfCgroup(t *testing.T, own string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(p, []byte("0::"+own+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// seedOwnCgroup creates the killer's own cgroup dir under root, the writable
// parent the probe is created in.
func seedOwnCgroup(t *testing.T, root, own string) string {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(own))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// seedProbeCgroup additionally materialises the probe's cgroup.kill, which on a
// real cgroup2 mount the kernel creates and on a tempdir nothing does.
func seedProbeCgroup(t *testing.T, root, own string) string {
	t.Helper()
	probe := filepath.Join(seedOwnCgroup(t, root, own), selfTestCgroup)
	if err := os.MkdirAll(probe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(probe, "cgroup.kill"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return probe
}

// writableCgroupRoot returns a cgroup root that a newCgroupKiller self-test
// accepts — seeded at this process's real own-cgroup path, since runMonitor
// builds its killer against the real /proc/self/cgroup.
func writableCgroupRoot(t *testing.T) string {
	t.Helper()
	own, err := ownCgroupPath(defaultProcSelfCgroup)
	if err != nil {
		t.Skipf("no cgroup v2 own-cgroup path: %v", err)
	}
	root := t.TempDir()
	seedProbeCgroup(t, root, own)
	return root
}

// newSelfTestKiller wires a killer at root with a fabricated own-cgroup path.
func newSelfTestKiller(t *testing.T, root string) *cgroupKiller {
	t.Helper()
	k := newCgroupKiller(root)
	k.procSelfCgroup = fakeProcSelfCgroup(t, testOwnCgroup)
	return k
}

func TestCgroupKiller_SelfTest_PassesAndExercisesTheKillPrimitive(t *testing.T) {
	root := t.TempDir()
	probe := seedProbeCgroup(t, root, testOwnCgroup)
	if err := newSelfTestKiller(t, root).selfTest(); err != nil {
		t.Fatalf("selfTest on a writable hierarchy: %v", err)
	}
	// The self-test must go through writeCgroupKill, not merely stat the file:
	// the field failure (ProtectControlGroups=yes) surfaces on open-for-write.
	contents, err := os.ReadFile(filepath.Join(probe, "cgroup.kill"))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "1" {
		t.Errorf("probe cgroup.kill = %q, want 1", contents)
	}
}

// A hierarchy with no cgroup.kill (pre-5.14 kernel) leaves the monitor no way
// to enforce, so the self-test must fail rather than pass silently.
func TestCgroupKiller_SelfTest_FailsWithoutKillInterface(t *testing.T) {
	root := t.TempDir()
	own := seedOwnCgroup(t, root, testOwnCgroup)
	if err := newSelfTestKiller(t, root).selfTest(); err == nil {
		t.Fatal("selfTest passed on a hierarchy with no cgroup.kill")
	}
	// And it must not litter the hierarchy with its probe cgroup.
	if _, err := os.Stat(filepath.Join(own, selfTestCgroup)); !os.IsNotExist(err) {
		t.Errorf("probe cgroup left behind: stat err = %v", err)
	}
}

// The field bug: /sys/fs/cgroup remounted read-only inside the unit's mount
// namespace, so nothing under it can be created or written.
func TestCgroupKiller_SelfTest_FailsOnReadOnlyHierarchy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory mode bits; the read-only case needs a real mount")
	}
	root := t.TempDir()
	own := seedOwnCgroup(t, root, testOwnCgroup)
	if err := os.Chmod(own, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(own, 0o755) })
	err := newSelfTestKiller(t, root).selfTest()
	if err == nil {
		t.Fatal("selfTest passed on a non-writable hierarchy")
	}
	if !strings.Contains(err.Error(), "create probe cgroup") {
		t.Errorf("error = %v, want it to name the probe-cgroup creation failure", err)
	}
}

// A cgroup root that isn't there at all (misconfigured --cgroup-root) is the
// same class of failure: no enforcement is possible.
func TestCgroupKiller_SelfTest_FailsOnMissingRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent", "deeper")
	if err := newSelfTestKiller(t, root).selfTest(); err == nil {
		t.Fatal("selfTest passed on a missing cgroup root")
	}
}

func TestCgroupKiller_SelfTest_FailsOnUnreadableOwnCgroup(t *testing.T) {
	k := newCgroupKiller(t.TempDir())
	k.procSelfCgroup = filepath.Join(t.TempDir(), "absent")
	err := k.selfTest()
	if err == nil {
		t.Fatal("selfTest passed without knowing its own cgroup")
	}
	if !strings.Contains(err.Error(), "read own cgroup") {
		t.Errorf("error = %v, want it to name the own-cgroup read", err)
	}
}

// The probe must land under the daemon's own cgroup, never at the hierarchy
// root: the root is mode 0555, so a group created there needs CAP_DAC_OVERRIDE
// — which the unit deliberately withholds, and a self-test that demanded it
// would fail on every guest.
func TestCgroupKiller_SelfTest_ProbeNestsUnderOwnCgroup(t *testing.T) {
	root := t.TempDir()
	seedProbeCgroup(t, root, testOwnCgroup)
	if err := newSelfTestKiller(t, root).selfTest(); err != nil {
		t.Fatalf("selfTest: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, selfTestCgroup)); !os.IsNotExist(err) {
		t.Errorf("probe created at the hierarchy root: stat err = %v", err)
	}
}

func TestOwnCgroupPath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    string
		wantErr bool
	}{
		{"unified", "0::/system.slice/policy-monitor.service\n", "system.slice/policy-monitor.service", false},
		{"root", "0::/\n", "", false},
		// A hybrid guest still reports the v2 hierarchy on the 0:: line.
		{"hybrid", "3:cpu:/foo\n0::/system.slice/a.service\n", "system.slice/a.service", false},
		{"v1 only", "3:cpu:/foo\n2:memory:/bar\n", "", true},
		{"empty", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cgroup")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := ownCgroupPath(path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ownCgroupPath err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("ownCgroupPath = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCgroupKiller_PropagatesMissingKillInterface(t *testing.T) {
	root := t.TempDir()
	cid := "missing-kill"
	dir := filepath.Join(root, cid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("1234\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	killer := &cgroupKiller{cgroupRoot: root, waitTimeout: time.Second, pollInterval: time.Millisecond}
	if ok, err := killer.kill(cid); err == nil || ok {
		t.Fatalf("kill = (%v, %v), want missing cgroup.kill error", ok, err)
	}
}
