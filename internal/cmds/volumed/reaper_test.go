package volumed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// livenessFor answers per pod UID.
type livenessFor struct {
	live map[string]bool
	err  error
}

func (l livenessFor) Live(pod PodCgroup) (bool, error) {
	if l.err != nil {
		return false, l.err
	}
	return l.live[pod.UID], nil
}

// openerWithVolumes opens one volume per name for testPodUID.
func openerWithVolumes(t *testing.T, ops *fakeOps, names ...string) *Opener {
	t.Helper()
	root, base := kubeletTree(t)
	for _, n := range names {
		if err := os.Mkdir(filepath.Join(base, KubeVolumeName(n)), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", n, err)
		}
	}
	o := &Opener{Ops: ops, KubeletRoot: root}
	for _, n := range names {
		req := testRequest(t)
		req.Name = n
		if err := o.Open(t.Context(), req); err != nil {
			t.Fatalf("open %s: %v", n, err)
		}
	}
	return o
}

func TestSweepTearsDownAGonePod(t *testing.T) {
	ops := newOps()
	o := openerWithVolumes(t, ops, "weights", "datasets")

	r := &Reaper{Opener: o, Liveness: livenessFor{live: map[string]bool{}}}
	if got := r.Sweep(t.Context()); got != 2 {
		t.Fatalf("swept %d volumes, want 2", got)
	}
	if o.Len() != 0 {
		t.Fatalf("opener holds %d mounts after the sweep", o.Len())
	}
	if c, v, m := ops.leaked(); c != 0 || v != 0 || m != 0 {
		t.Fatalf("leaked crypt=%d verity=%d mounts=%d", c, v, m)
	}
}

func TestSweepLeavesALivePodAlone(t *testing.T) {
	ops := newOps()
	o := openerWithVolumes(t, ops, "weights")

	r := &Reaper{Opener: o, Liveness: livenessFor{live: map[string]bool{testPodUID: true}}}
	if got := r.Sweep(t.Context()); got != 0 {
		t.Fatalf("swept %d volumes from a live pod", got)
	}
	if o.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want 1", o.Len())
	}
}

// Unmounting on a failed lookup would pull volumes out from under running
// workloads. The next sweep retries anyway.
func TestSweepLeavesVolumesOpenWhenLivenessIsUnknown(t *testing.T) {
	ops := newOps()
	o := openerWithVolumes(t, ops, "weights")

	r := &Reaper{Opener: o, Liveness: livenessFor{err: errors.New("cgroup root unreadable")}}
	if got := r.Sweep(t.Context()); got != 0 {
		t.Fatalf("swept %d volumes on an unanswered lookup", got)
	}
	if o.Len() != 1 {
		t.Fatal("an unanswered liveness lookup tore down a volume")
	}
}

// Only the gone pod's volumes go.
func TestSweepIsPerPod(t *testing.T) {
	const other = "99999999-8888-7777-6666-555555555555"
	ops := newOps()
	root, base := kubeletTree(t)
	otherBase := filepath.Join(root, "pods", other, emptyDirSubdir)
	if err := os.MkdirAll(otherBase, 0o755); err != nil {
		t.Fatalf("mkdir other pod: %v", err)
	}
	for dir, name := range map[string]string{base: "weights", otherBase: "datasets"} {
		if err := os.Mkdir(filepath.Join(dir, KubeVolumeName(name)), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}
	o := &Opener{Ops: ops, KubeletRoot: root}

	for name, uid := range map[string]string{"weights": testPodUID, "datasets": other} {
		req := testRequest(t)
		req.Name, req.Pod = name, testPod(uid)
		if err := o.Open(t.Context(), req); err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
	}

	r := &Reaper{Opener: o, Liveness: livenessFor{live: map[string]bool{other: true}}}
	if got := r.Sweep(t.Context()); got != 1 {
		t.Fatalf("swept %d volumes, want 1", got)
	}
	if o.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want the surviving pod's 1", o.Len())
	}
}

func TestSweepIsIdempotent(t *testing.T) {
	ops := newOps()
	o := openerWithVolumes(t, ops, "weights")
	r := &Reaper{Opener: o, Liveness: livenessFor{live: map[string]bool{}}}

	if got := r.Sweep(t.Context()); got != 1 {
		t.Fatalf("first sweep closed %d", got)
	}
	if got := r.Sweep(t.Context()); got != 0 {
		t.Fatalf("second sweep closed %d, want 0", got)
	}
}

func TestSweepIsANoopWithoutDependencies(t *testing.T) {
	if got := (&Reaper{}).Sweep(context.Background()); got != 0 {
		t.Fatalf("swept %d with nothing configured", got)
	}
}

func TestRunSweepsUntilContextIsDone(t *testing.T) {
	ops := newOps()
	o := openerWithVolumes(t, ops, "weights")
	r := &Reaper{Opener: o, Liveness: livenessFor{live: map[string]bool{}}, Interval: time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	for o.Len() != 0 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("the reaper never tore down the gone pod")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
}

// Pods reports each pod once, whatever it holds.
func TestPodsAreDistinct(t *testing.T) {
	ops := newOps()
	o := openerWithVolumes(t, ops, "weights", "datasets")
	if got := o.Pods(); len(got) != 1 || got[0].UID != testPodUID {
		t.Fatalf("pods = %v, want one entry", got)
	}
}

func TestClosePodIgnoresAnEmptyUID(t *testing.T) {
	ops := newOps()
	o := openerWithVolumes(t, ops, "weights")
	if got := o.ClosePod(t.Context(), ""); got != 0 {
		t.Fatalf("closed %d volumes for an empty pod uid", got)
	}
	if o.Len() != 1 {
		t.Fatal("an empty pod uid tore down a volume")
	}
}

// A pod whose cgroup is gone is gone; anything else is an error, so the sweep
// leaves the volume alone.
func TestCgroupLivenessReadsTheCgroupTree(t *testing.T) {
	root := t.TempDir()
	pod := testPod(testPodUID)
	if err := os.MkdirAll(filepath.Join(root, pod.Path), 0o755); err != nil {
		t.Fatalf("mkdir pod slice: %v", err)
	}

	live := CgroupLiveness{Root: root}
	ok, err := live.Live(pod)
	if err != nil || !ok {
		t.Fatalf("live = %v, %v; want true, nil", ok, err)
	}

	if err := os.Remove(filepath.Join(root, pod.Path)); err != nil {
		t.Fatalf("remove pod slice: %v", err)
	}
	ok, err = live.Live(pod)
	if err != nil || ok {
		t.Fatalf("gone = %v, %v; want false, nil", ok, err)
	}
}

// A pod recorded without a cgroup path cannot be judged, so it is an error
// rather than a silent teardown.
func TestCgroupLivenessRefusesAPathlessPod(t *testing.T) {
	if _, err := (CgroupLiveness{Root: t.TempDir()}).Live(PodCgroup{UID: testPodUID}); err == nil {
		t.Fatal("a pod with no cgroup path was judged")
	}
}

// A stat that fails for any reason other than "not there" is unanswered, not a
// teardown signal.
func TestCgroupLivenessReportsAnUnreadablePath(t *testing.T) {
	root := t.TempDir()
	pod := testPod(testPodUID)
	// A file where the tree expects a directory: stat of anything beneath it
	// fails with ENOTDIR rather than ENOENT.
	blocker := filepath.Join(root, "kubepods.slice")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if _, err := (CgroupLiveness{Root: root}).Live(pod); err == nil {
		t.Fatal("an unreadable cgroup path reported the pod gone")
	}
}

// A cgroup root that is not mounted must not read as every pod having exited.
func TestCgroupLivenessRefusesAnAbsentRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "never-mounted")
	if _, err := (CgroupLiveness{Root: root}).Live(testPod(testPodUID)); err == nil {
		t.Fatal("an unmounted cgroup root reported the pod gone")
	}
}

func TestCgroupLivenessDefaultsItsRoot(t *testing.T) {
	if got := (CgroupLiveness{}).root(); got != DefaultCgroupRoot {
		t.Fatalf("root = %q, want %q", got, DefaultCgroupRoot)
	}
}

// The reaper and server fall back to package defaults rather than panicking on
// a zero value.
func TestZeroValuesFallBackToDefaults(t *testing.T) {
	if got := (&Reaper{}).interval(); got != DefaultReapInterval {
		t.Errorf("interval = %v, want %v", got, DefaultReapInterval)
	}
	if (&Reaper{}).logger() == nil {
		t.Error("reaper has no logger")
	}
	if (&Server{}).logger() == nil {
		t.Error("server has no logger")
	}
}
