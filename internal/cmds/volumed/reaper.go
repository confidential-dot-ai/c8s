package volumed

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultReapInterval is how often teardown checks which pods are gone.
const DefaultReapInterval = 15 * time.Second

// DefaultConfirmGone is how many consecutive sweeps must agree a pod is gone.
const DefaultConfirmGone = 2

// DefaultCgroupRoot is where the unified cgroup hierarchy is mounted.
const DefaultCgroupRoot = "/sys/fs/cgroup"

// PodLiveness reports whether a pod still exists.
type PodLiveness interface {
	// Live reports whether the pod is still there. An error means the question
	// could not be answered, which is not the same as "gone".
	Live(pod PodCgroup) (bool, error)
}

// Reaper tears down volumes whose pod has gone away. It is the fallback behind
// the sidecar's close at termination (ClosePath): a pod that dies without one —
// a crashed sidecar, a force delete — still gets its volumes collected.
//
// The signal is the pod's cgroup emptying of processes, which the runtime does
// as it removes the last container. Neither the pod's kubelet directory nor its
// cgroup itself can serve: kubelet removes the directory only once the pod's
// volumes are cleaned up, and this daemon's mount is what that cleanup blocks
// on, so both outlive the pod for exactly as long as the reaper waits for them.
// kubelet retries volume cleanup with backoff, so unmounting once the processes
// go costs a few "orphaned pod" log lines rather than a stuck pod.
//
// Emptiness must hold for ConfirmGone consecutive sweeps. A volume torn down
// under a live pod does not come back — the sidecar opens once and then idles
// for the pod's life — so a pod whose containers are momentarily all restarting
// must not read as gone.
type Reaper struct {
	Opener   *Opener
	Liveness PodLiveness
	// Interval between sweeps; zero means DefaultReapInterval.
	Interval time.Duration
	// ConfirmGone is how many consecutive sweeps must find a pod gone before its
	// volumes go; zero means DefaultConfirmGone.
	ConfirmGone int
	Logger      *slog.Logger

	// gone counts consecutive sweeps that found each pod gone. Confined to
	// Sweep, which only Run calls, so it carries no lock.
	gone map[string]int
}

func (r *Reaper) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.Default()
}

func (r *Reaper) interval() time.Duration {
	if r.Interval > 0 {
		return r.Interval
	}
	return DefaultReapInterval
}

func (r *Reaper) confirmGone() int {
	if r.ConfirmGone > 0 {
		return r.ConfirmGone
	}
	return DefaultConfirmGone
}

// Run sweeps until ctx is done.
func (r *Reaper) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Sweep(ctx)
		}
	}
}

// Sweep tears down the volumes of every pod now gone, and reports how many
// volumes it closed.
//
// A pod whose liveness cannot be determined is left alone. Unmounting on a
// failed lookup would pull volumes out from under running workloads — the
// failure mode is worse than the leak it would avoid, and the next sweep
// retries anyway.
func (r *Reaper) Sweep(ctx context.Context) int {
	if r.Opener == nil || r.Liveness == nil {
		return 0
	}
	var closed int
	// Rebuilt from this sweep alone, so a pod that came back — or one torn down
	// here — leaves no count behind.
	seen := map[string]int{}
	for _, pod := range r.Opener.Pods() {
		live, err := r.Liveness.Live(pod)
		if err != nil {
			r.logger().Warn("pod liveness unknown; leaving its volumes open",
				"pod", pod.UID, "error", err)
			// The question went unanswered, so carry the count rather than
			// letting an unreadable sweep either confirm or forget.
			seen[pod.UID] = r.gone[pod.UID]
			continue
		}
		if live {
			continue
		}
		if n := r.gone[pod.UID] + 1; n < r.confirmGone() {
			seen[pod.UID] = n
			continue
		}
		if n := r.Opener.ClosePod(ctx, pod.UID); n > 0 {
			closed += n
			r.logger().Info("pod gone; volumes torn down", "pod", pod.UID, "volumes", n)
		}
	}
	r.gone = seen
	return closed
}

// CgroupLiveness answers from the cgroup tree, where the runtime removes a
// container's cgroup as the container goes.
type CgroupLiveness struct {
	// Root is the cgroup mount; zero means DefaultCgroupRoot.
	Root string
}

// Live treats a missing or unpopulated pod cgroup as gone. Any other failure is
// an error, so Sweep leaves the volume alone rather than acting on a lookup that
// did not happen.
func (l CgroupLiveness) Live(pod PodCgroup) (bool, error) {
	if pod.Path == "" {
		return false, fmt.Errorf("volumed: pod %s has no cgroup path", pod.UID)
	}
	dir := filepath.Join(l.root(), pod.Path)
	switch _, err := os.Stat(dir); {
	case err == nil:
		return populated(dir)
	case errors.Is(err, fs.ErrNotExist):
		// An unmounted cgroup root reads as every pod having exited, which
		// would tear down every live volume on the node. Confirm the tree is
		// there before believing the pod is gone.
		if _, err := os.Stat(l.root()); err != nil {
			return false, fmt.Errorf("volumed: stat cgroup root: %w", err)
		}
		return false, nil
	default:
		return false, fmt.Errorf("volumed: stat pod cgroup: %w", err)
	}
}

// populated reports whether any process remains anywhere beneath a cgroup.
//
// cgroup.events carries the kernel's own answer over the whole subtree, which is
// what a pod slice needs: its processes live in the per-container cgroups below
// it, never in the slice itself. A hierarchy that does not publish the file —
// cgroup v1 — offers nothing better than the slice being there.
func populated(dir string) (bool, error) {
	events := filepath.Join(dir, "cgroup.events")
	b, err := os.ReadFile(events)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("volumed: read %s: %w", events, err)
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), " "); ok && key == "populated" {
			return value != "0", nil
		}
	}
	return false, fmt.Errorf("volumed: %s has no populated field", events)
}

func (l CgroupLiveness) root() string {
	if l.Root != "" {
		return l.Root
	}
	return DefaultCgroupRoot
}
