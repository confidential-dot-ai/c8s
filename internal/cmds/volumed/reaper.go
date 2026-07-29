package volumed

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// DefaultReapInterval is how often teardown checks which pods are gone.
const DefaultReapInterval = 15 * time.Second

// DefaultCgroupRoot is where the unified cgroup hierarchy is mounted.
const DefaultCgroupRoot = "/sys/fs/cgroup"

// PodLiveness reports whether a pod still exists.
type PodLiveness interface {
	// Live reports whether the pod is still there. An error means the question
	// could not be answered, which is not the same as "gone".
	Live(pod PodCgroup) (bool, error)
}

// Reaper tears down volumes whose pod has gone away.
//
// The signal is the pod's cgroup disappearing, not its kubelet directory.
// kubelet removes that directory when it tears a pod down — but with a volume
// still mounted under it that removal fails with EBUSY, so waiting for the
// directory to vanish waits for something this daemon is itself preventing.
// kubelet retries volume cleanup with backoff, so unmounting shortly after the
// cgroup goes costs a few "orphaned pod" log lines rather than a stuck pod.
type Reaper struct {
	Opener   *Opener
	Liveness PodLiveness
	// Interval between sweeps; zero means DefaultReapInterval.
	Interval time.Duration
	Logger   *slog.Logger
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
	for _, pod := range r.Opener.Pods() {
		live, err := r.Liveness.Live(pod)
		if err != nil {
			r.logger().Warn("pod liveness unknown; leaving its volumes open",
				"pod", pod.UID, "error", err)
			continue
		}
		if live {
			continue
		}
		if n := r.Opener.ClosePod(ctx, pod.UID); n > 0 {
			closed += n
			r.logger().Info("pod gone; volumes torn down", "pod", pod.UID, "volumes", n)
		}
	}
	return closed
}

// CgroupLiveness answers from the cgroup tree, where the runtime removes a
// pod's slice once its last container is gone.
type CgroupLiveness struct {
	// Root is the cgroup mount; zero means DefaultCgroupRoot.
	Root string
}

// Live treats a missing pod cgroup as gone. Any other stat failure is an error,
// so Sweep leaves the volume alone rather than acting on a lookup that did not
// happen.
func (l CgroupLiveness) Live(pod PodCgroup) (bool, error) {
	if pod.Path == "" {
		return false, fmt.Errorf("volumed: pod %s has no cgroup path", pod.UID)
	}
	switch _, err := os.Stat(filepath.Join(l.root(), pod.Path)); {
	case err == nil:
		return true, nil
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

func (l CgroupLiveness) root() string {
	if l.Root != "" {
		return l.Root
	}
	return DefaultCgroupRoot
}
