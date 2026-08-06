//go:build linux

package policymonitor

// The admission decision, written where kata-agent reads it.
//
// policy-monitor decides after kata-agent has forked the container's init, but
// that init is parked on the exec fifo until StartContainerRequest. The patched
// agent (kata-guest-base/patches/0002-*) waits for this file before writing the
// fifo, so a denied image never reaches execve — the post-start window closes
// (docs/kata-image-policy.md G1).
//
// The file lives in the container's bundle, which only in-guest root can write:
// the baked policy scopes CopyFileRequest to the sandbox seeding directory, so
// the host cannot forge a verdict. No file means no decision, and the agent
// fails closed on its own timeout.

import (
	"fmt"
	"os"
	"path/filepath"
)

// VerdictFile is the bundle-relative name the agent polls for.
const VerdictFile = "c8s-verdict"

const (
	verdictAllow = "allow"
	verdictDeny  = "deny"
)

// writeVerdict records the decision for the container whose bundle is dir.
// Written to a temp file and renamed so the agent never reads a partial value.
func writeVerdict(dir, verdict string) error {
	tmp, err := os.CreateTemp(dir, "."+VerdictFile+"-*")
	if err != nil {
		return fmt.Errorf("create verdict temp in %s: %w", dir, err)
	}
	return commitVerdict(tmp, dir, verdict)
}

// commitVerdict flushes verdict through tmp and renames it into place. Split
// out so tests can drive the flush-time error branches (write on a closed
// file, chmod on a removed name, …) without hijacking os operations. The
// temp is best-effort removed on every error path; a successful rename
// leaves it as the final file so the Remove is a no-op.
func commitVerdict(tmp *os.File, dir, verdict string) (retErr error) {
	name := tmp.Name()
	defer func() {
		if retErr != nil {
			_ = os.Remove(name)
		}
	}()

	if _, err := tmp.WriteString(verdict); err != nil {
		tmp.Close()
		return fmt.Errorf("write verdict: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync verdict: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close verdict: %w", err)
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return fmt.Errorf("chmod verdict: %w", err)
	}
	return os.Rename(name, filepath.Join(dir, VerdictFile))
}

// record writes the verdict and logs at Error when it cannot: the agent then
// waits out its timeout and refuses to start the container, so a container the
// monitor meant to admit does not run. That is the safe direction, but it turns
// an allow into a pod failure, which an operator has to be able to see.
func (m *monitor) recordVerdict(dir, verdict string) {
	if err := writeVerdict(dir, verdict); err != nil {
		m.logger.Error("cannot record admission verdict; kata-agent will refuse to start this container",
			"dir", dir, "verdict", verdict, "error", err)
	}
}
