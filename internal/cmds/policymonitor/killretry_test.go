//go:build linux

package policymonitor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedKiller answers attempt n from answer(n) and counts the attempts.
type scriptedKiller struct {
	mu       sync.Mutex
	attempts int
	answer   func(attempt int) (bool, error)
}

func (k *scriptedKiller) kill(string) (bool, error) {
	k.mu.Lock()
	k.attempts++
	n := k.attempts
	k.mu.Unlock()
	return k.answer(n)
}

func (k *scriptedKiller) selfTest() error { return nil }

func (k *scriptedKiller) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.attempts
}

// newRetryMonitor wires a monitor whose killer follows answer, and returns the
// denied container's bundle directory alongside it.
func newRetryMonitor(t *testing.T, answer func(attempt int) (bool, error)) (*monitor, *scriptedKiller, string) {
	t.Helper()
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	killer := &scriptedKiller{answer: answer}
	m.killer = killer
	dir := filepath.Join(watchDir, testCID("denied"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return m, killer, dir
}

func countLevel(logs, level string) int {
	return strings.Count(logs, `"level":"`+level+`"`)
}

// The cgroup can materialise after the killer's own poll window closes — a slow
// init, or one that forks later. The deny must survive that.
func TestMonitorKill_LandsOnALaterAttempt(t *testing.T) {
	m, killer, dir := newRetryMonitor(t, func(attempt int) (bool, error) {
		return attempt >= 4, nil
	})
	buf := captureLogs(m)

	m.kill(context.Background(), dir)

	if got := killer.count(); got != 4 {
		t.Fatalf("attempts = %d, want 4 (retry until the cgroup appears)", got)
	}
	if !strings.Contains(buf.String(), "SIGKILLed container cgroup") {
		t.Fatalf("no confirmed-kill record: %s", buf.String())
	}
	// The first unconfirmed attempt is an Error; the rest are throttled.
	if n := countLevel(buf.String(), "ERROR"); n != 1 {
		t.Errorf("ERROR lines = %d, want 1 (one per escalation, not per attempt)", n)
	}
}

// kata-agent removing the bundle means there is no container left to kill.
func TestMonitorKill_StopsWhenBundleRemoved(t *testing.T) {
	var dir string
	m, killer, bundle := newRetryMonitor(t, func(attempt int) (bool, error) {
		if attempt == 3 {
			if err := os.RemoveAll(dir); err != nil {
				t.Error(err)
			}
		}
		return false, nil
	})
	dir = bundle
	buf := captureLogs(m)

	m.kill(context.Background(), dir)

	if got := killer.count(); got != 3 {
		t.Fatalf("attempts = %d, want 3 (stop once the bundle is gone)", got)
	}
	if strings.Contains(buf.String(), "SIGKILLed container cgroup") {
		t.Error("reported a confirmed kill that never landed")
	}
	if !strings.Contains(buf.String(), "bundle was removed before a kill was confirmed") {
		t.Errorf("removal not recorded: %s", buf.String())
	}
}

// A cgroup.kill that never accepts the write (EROFS under
// ProtectControlGroups=yes) keeps the denied container under attack for as long
// as the monitor runs.
func TestMonitorKill_RetriesWhileTheWriteKeepsFailing(t *testing.T) {
	m, killer, dir := newRetryMonitor(t, func(int) (bool, error) {
		return false, errors.New("kill cgroup: read-only file system")
	})
	buf := captureLogs(m)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); m.kill(ctx, dir) }()

	// Past the tight phase, so the back-off escalation is exercised too.
	start := time.Now()
	for killer.count() < 10 || time.Since(start) < 2*m.killRetryDeadline {
		if time.Since(start) > 10*time.Second {
			t.Fatalf("kill stopped retrying after %d attempts", killer.count())
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("kill did not return after the context was cancelled")
	}

	attempts := killer.count()
	if attempts < 10 {
		t.Fatalf("attempts = %d, want the kill retried until the context ended", attempts)
	}
	if !strings.Contains(buf.String(), "gave up killing a denied container") {
		t.Errorf("context cancellation not recorded: %s", buf.String())
	}
	// One line for the first failure, one for the back-off, one for the give-up
	// — not one per attempt.
	if n := countLevel(buf.String(), "ERROR"); n != 3 {
		t.Errorf("ERROR lines = %d across %d attempts, want 3", n, attempts)
	}
}

// A kill confirmed on the first attempt is the ordinary path: one Info line and
// nothing at Error.
func TestMonitorKill_ConfirmedFirstAttemptStaysInfo(t *testing.T) {
	m, killer, dir := newRetryMonitor(t, func(int) (bool, error) { return true, nil })
	buf := captureLogs(m)

	m.kill(context.Background(), dir)

	if got := killer.count(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
	if countLevel(buf.String(), "ERROR") != 0 {
		t.Errorf("confirmed kill logged at ERROR: %s", buf.String())
	}
	if countLevel(buf.String(), "INFO") == 0 {
		t.Errorf("confirmed kill not logged at INFO: %s", buf.String())
	}
}
