//go:build linux

package policymonitor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readVerdict(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, VerdictFile))
	if err != nil {
		t.Fatalf("read verdict in %s: %v", dir, err)
	}
	return string(b)
}

func noVerdict(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, VerdictFile)); err == nil {
		t.Fatalf("expected no verdict in %s, found %q", dir, readVerdict(t, dir))
	}
}

// The patched kata-agent refuses to release the exec fifo without an "allow",
// so every path that admits a container has to leave one behind.
func TestVerdict_AllowedContainer(t *testing.T) {
	digest := strings.Repeat("a", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})
	writeConfigJSON(t, watchDir, "allowed", map[string]string{
		"io.kubernetes.cri.container-type": "container",
		"io.kubernetes.cri.image-name":     "ghcr.io/x/y@sha256:" + digest,
	})
	dir := filepath.Join(watchDir, "allowed")
	m.handleNewContainer(context.Background(), dir)

	if got := readVerdict(t, dir); got != verdictAllow {
		t.Errorf("verdict = %q, want %q", got, verdictAllow)
	}
	if calls := killer.snapshot(); len(calls) != 0 {
		t.Errorf("unexpected kills: %+v", calls)
	}
}

func TestVerdict_SandboxContainer(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	writeConfigJSON(t, watchDir, "sandbox-ctr", map[string]string{
		"io.kubernetes.cri.container-type": "sandbox",
	})
	dir := filepath.Join(watchDir, "sandbox-ctr")
	m.handleNewContainer(context.Background(), dir)
	if got := readVerdict(t, dir); got != verdictAllow {
		t.Errorf("verdict = %q, want %q — the pause would never start", got, verdictAllow)
	}
}

func TestVerdict_DeniedPaths(t *testing.T) {
	allowed := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name        string
		cid         string
		annotations map[string]string
	}{
		{"not allowlisted", "denied", map[string]string{
			"io.kubernetes.cri.container-type": "container",
			"io.kubernetes.cri.image-name":     "ghcr.io/evil@sha256:" + strings.Repeat("b", 64),
		}},
		{"tag-form reference", "tagged", map[string]string{
			"io.kubernetes.cri.container-type": "container",
			"io.kubernetes.cri.image-name":     "nginx:1.27-alpine",
		}},
		{"no reference at all", "bare", map[string]string{
			"io.kubernetes.cri.container-type": "container",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + allowed})
			writeConfigJSON(t, watchDir, tc.cid, tc.annotations)
			dir := filepath.Join(watchDir, tc.cid)
			m.handleNewContainer(context.Background(), dir)

			if got := readVerdict(t, dir); got != verdictDeny {
				t.Errorf("verdict = %q, want %q", got, verdictDeny)
			}
			if calls := killer.snapshot(); len(calls) != 1 {
				t.Errorf("expected the denied container to be killed, got %+v", calls)
			}
		})
	}
}

// A bundle with an unreadable spec is a container whose image cannot be
// determined; the agent must not start it.
func TestVerdict_UnreadableConfigDenies(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	dir := filepath.Join(watchDir, "bad-config")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{ not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.handleNewContainer(context.Background(), dir)
	if got := readVerdict(t, dir); got != verdictDeny {
		t.Errorf("verdict = %q, want %q", got, verdictDeny)
	}
}

// No decision is not an admission: the agent's own wait expires and refuses.
// Writing "allow" for a bundle we never resolved would hand it a free pass.
func TestVerdict_UndecidedContainerGetsNone(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 20 * time.Millisecond
	m.configReadInterval = 5 * time.Millisecond
	m.configPendingInterval = 5 * time.Millisecond

	dir := filepath.Join(watchDir, "ghost")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(60 * time.Millisecond)
		os.RemoveAll(dir)
	}()
	m.handleNewContainer(context.Background(), dir)
	noVerdict(t, dir)
}

// A bundle dir the agent tore down between kata-agent's do_create_container
// and our decision is not a coverage hole — writeVerdict has to report the
// failure so recordVerdict logs it (rather than reporting success and
// leaving the agent's own wait to be the only signal).
func TestVerdict_WriteRequiresBundleDir(t *testing.T) {
	err := writeVerdict(filepath.Join(t.TempDir(), "does-not-exist"), verdictAllow)
	if err == nil {
		t.Fatal("writeVerdict on a missing dir returned nil; agent would treat as absent-verdict timeout with no monitor-side signal")
	}
	if !strings.Contains(err.Error(), "create verdict temp") {
		t.Errorf("error %q should name the failing step (CreateTemp)", err)
	}
}

// recordVerdict swallows the error so the caller (handleNewContainer) can
// still kill on a deny path even if writing failed. It has to log at Error
// so the operator sees it — an allow-that-didn't-record turns into a pod
// stuck at StartContainer with no monitor-side breadcrumb.
func TestVerdict_RecordLogsWhenWriteFails(t *testing.T) {
	m, _, _ := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	buf := captureLogs(m)
	m.recordVerdict(filepath.Join(t.TempDir(), "does-not-exist"), verdictAllow)
	if !strings.Contains(buf.String(), `"level":"ERROR"`) {
		t.Fatalf("recordVerdict should log at ERROR when writeVerdict fails; got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "cannot record admission verdict") {
		t.Errorf("log missing the operator-facing message; got:\n%s", buf.String())
	}
}

// A file handle that's already gone (closed under us, or a bundle whose
// tmpfile was reaped) has to surface as a labelled error so the operator
// sees which flush step failed. The kata-agent's own absent-verdict timeout
// still catches it, but a monitor that silently swallowed the failure would
// leave nothing to diagnose against.
func TestVerdict_CommitReportsWriteFailure(t *testing.T) {
	dir := t.TempDir()
	tmp, err := os.CreateTemp(dir, "."+VerdictFile+"-*")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	tmp.Close() // simulate a handle that lost its file — WriteString → EBADF
	err = commitVerdict(tmp, dir, verdictAllow)
	if err == nil {
		t.Fatal("commitVerdict on a closed file returned nil")
	}
	if !strings.Contains(err.Error(), "write verdict") {
		t.Errorf("error %q should name the failing step (write)", err)
	}
	// The temp is cleaned up on the error path; the caller's dir stays
	// verdict-less, so the agent's own timeout fires.
	if _, statErr := os.Stat(filepath.Join(dir, VerdictFile)); statErr == nil {
		t.Errorf("verdict file exists after commit failed — a stale allow would open the exec fifo")
	}
}

// The agent reads this file while policy-monitor may still be writing it, so
// it has to appear whole or not at all.
func TestVerdict_WriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	if err := writeVerdict(dir, verdictAllow); err != nil {
		t.Fatalf("writeVerdict: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != VerdictFile {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dir contains %v, want just %q — a temp file was left behind", names, VerdictFile)
	}
	if got := readVerdict(t, dir); got != verdictAllow {
		t.Errorf("verdict = %q, want %q", got, verdictAllow)
	}
}
