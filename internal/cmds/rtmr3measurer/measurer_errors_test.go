//go:build linux

package rtmr3measurer

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// An unreadable watch dir warns (throttled) instead of spinning silently, and
// the failure counter resets once the dir is back.
func TestScanOnceUnreadableWatchDir(t *testing.T) {
	watch, state := filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	m.scanOnce()
	m.scanOnce()
	if m.readDirFails != 2 {
		t.Fatalf("readDirFails = %d, want 2", m.readDirFails)
	}

	if err := os.MkdirAll(watch, 0o755); err != nil {
		t.Fatal(err)
	}
	m.scanOnce()
	if m.readDirFails != 0 {
		t.Fatalf("readDirFails = %d, want 0 after the dir is readable again", m.readDirFails)
	}
}

// Non-container entries are ignored: plain files, and dirs whose name is not a
// 64-hex container id ("shared"/"sandbox"/"image").
func TestScanOnceIgnoresNonContainerEntries(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	if err := os.WriteFile(filepath.Join(watch, "stray-file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	writeConfigJSON(t, watch, "shared", map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/confidential-dot-ai/app@sha256:" + hexA,
	})
	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0 (non-cid entries are not workloads)", tdx.extends)
	}
	if len(m.seenCids) != 0 {
		t.Fatalf("seenCids = %v, want empty", m.seenCids)
	}
}

// A config.json that stays invalid JSON past the deadline is retried next
// scan (cid not marked seen); one that never appears behaves the same.
func TestReadConfigInvalidJSONAndMissingFile(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)
	m.configReadDeadline = 20 * time.Millisecond

	dir1 := filepath.Join(watch, cid1)
	if err := os.MkdirAll(dir1, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir1, "config.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(watch, cid2), 0o755); err != nil { // no config.json at all
		t.Fatal(err)
	}

	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0", tdx.extends)
	}
	if len(m.seenCids) != 0 {
		t.Fatalf("seenCids = %v, want empty (undecided cids must be retried)", m.seenCids)
	}

	// The config becoming valid on a later scan is then measured.
	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	if tdx.extends != 1 {
		t.Fatalf("extends = %d, want 1 once config.json turns valid", tdx.extends)
	}
}
