//go:build linux

package rtmr3measurer

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

const (
	hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hexB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cid1 = "1111111111111111111111111111111111111111111111111111111111111111"
	cid2 = "2222222222222222222222222222222222222222222222222222222222222222"
	cid3 = "3333333333333333333333333333333333333333333333333333333333333333"
)

// fakeTDX emulates the RTMR[3] sysfs node: writes fold into the register,
// reads return it. readFail makes the readback fail without failing writes.
type fakeTDX struct {
	reg      [runtimemeasure.Size]byte
	extends  int
	fail     error
	readFail error
}

func (f *fakeTDX) Extend(event []byte) error {
	if f.fail != nil {
		return f.fail
	}
	f.reg = runtimemeasure.Extend(f.reg, [runtimemeasure.Size]byte(event))
	f.extends++
	return nil
}

func (f *fakeTDX) Extension() ([]byte, error) {
	if f.readFail != nil {
		return nil, f.readFail
	}
	return bytes.Clone(f.reg[:]), nil
}

// newTestMeasurer wires a measurer against a tempdir watch dir, a tempdir
// state file, and a fake TDX register. Reusing statePath and tdx across
// instances simulates a daemon restart inside a still-running VM.
func newTestMeasurer(t *testing.T, watchDir, statePath string, reg runtimemeasure.Register) *measurer {
	t.Helper()
	m := newMeasurer(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	m.watchDir = watchDir
	m.statePath = statePath
	m.reg = reg
	m.configReadDeadline = 100 * time.Millisecond
	m.configReadInterval = 5 * time.Millisecond
	if err := m.open(); err != nil {
		t.Fatalf("open: %v", err)
	}
	return m
}

func writeConfigJSON(t *testing.T, watchDir, cid string, annotations map[string]string) {
	t.Helper()
	dir := filepath.Join(watchDir, cid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ociSpec{Annotations: annotations})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeWorkload(t *testing.T, watchDir, cid, hexDigest string) {
	t.Helper()
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/confidential-dot-ai/app@sha256:" + hexDigest,
	})
}

func TestScanMeasuresWorkloadExactlyOnce(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	m.scanOnce()
	m.scanOnce()

	if tdx.extends != 1 {
		t.Fatalf("extends = %d, want 1", tdx.extends)
	}
	if tdx.reg != runtimemeasure.FromDigests([]string{"sha256:" + hexA}) {
		t.Fatal("register does not match the expected single-extend fold")
	}
}

func TestReplicaOrRestartSameImageDoesNotReExtend(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	// Same image under a new cid: a crash-looped container or a second replica.
	writeWorkload(t, watch, cid2, hexA)
	m.scanOnce()

	if tdx.extends != 1 {
		t.Fatalf("extends = %d, want 1 (same digest must dedup across cids)", tdx.extends)
	}
}

// The finding this package's persistence exists for: a daemon restart
// (Restart=always) inside a still-running VM must NOT re-extend digests the
// previous process already measured. The journal file is the real one, so
// this exercises the on-disk format the two processes share.
func TestDaemonRestartDoesNotReExtend(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m1 := newTestMeasurer(t, watch, state, tdx)
	writeWorkload(t, watch, cid1, hexA)
	m1.scanOnce()
	if tdx.extends != 1 {
		t.Fatalf("setup: extends = %d, want 1", tdx.extends)
	}

	// New process, same VM: fresh maps, same state file, same register.
	m2 := newTestMeasurer(t, watch, state, tdx)
	m2.scanOnce()
	m2.scanOnce()

	if tdx.extends != 1 {
		t.Fatalf("extends = %d after restart, want 1 (double-extend corrupts the register)", tdx.extends)
	}
	// A genuinely new image after the restart still measures.
	writeWorkload(t, watch, cid2, hexB)
	m2.scanOnce()
	if tdx.extends != 2 {
		t.Fatalf("extends = %d, want 2 (new digest after restart must extend)", tdx.extends)
	}
	if tdx.reg != runtimemeasure.FromDigests([]string{"sha256:" + hexA, "sha256:" + hexB}) {
		t.Fatal("register does not match the expected two-extend fold")
	}
}

// A register carrying extends the journal cannot account for is a soft
// anomaly: the daemon starts, logs, and keeps scanning — it just never
// extends again, because an extra extend is unrecoverable.
func TestForeignExtendKeepsTheDaemonRunning(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	if err := os.WriteFile(state, []byte("sha256:"+hexA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tdx := &fakeTDX{reg: runtimemeasure.FromDigests([]string{"sha256:" + hexB})}

	m := newTestMeasurer(t, watch, state, tdx)
	writeWorkload(t, watch, cid1, hexB)
	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0 (a diverged register must not be extended)", tdx.extends)
	}
}

// An unreadable register at startup must not block either: the journal stays
// the dedup truth and the daemon keeps measuring new images.
func TestUnreadableRegisterKeepsTheDaemonRunning(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	if err := os.WriteFile(state, []byte("sha256:"+hexA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tdx := &fakeTDX{readFail: errors.New("sysfs read failed")}

	m := newTestMeasurer(t, watch, state, tdx)
	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0 (the journaled digest stays deduped)", tdx.extends)
	}
	writeWorkload(t, watch, cid2, hexB)
	m.scanOnce()
	if tdx.extends != 1 {
		t.Fatalf("extends = %d, want 1 (a new digest must still measure)", tdx.extends)
	}
}

// A journal the register is one extend behind is repaired at open; a repair
// that itself fails is the one fatal case, so the daemon refuses to run with
// a mismatch it knows how to fix but could not.
func TestFailedStartupRepairIsFatal(t *testing.T) {
	state := filepath.Join(t.TempDir(), "measured")
	if err := os.WriteFile(state, []byte("sha256:"+hexA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := newMeasurer(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	m.statePath = state
	m.reg = &fakeTDX{fail: errors.New("sysfs write failed")} // register still at boot value

	if err := m.open(); err == nil {
		t.Fatal("open = nil, want an error when the repair extend fails")
	}
}

func TestSandboxContainerNotMeasured(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	writeConfigJSON(t, watch, cid1, map[string]string{
		"io.katacontainers.pkg.oci.container_type": "pod_sandbox",
		"io.kubernetes.cri.container-type":         "sandbox",
	})
	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0 (sandbox/pause is not a workload)", tdx.extends)
	}
}

// The CRI-O container-type key is not a sandbox marker in this shape; a
// container carrying only it is a workload and its digest is measured.
func TestCRIOMarkedContainerIsMeasured(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	writeConfigJSON(t, watch, cid1, map[string]string{
		"io.kubernetes.cri.container-type":  "container",
		"io.kubernetes.cri-o.ContainerType": "sandbox",
		"io.kubernetes.cri.image-name":      "ghcr.io/confidential-dot-ai/app@sha256:" + hexA,
	})
	m.scanOnce()
	if tdx.extends != 1 {
		t.Fatalf("extends = %d, want 1 (the CRI-O marker does not exempt from measurement)", tdx.extends)
	}
}

func TestUnpinnedImageNotMeasured(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	writeConfigJSON(t, watch, cid1, map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/confidential-dot-ai/app:latest",
	})
	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0 (tag-only image carries no digest)", tdx.extends)
	}
	if _, seen := m.seenCids[cid1]; !seen {
		t.Fatal("unmeasurable cid must be marked seen (no rescan loop)")
	}
}

// A failed extend must leave the journal able to retry, so a later cid with
// the same digest still measures.
func TestExtendFailureRetriesOnTheNextContainer(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{fail: errors.New("sysfs write failed")}
	m := newTestMeasurer(t, watch, state, tdx)

	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	if tdx.extends != 0 {
		t.Fatalf("extends = %d, want 0", tdx.extends)
	}

	tdx.fail = nil
	writeWorkload(t, watch, cid2, hexA) // same image, new cid
	m.scanOnce()
	if tdx.extends != 1 {
		t.Fatalf("extends = %d, want 1 (retry after the failed extend)", tdx.extends)
	}
}

func TestSeenCidsPrunedWhenContainerDirGoes(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	tdx := &fakeTDX{}
	m := newTestMeasurer(t, watch, state, tdx)

	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()
	if _, seen := m.seenCids[cid1]; !seen {
		t.Fatal("cid1 should be seen")
	}
	if err := os.RemoveAll(filepath.Join(watch, cid1)); err != nil {
		t.Fatal(err)
	}
	m.scanOnce()
	if _, seen := m.seenCids[cid1]; seen {
		t.Fatal("cid1 should be pruned after its dir disappeared")
	}
	if got := m.journal.Digests(); len(got) != 1 || got[0] != "sha256:"+hexA {
		t.Fatalf("journal digests = %v; the journal must NOT be pruned (it mirrors the append-only register)", got)
	}
}

// The measurer must drive the register it opened, not a copy: a workload
// measured through a real TDXRegister lands in the backing node.
func TestMeasurerExtendsTheRegisterItOpened(t *testing.T) {
	watch, state := t.TempDir(), filepath.Join(t.TempDir(), "measured")
	node := filepath.Join(t.TempDir(), "rtmr3:sha384")
	if err := os.WriteFile(node, make([]byte, runtimemeasure.Size), 0o600); err != nil {
		t.Fatal(err)
	}
	m := newTestMeasurer(t, watch, state, runtimemeasure.TDXRegister(node))

	writeWorkload(t, watch, cid1, hexA)
	m.scanOnce()

	got, err := os.ReadFile(node)
	if err != nil {
		t.Fatal(err)
	}
	event := runtimemeasure.Event("sha256:" + hexA)
	if !bytes.Equal(got, event[:]) {
		t.Fatalf("register node holds %x, want the measured event %x", got, event)
	}
}
