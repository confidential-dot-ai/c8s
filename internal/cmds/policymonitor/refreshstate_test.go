//go:build linux

package policymonitor

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// captureLogs swaps m's logger for one writing to the returned buffer.
func captureLogs(m *monitor) *bytes.Buffer {
	var buf bytes.Buffer
	m.logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &buf
}

// A deny on a guest whose allowlist never left the baked seed must say so.
// Without it, "frozen allowlist" and "genuinely unlisted image" are the same
// log line — and once the SIGKILL lands, a frozen guest denies every workload
// at once with no indication why.
func TestDenyNamesFrozenAllowlist(t *testing.T) {
	seed := strings.Repeat("a", 64)
	unlisted := strings.Repeat("b", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + seed})
	m.refresh = &refreshState{reason: reasonNoMeasurements}
	buf := captureLogs(m)

	cid := testCID("frozen-deny")
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "container",
		"io.kubernetes.cri.image-name":     "ghcr.io/tenant/app@sha256:" + unlisted,
	})
	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	if len(killer.snapshot()) != 1 {
		t.Fatalf("want exactly one kill, got %+v", killer.snapshot())
	}
	line := findLog(t, buf, denyMsg)
	if frozen, _ := line["allowlist_frozen"].(bool); !frozen {
		t.Fatalf("deny line does not report the frozen allowlist: %v", line)
	}
	if reason, _ := line["frozen_reason"].(string); reason != reasonNoMeasurements {
		t.Fatalf("frozen_reason = %q, want %q", reason, reasonNoMeasurements)
	}
	if entries, _ := line["allowlist_entries"].(float64); entries != 1 {
		t.Fatalf("allowlist_entries = %v, want 1", line["allowlist_entries"])
	}
}

// With the refresh live, a deny is an ordinary policy decision and must not be
// dressed up as a degraded guest.
func TestDenyOmitsFrozenAttrsWhenRefreshLive(t *testing.T) {
	seed := strings.Repeat("a", 64)
	unlisted := strings.Repeat("b", 64)
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + seed})
	m.refresh = &refreshState{}
	m.refresh.enable()
	buf := captureLogs(m)

	cid := testCID("live-deny")
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "container",
		"io.kubernetes.cri.image-name":     "ghcr.io/tenant/app@sha256:" + unlisted,
	})
	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	line := findLog(t, buf, denyMsg)
	if _, present := line["allowlist_frozen"]; present {
		t.Fatalf("live refresh reported as frozen: %v", line)
	}
}

// A nil refreshState (tests, and any construction path that skips it) must not
// panic the decision path.
func TestFrozenAttrsNilStateIsSafe(t *testing.T) {
	m := &monitor{}
	if attrs := m.frozenAttrs(); attrs != nil {
		t.Fatalf("frozenAttrs = %v, want nil", attrs)
	}
}

// The posture must reach the digests endpoint, which is the only way it leaves
// a guest whose journal the operator cannot read.
func TestInventoryReportsRefreshPosture(t *testing.T) {
	b := newAdmissionInventory()
	if _, reported := b.AllowlistRefresh(); reported {
		t.Fatal("unwired inventory reported a posture; absent must not read as disabled")
	}

	state := &refreshState{reason: reasonNoMeasurements}
	b.refresh = func() workloadclaims.AllowlistRefresh { return state.report(3) }
	got, reported := b.AllowlistRefresh()
	if !reported || got.Enabled || got.Entries != 3 || got.Reason != reasonNoMeasurements {
		t.Fatalf("AllowlistRefresh = %+v, %v", got, reported)
	}

	state.enable()
	if got, _ := b.AllowlistRefresh(); !got.Enabled || got.Reason != "" {
		t.Fatalf("after enable: %+v", got)
	}
}

// findLog returns the first JSON log record whose msg matches.
// denyMsg is the deny line these tests read the frozen-allowlist attributes
// off. Kept next to them so a reworded message moves in one place.
const denyMsg = "deny container: not admitted by digest, argv, mounts or env"

func findLog(t *testing.T, buf *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue
		}
		if m, _ := rec["msg"].(string); m == msg {
			return rec
		}
	}
	t.Fatalf("no log record with msg %q in:\n%s", msg, buf.String())
	return nil
}
