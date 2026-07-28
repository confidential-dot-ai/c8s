//go:build linux

package policymonitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	allowlistpkg "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// lockedBuffer is a goroutine-safe log sink for monitors running in goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogger returns a debug-level JSON logger writing into the returned buffer.
func captureLogger() (*slog.Logger, *lockedBuffer) {
	buf := &lockedBuffer{}
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

// logMessages decodes each JSON log line in raw and returns the msg values.
func logMessages(t *testing.T, raw string) []string {
	t.Helper()
	var msgs []string
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			Msg string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		msgs = append(msgs, rec.Msg)
	}
	return msgs
}

func containsMsg(msgs []string, want string) bool {
	for _, m := range msgs {
		if m == want {
			return true
		}
	}
	return false
}

// probeWatcherLive creates disallowed probe bundles until one is decided,
// which proves the inotify watch is installed: seeding only saw the dir's
// earlier state, so a decision can come from the event path alone.
func probeWatcherLive(t *testing.T, mkProbe func(cid string), decided func(cid string) bool) {
	t.Helper()
	for i := 0; i < 40; i++ {
		cid := fmt.Sprintf("watch-probe-%d", i)
		mkProbe(cid)
		if waitUntil(250*time.Millisecond, func() bool { return decided(cid) }) {
			return
		}
	}
	t.Fatal("watcher never decided a probe bundle")
}

// waitUntil polls cond every 20ms until it holds or timeout passes.
func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// writeSeedFile writes a bootstrap allowlist file and returns its path.
func writeSeedFile(t *testing.T, digests ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "allowlist.json")
	body, err := json.Marshal(bootstrapAllowlistFile{Sha256Digests: digests})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// makeFakeCgroup lays out a minimal v2 cgroup for cid under root, with one
// member pid, so a real cgroupKiller can find it; the kill is observable as
// "1" landing in cgroup.kill.
func makeFakeCgroup(t *testing.T, root, cid string) string {
	t.Helper()
	dir := filepath.Join(root, cid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.kill"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func cgroupKillContent(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.kill"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// --- normalizeDigest edge: separator at position zero ----------------------

func TestNormalizeDigest_SeparatorAtStart(t *testing.T) {
	hex := strings.Repeat("a", 64)
	got, err := normalizeDigest("@sha256:" + hex)
	if err != nil {
		t.Fatalf("normalizeDigest: %v", err)
	}
	if got != hex {
		t.Fatalf("got %q, want %q", got, hex)
	}
}

// --- writeCgroupKill --------------------------------------------------------

func TestWriteCgroupKill_WritesOne(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.kill"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeCgroupKill(dir); err != nil {
		t.Fatalf("writeCgroupKill: %v", err)
	}
	if got := cgroupKillContent(t, dir); got != "1" {
		t.Fatalf("cgroup.kill content = %q, want %q", got, "1")
	}
}

func TestWriteCgroupKill_WriteErrorSurfaces(t *testing.T) {
	// /dev/full accepts the open but fails the write with ENOSPC; the write
	// error itself must surface, not a short-write approximation.
	dir := t.TempDir()
	if err := os.Symlink("/dev/full", filepath.Join(dir, "cgroup.kill")); err != nil {
		t.Fatal(err)
	}
	if err := writeCgroupKill(dir); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("err = %v, want ENOSPC", err)
	}
}

// --- kill outcome logging ---------------------------------------------------

// The kill outcome log is the only in-guest audit record of enforcement, so
// each killer outcome must produce its own message and never a wrong one.
func TestKill_LogsOutcome(t *testing.T) {
	const (
		msgKilled   = "SIGKILLed container cgroup"
		msgFailed   = "kill cgroup failed"
		msgNotFound = "container cgroup not found"
	)
	for _, tc := range []struct {
		name   string
		killer *fakeKiller
		want   string
		forbid []string
	}{
		{"killed", &fakeKiller{ok: true}, msgKilled, []string{msgFailed, msgNotFound}},
		{"killer error", &fakeKiller{err: os.ErrPermission}, msgFailed, []string{msgKilled, msgNotFound}},
		{"cgroup not found", &fakeKiller{ok: false}, msgNotFound, []string{msgKilled, msgFailed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := captureLogger()
			m := &monitor{logger: logger, killer: tc.killer}
			m.kill("cid-under-test")
			msgs := logMessages(t, buf.String())
			if !containsMsg(msgs, tc.want) {
				t.Fatalf("missing %q in %v", tc.want, msgs)
			}
			for _, f := range tc.forbid {
				if containsMsg(msgs, f) {
					t.Fatalf("unexpected %q in %v", f, msgs)
				}
			}
		})
	}
}

// --- watch loop steady state ------------------------------------------------

// A healthy watch generation must not report seed failures or dir
// replacements: a spurious replacement means constant watch churn, a spurious
// seed failure means the operator is told enforcement is degraded when it
// is not.
func TestRun_HealthySteadyStateEmitsNoRecoveryWarnings(t *testing.T) {
	digest := strings.Repeat("a", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})
	logger, buf := captureLogger()
	m.logger = logger
	m.revalidateInterval = 20 * time.Millisecond

	// A pre-existing allowed container gives the seed pass real work.
	writeConfigJSON(t, watchDir, "seed-ok", map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/ok@sha256:" + digest,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()

	// Observe several revalidation ticks; stop early if a recovery fires.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "watch dir replaced") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}

	msgs := logMessages(t, buf.String())
	if containsMsg(msgs, "watch dir replaced; re-establishing watch and re-seeding") {
		t.Fatal("healthy watch dir treated as replaced")
	}
	if containsMsg(msgs, "seed existing containers failed") {
		t.Fatal("successful seed pass logged as a failure")
	}
	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("allowed container killed: %v", calls)
	}
}

// Removing the watch dir must end the generation via the inotify event alone:
// the periodic identity check is parked out of the test window, so only the
// dir's own Remove event can trigger the re-watch that re-creates the dir.
func TestRun_WatchDirRemovalReestablishesWatch(t *testing.T) {
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.revalidateInterval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()

	probeWatcherLive(t, func(cid string) {
		writeConfigJSON(t, watchDir, cid, map[string]string{
			"io.kubernetes.cri.image-name": "ghcr.io/probe@sha256:" + strings.Repeat("e", 64),
		})
	}, func(cid string) bool {
		return slices.Contains(killer.snapshot(), cid)
	})

	if err := os.RemoveAll(watchDir); err != nil {
		t.Fatal(err)
	}
	if !waitUntil(2*time.Second, func() bool {
		fi, err := os.Stat(watchDir)
		return err == nil && fi.IsDir()
	}) {
		t.Fatal("watch dir not re-created after removal; the generation did not end on the dir's Remove event")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
}

// --- runMonitor: workload-claims broker wiring ------------------------------

func TestRunMonitor_ServesWorkloadClaimsSocket(t *testing.T) {
	sockDir := t.TempDir()
	cfg := &Config{
		LogLevel:                "info",
		AllowlistPath:           writeSeedFile(t, "sha256:"+strings.Repeat("a", 64)),
		WatchDir:                filepath.Join(t.TempDir(), "watch"),
		CgroupRoot:              t.TempDir(),
		WorkloadClaimsSocketDir: sockDir,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runMonitor(ctx, cfg) }()

	sockPath := filepath.Join(sockDir, workloadclaims.SocketName)
	if !waitUntil(2*time.Second, func() bool {
		fi, err := os.Stat(sockPath)
		return err == nil && fi.Mode()&os.ModeSocket != 0
	}) {
		t.Fatal("workload-claims socket not created despite a configured socket dir")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runMonitor: %v", err)
	}
}

func TestRunMonitor_WorkloadClaimsSocketDirMissingFails(t *testing.T) {
	cfg := &Config{
		LogLevel:                "info",
		AllowlistPath:           writeSeedFile(t, "sha256:"+strings.Repeat("a", 64)),
		WatchDir:                filepath.Join(t.TempDir(), "watch"),
		CgroupRoot:              t.TempDir(),
		WorkloadClaimsSocketDir: filepath.Join(t.TempDir(), "absent", "deeper"),
	}
	err := runMonitor(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "workload-claims") {
		t.Fatalf("err = %v, want workload-claims broker start failure", err)
	}
}

// --- runMonitor: config.json settle window ----------------------------------

// A config.json that lands shortly after the bundle dir's CREATE event must
// still get a decision: the read budget has to absorb kata-agent's
// mkdir-then-write gap instead of giving up on the first absent read.
func TestRunMonitor_ConfigWrittenAfterCreateStillDenied(t *testing.T) {
	allowed := strings.Repeat("a", 64)
	denied := strings.Repeat("b", 64)
	watchDir := filepath.Join(t.TempDir(), "watch")
	cgroupRoot := t.TempDir()
	cid := "late-deny"
	cg := makeFakeCgroup(t, cgroupRoot, cid)

	cfg := &Config{
		LogLevel:      "info",
		AllowlistPath: writeSeedFile(t, "sha256:"+allowed),
		WatchDir:      watchDir,
		CgroupRoot:    cgroupRoot,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runMonitor(ctx, cfg) }()

	probeWatcherLive(t, func(pcid string) {
		makeFakeCgroup(t, cgroupRoot, pcid)
		writeConfigJSON(t, watchDir, pcid, map[string]string{
			"io.kubernetes.cri.image-name": "ghcr.io/probe@sha256:" + denied,
		})
	}, func(pcid string) bool {
		return cgroupKillContent(t, filepath.Join(cgroupRoot, pcid)) == "1"
	})

	bundle := filepath.Join(watchDir, cid)
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	// config.json lands after the CREATE event, inside the read budget.
	time.Sleep(150 * time.Millisecond)
	body, err := json.Marshal(ociSpec{Annotations: map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/evil@sha256:" + denied,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	if !waitUntil(4*time.Second, func() bool { return cgroupKillContent(t, cg) == "1" }) {
		t.Fatal("denied container with a late config.json was not killed")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runMonitor: %v", err)
	}
}

// --- runMonitor: CDS refresh wiring -----------------------------------------

// With a CDS URL configured, runMonitor must keep the allowlist current: a
// digest served by CDS but absent from the baked seed is admitted after a
// refresh, while an unknown digest is still killed.
func TestRunMonitor_CDSRefreshAdmitsPulledDigest(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	pulled := "sha256:" + strings.Repeat("b", 64)
	deniedHex := strings.Repeat("c", 64)

	al := &allowlistpkg.Allowlist{Schema: allowlistpkg.Schema, Digests: map[string]string{
		seed:   "seed-image",
		pulled: "pulled-image",
	}}
	body, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", `W/"2"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	watchDir := filepath.Join(t.TempDir(), "watch")
	cgroupRoot := t.TempDir()
	cgAllowed := makeFakeCgroup(t, cgroupRoot, "cds-allowed")
	cgDenied := makeFakeCgroup(t, cgroupRoot, "cds-denied")

	cfg := &Config{
		LogLevel:              "info",
		AllowlistPath:         writeSeedFile(t, seed),
		WatchDir:              watchDir,
		CgroupRoot:            cgroupRoot,
		CDSURL:                srv.URL,
		CDSMeasurements:       strings.Repeat("ab", 48),
		AttestationServiceURL: "http://127.0.0.1:8400",
		RefreshInterval:       50 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runMonitor(ctx, cfg) }()

	// Wait for the second poll: the first response is fully merged by then.
	if !waitUntil(3*time.Second, func() bool { return requests.Load() >= 2 }) {
		t.Fatal("CDS was never polled despite a configured CDS URL")
	}
	probeWatcherLive(t, func(pcid string) {
		makeFakeCgroup(t, cgroupRoot, pcid)
		writeConfigJSON(t, watchDir, pcid, map[string]string{
			"io.kubernetes.cri.image-name": "ghcr.io/probe@sha256:" + strings.Repeat("e", 64),
		})
	}, func(pcid string) bool {
		return cgroupKillContent(t, filepath.Join(cgroupRoot, pcid)) == "1"
	})

	writeConfigJSON(t, watchDir, "cds-allowed", map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/tenant/app@" + pulled,
	})
	writeConfigJSON(t, watchDir, "cds-denied", map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/evil@sha256:" + deniedHex,
	})

	if !waitUntil(4*time.Second, func() bool { return cgroupKillContent(t, cgDenied) == "1" }) {
		t.Fatal("unknown digest was not killed")
	}
	// Decisions run concurrently; give the allowed one time to settle before
	// asserting it was left alone.
	time.Sleep(200 * time.Millisecond)
	if got := cgroupKillContent(t, cgAllowed); got != "" {
		t.Fatal("digest merged from CDS was killed; refresh did not extend admission")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runMonitor: %v", err)
	}
}

// runAllowlistRefresh with valid pinned measurements must actually poll and
// merge; every disable path (bad measurements, no measurements) is already
// covered separately.
func TestRunAllowlistRefresh_MergesFromCDS(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	pulled := "sha256:" + strings.Repeat("b", 64)
	a := newSeededAllowlist(t, seed)
	overlay := &policyOverlay{}
	srv := httptest.NewServer(cdsAllowlistHandler(t, "2", map[string]string{
		seed:   "seed-image",
		pulled: "pulled-image",
	}))
	defer srv.Close()

	cfg := &Config{
		CDSURL:                srv.URL,
		CDSMeasurements:       strings.Repeat("ab", 48),
		AttestationServiceURL: "http://127.0.0.1:8400",
		RefreshInterval:       50 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runAllowlistRefresh(ctx, testLogger(t), cfg, a, overlay)
		close(done)
	}()

	if !waitUntil(3*time.Second, func() bool { return a.Contains(pulled) }) {
		t.Fatal("pulled digest never merged; refresh loop did not run")
	}
	cancel()
	<-done
}

// --- Config.fillDefaults ----------------------------------------------------

func TestConfig_FillDefaults_WorkloadClaimsSocketDirFromEnv(t *testing.T) {
	t.Setenv("C8S_WORKLOAD_CLAIMS_SOCKET_DIR", "/from/env")
	var c Config
	c.fillDefaults()
	if c.WorkloadClaimsSocketDir != "/from/env" {
		t.Fatalf("WorkloadClaimsSocketDir = %q, want env value", c.WorkloadClaimsSocketDir)
	}
	c2 := Config{WorkloadClaimsSocketDir: "/explicit"}
	c2.fillDefaults()
	if c2.WorkloadClaimsSocketDir != "/explicit" {
		t.Fatalf("explicit WorkloadClaimsSocketDir overwritten: %q", c2.WorkloadClaimsSocketDir)
	}
}

func TestConfig_FillDefaults_RefreshIntervalValue(t *testing.T) {
	var c Config
	c.fillDefaults()
	if c.RefreshInterval != 30*time.Second {
		t.Fatalf("RefreshInterval = %v, want 30s", c.RefreshInterval)
	}
}

// --- workload-claims broker helpers -----------------------------------------

func TestWorkloadBrokerRecord_FiltersInjectedAndEmptyDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	b := newWorkloadBroker()
	b.record("cid-app", "app", digest)
	b.record("cid-injected", workloadclaims.ReservedInjectedNames[0], digest)
	b.record("cid-empty", "other", "")

	got, err := b.ContainersForPeer(0)
	if err != nil {
		t.Fatalf("ContainersForPeer: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d containers, want 1: %+v", len(got), got)
	}
	if got[0].Name != "app" || got[0].Digest != digest {
		t.Fatalf("got %+v, want the app container with its digest", got[0])
	}
}

func TestContainerName_AnnotationKeys(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        string
	}{
		{"containerd key", map[string]string{"io.kubernetes.cri.container-name": "app"}, "app"},
		{"cri-o key", map[string]string{"io.kubernetes.cri-o.ContainerName": "crio-app"}, "crio-app"},
		{"empty containerd falls through", map[string]string{
			"io.kubernetes.cri.container-name":  "",
			"io.kubernetes.cri-o.ContainerName": "fallback",
		}, "fallback"},
		{"absent", map[string]string{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := containerName(tc.annotations); got != tc.want {
				t.Fatalf("containerName = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStartWorkloadClaimsBroker_ListenErrorSurfaces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger, _ := captureLogger()
	err := startWorkloadClaimsBroker(ctx, logger, newWorkloadBroker(),
		filepath.Join(t.TempDir(), "absent", "x.sock"))
	if err == nil {
		t.Fatal("expected a listen error for a missing socket directory")
	}
}
