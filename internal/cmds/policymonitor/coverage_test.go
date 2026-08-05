//go:build linux

package policymonitor

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	allowlistpkg "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// cdsAllowlistHandler serves a canonical allowlist body with the given version
// as the CDS /allowlist endpoint (weak ETag + JSON content type).
func cdsAllowlistHandler(t *testing.T, version string, digests map[string]string) http.HandlerFunc {
	t.Helper()
	al := &allowlistpkg.Allowlist{Schema: allowlistpkg.Schema, Digests: digests}
	body, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/allowlist" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("ETag", `W/"`+version+`"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

// testLogger returns a debug-level JSON logger for tests that drive the
// CDS-refresh helpers directly (which take a *slog.Logger).
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	logger, err := certutil.NewJSONLogger("debug")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return logger
}

// --- splitCSV -------------------------------------------------------------

func TestSplitCSV(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b ,, c ", []string{"a", "b", "c"}},
		{",,,", nil},
	} {
		got := splitCSV(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("splitCSV(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

// --- refreshOnce ----------------------------------------------------------

// newSeededAllowlist builds an *allowlist with a single seed digest.
func newSeededAllowlist(t *testing.T, seed string) *allowlist {
	t.Helper()
	dir := t.TempDir()
	body, err := json.Marshal(bootstrapAllowlistFile{Sha256Digests: []string{seed}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "seed.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	a, _, err := loadAllowlist(path)
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	return a
}

func TestRefreshOnce_MergesNewDigests(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	pulled := "sha256:" + strings.Repeat("b", 64)
	a := newSeededAllowlist(t, seed)
	overlay := &policyOverlay{}

	srv := httptest.NewServer(cdsAllowlistHandler(t, "2", map[string]string{
		seed:   "seed-image",
		pulled: "pulled-image",
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, srv.Client())
	refreshOnce(context.Background(), testLogger(t), client, a, overlay, time.Second)

	if a.Size() != 2 {
		t.Fatalf("size after refresh = %d, want 2", a.Size())
	}
	if !a.Contains(pulled) {
		t.Error("pulled digest not merged")
	}
	if !a.Contains(seed) {
		t.Error("seed digest dropped")
	}
	if overlay.version != 2 {
		t.Errorf("overlay version = %d, want 2", overlay.version)
	}
}

func TestRefreshOnce_NoNewDigests(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	a := newSeededAllowlist(t, seed)
	overlay := &policyOverlay{}

	srv := httptest.NewServer(cdsAllowlistHandler(t, "1", map[string]string{seed: "seed-image"}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, srv.Client())
	refreshOnce(context.Background(), testLogger(t), client, a, overlay, time.Second)

	if a.Size() != 1 {
		t.Fatalf("size = %d, want 1 (no growth)", a.Size())
	}
}

// A lower CDS version is ignored: the overlay keeps the higher applied epoch.
func TestRefreshOnce_RolledBackVersionIgnored(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	pulled := "sha256:" + strings.Repeat("b", 64)
	a := newSeededAllowlist(t, seed)
	overlay := &policyOverlay{}

	high := httptest.NewServer(cdsAllowlistHandler(t, "5", map[string]string{seed: "seed-image"}))
	client := allowlistclient.NewClientWithHTTP(high.URL, high.Client())
	refreshOnce(context.Background(), testLogger(t), client, a, overlay, time.Second)
	high.Close()
	if overlay.version != 5 {
		t.Fatalf("overlay version = %d, want 5", overlay.version)
	}

	// A withheld/rolled-back CDS now serves version 3 with an extra floor digest.
	low := httptest.NewServer(cdsAllowlistHandler(t, "3", map[string]string{seed: "seed-image", pulled: "pulled-image"}))
	defer low.Close()
	client = allowlistclient.NewClientWithHTTP(low.URL, low.Client())
	refreshOnce(context.Background(), testLogger(t), client, a, overlay, time.Second)

	if overlay.version != 5 {
		t.Fatalf("overlay version after rollback = %d, want 5 (unchanged)", overlay.version)
	}
	// The additive floor still grows — a floor digest, once seen, is never dropped.
	if !a.Contains(pulled) {
		t.Error("floor merge should still add pulled digest even on a rolled-back version")
	}
}

func TestRefreshOnce_CDSErrorKeepsAllowlist(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	a := newSeededAllowlist(t, seed)
	overlay := &policyOverlay{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, srv.Client())
	refreshOnce(context.Background(), testLogger(t), client, a, overlay, time.Second)

	// A CDS failure must never shrink the allowlist below the seed.
	if a.Size() != 1 {
		t.Fatalf("size after failed refresh = %d, want 1 (seed preserved)", a.Size())
	}
	if !a.Contains(seed) {
		t.Error("seed dropped after CDS failure")
	}
}

// --- runAllowlistRefresh disabled paths -----------------------------------

func TestRunAllowlistRefresh_InvalidMeasurements(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	a := newSeededAllowlist(t, seed)
	cfg := &Config{
		CDSURL:          "https://cds.example",
		CDSMeasurements: "not-valid-hex!!",
		RefreshInterval: time.Second,
	}
	// Returns promptly (refresh disabled) and never touches the network.
	state := &refreshState{reason: reasonNotYetStarted}
	runAllowlistRefresh(context.Background(), testLogger(t), cfg, a, &policyOverlay{}, state)
	if a.Size() != 1 {
		t.Fatalf("size = %d, want 1 (seed unchanged)", a.Size())
	}
	if got := state.frozenReason(); got != reasonBadMeasurements {
		t.Fatalf("frozenReason = %q, want %q", got, reasonBadMeasurements)
	}
}

func TestRunAllowlistRefresh_EmptyMeasurementsFailsClosed(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	a := newSeededAllowlist(t, seed)
	cfg := &Config{
		CDSURL:          "https://cds.example",
		CDSMeasurements: "",
		RefreshInterval: time.Second,
	}
	state := &refreshState{reason: reasonNotYetStarted}
	runAllowlistRefresh(context.Background(), testLogger(t), cfg, a, &policyOverlay{}, state)
	if a.Size() != 1 {
		t.Fatalf("size = %d, want 1", a.Size())
	}
	// The fail-closed must also be reportable, not just logged and forgotten.
	if got := state.frozenReason(); got != reasonNoMeasurements {
		t.Fatalf("frozenReason = %q, want %q", got, reasonNoMeasurements)
	}
	if rep := state.report(a.Size()); rep.Enabled || rep.Entries != 1 {
		t.Fatalf("report = %+v, want disabled with 1 entry", rep)
	}
}

// --- monitor.kill paths ---------------------------------------------------
// captureLogs lives in refreshstate_test.go.

func TestMonitorKill_KillerError(t *testing.T) {
	m, killer, _ := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	killer.err = os.ErrPermission
	buf := captureLogs(m)
	m.kill("somecid")
	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected one cgroup kill attempt, got %+v", calls)
	}
	// A denied container that survives its kill is a total bypass of the image
	// policy, not a warning-grade hiccup.
	if !strings.Contains(buf.String(), `"level":"ERROR"`) {
		t.Errorf("failed kill logged at %s, want ERROR", buf.String())
	}
}

func TestMonitorKill_CgroupNotFound(t *testing.T) {
	m, killer, _ := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	killer.ok = false
	buf := captureLogs(m)
	m.kill("somecid")
	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected one cgroup lookup, got %+v", calls)
	}
	// "denied but never confirmed dead" is the same bypass — the cgroup that
	// never materialised is indistinguishable from one we simply failed to find.
	if !strings.Contains(buf.String(), `"level":"ERROR"`) {
		t.Errorf("unconfirmed kill logged at %s, want ERROR", buf.String())
	}
}

func TestMonitorKill_SuccessStaysInfo(t *testing.T) {
	m, killer, _ := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	killer.ok = true
	buf := captureLogs(m)
	m.kill("somecid")
	if strings.Contains(buf.String(), `"level":"ERROR"`) {
		t.Errorf("confirmed kill logged at ERROR: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"level":"INFO"`) {
		t.Errorf("confirmed kill logged at %s, want INFO", buf.String())
	}
}

// --- seedExisting ---------------------------------------------------------

func TestSeedExisting_DeniesPreexistingContainer(t *testing.T) {
	denied := strings.Repeat("b", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})

	// A container directory already present when the monitor starts (e.g.
	// systemd restarted policy-monitor while a workload was live).
	writeConfigJSON(t, watchDir, "preexisting", map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/evil@sha256:" + denied,
	})
	// A sibling artifact that is not a container id should be skipped.
	if err := os.MkdirAll(filepath.Join(watchDir, "shared", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := m.seedExisting(context.Background()); err != nil {
		t.Fatalf("seedExisting: %v", err)
	}
	// seedExisting dispatches one goroutine per bundle so a slow pull cannot
	// stall the watcher; the decision lands shortly after.
	deadline := time.Now().Add(5 * time.Second)
	for len(killer.snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected 1 kill for the preexisting denied container, got %+v", calls)
	}
}

func TestSeedExisting_MissingWatchDir(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.cfg.WatchDir = filepath.Join(watchDir, "does-not-exist")
	if err := m.seedExisting(context.Background()); err == nil {
		t.Fatal("expected error reading a missing watch dir")
	}
}

// --- readConfigJSON / readOCISpec error paths -----------------------------

func TestReadConfigJSON_BundleGoneGivesUp(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 20 * time.Millisecond
	m.configReadInterval = 5 * time.Millisecond
	m.configPendingInterval = 5 * time.Millisecond
	_, err := m.readConfigJSON(context.Background(), filepath.Join(watchDir, "nope"))
	if err == nil {
		t.Fatal("expected error when the bundle directory does not exist")
	}
}

// The bundle appears when the guest pull starts and config.json only after it
// finishes, so a pull slower than configReadDeadline must still get a decision.
func TestReadConfigJSON_WaitsOutASlowPull(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 20 * time.Millisecond
	m.configReadInterval = 5 * time.Millisecond
	m.configPendingInterval = 5 * time.Millisecond

	dir := filepath.Join(watchDir, "slowpull")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		writeConfigJSON(t, watchDir, "slowpull", map[string]string{
			"io.kubernetes.cri.image-name": "ghcr.io/x@sha256:" + strings.Repeat("a", 64),
		})
	}()

	spec, err := m.readConfigJSON(context.Background(), dir)
	if err != nil {
		t.Fatalf("readConfigJSON: %v", err)
	}
	if spec.Annotations["io.kubernetes.cri.image-name"] == "" {
		t.Fatal("spec parsed without the image-name annotation")
	}
}

func TestReadConfigJSON_ContextCancelled(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 5 * time.Second
	m.configReadInterval = 10 * time.Millisecond
	dir := filepath.Join(watchDir, "pending")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.readConfigJSON(ctx, dir); err == nil {
		t.Fatal("expected context error")
	}
}

func TestReadConfigJSON_UnrecoverableIsADir(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	// Point at a directory: os.ReadFile returns a non-ENOENT, non-partial
	// error, which readConfigJSON must surface immediately rather than
	// waiting for the bundle to go away.
	dir := filepath.Join(watchDir, "isadir")
	if err := os.MkdirAll(filepath.Join(dir, "config.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	m.configReadDeadline = 5 * time.Second
	start := time.Now()
	if _, err := m.readConfigJSON(context.Background(), dir); err == nil {
		t.Fatal("expected error for a directory in place of config.json")
	}
	if time.Since(start) > time.Second {
		t.Fatal("readConfigJSON retried an unrecoverable error instead of failing fast")
	}
}

// A symlink the host planted that resolves nowhere is a name that exists: the
// container has a bundle whose spec cannot be read, which is a deny, not a
// reason to keep waiting.
func TestReadConfigJSON_DanglingSymlinkIsUnrecoverable(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 20 * time.Millisecond
	m.configReadInterval = 5 * time.Millisecond
	m.configPendingInterval = 5 * time.Millisecond
	dir := filepath.Join(watchDir, "dangling")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent/target", filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := m.readConfigJSON(context.Background(), dir); err == nil {
		t.Fatal("expected error for a config.json symlink that does not resolve")
	}
	if time.Since(start) > time.Second {
		t.Fatal("readConfigJSON waited on a dangling symlink instead of failing")
	}
}

func TestReadOCISpec_EmptyFileIsPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readOCISpec(path)
	if !isPartialJSON(err) {
		t.Fatalf("empty file: err = %v, want partial-json sentinel", err)
	}
}

func TestReadOCISpec_BadJSONIsPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readOCISpec(path)
	if !isPartialJSON(err) {
		t.Fatalf("bad json: err = %v, want partial-json sentinel", err)
	}
}

// The bundle directory is created when the guest pull starts, so a container
// whose config.json has not landed yet is undecided, not admitted: the decision
// has to survive a pull longer than configReadDeadline.
func TestHandleNewContainer_SlowPullStillDenies(t *testing.T) {
	denied := strings.Repeat("b", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 20 * time.Millisecond
	m.configReadInterval = 5 * time.Millisecond
	m.configPendingInterval = 5 * time.Millisecond

	dir := filepath.Join(watchDir, "slowpull")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(120 * time.Millisecond)
		writeConfigJSON(t, watchDir, "slowpull", map[string]string{
			"io.kubernetes.cri.image-name": "ghcr.io/evil@sha256:" + denied,
		})
	}()

	m.handleNewContainer(context.Background(), dir)
	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected the denied container to be killed once the slow pull wrote config.json, got %+v", calls)
	}
}

// A bundle that disappears without ever growing a config.json had no container
// to decide on.
func TestHandleNewContainer_BundleRemovedNoKill(t *testing.T) {
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
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
	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("expected no kill when the bundle went away, got %+v", calls)
	}
}

// A tag names whatever the registry serves the guest at pull time, so there is
// no digest to check against the allowlist.
func TestHandleNewContainer_TagFormReferenceDenied(t *testing.T) {
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	writeConfigJSON(t, watchDir, "tagged", map[string]string{
		"io.kubernetes.cri.image-name": "nginx:1.27-alpine",
	})
	m.handleNewContainer(context.Background(), filepath.Join(watchDir, "tagged"))
	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected a kill for a tag-form image reference, got %+v", calls)
	}
}

// The digest kata pulls is the one in image-name. A digest parked on image-id
// describes bytes the guest never fetches, so it must not admit anything.
func TestHandleNewContainer_AllowlistedImageIDDoesNotAdmit(t *testing.T) {
	allowed := strings.Repeat("a", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + allowed})
	writeConfigJSON(t, watchDir, "spoofed", map[string]string{
		"io.kubernetes.cri.image-name": "attacker.example/evil:latest",
		"io.kubernetes.cri.image-id":   "sha256:" + allowed,
	})
	m.handleNewContainer(context.Background(), filepath.Join(watchDir, "spoofed"))
	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected a kill: the allowlisted digest is not the reference the guest pulls, got %+v", calls)
	}
}

// --- cgroup helpers -------------------------------------------------------

func TestNewCgroupKiller_Defaults(t *testing.T) {
	killer := newCgroupKiller("/sys/fs/cgroup")
	if killer.cgroupRoot != "/sys/fs/cgroup" {
		t.Errorf("cgroupRoot = %q", killer.cgroupRoot)
	}
	if killer.waitTimeout <= 0 || killer.pollInterval <= 0 {
		t.Errorf("expected positive wait/poll, got %v/%v", killer.waitTimeout, killer.pollInterval)
	}
}

func TestFindCgroupDir_EmptyID(t *testing.T) {
	_, err := findCgroupDir(t.TempDir(), "")
	if err == nil {
		t.Fatal("expected error for empty container id")
	}
}

// --- allowlist nil receivers ----------------------------------------------

func TestAllowlistNilReceivers(t *testing.T) {
	var a *allowlist
	if a.Contains("sha256:" + strings.Repeat("a", 64)) {
		t.Error("nil allowlist Contains should be false")
	}
	if a.Size() != 0 {
		t.Error("nil allowlist Size should be 0")
	}
	if a.MergePulled([]string{"sha256:" + strings.Repeat("a", 64)}) != 0 {
		t.Error("nil allowlist MergePulled should add 0")
	}
}

func TestAllowlistContains_Malformed(t *testing.T) {
	a := newSeededAllowlist(t, "sha256:"+strings.Repeat("a", 64))
	if a.Contains("garbage") {
		t.Error("Contains should be false for malformed input")
	}
	if a.Contains("") {
		t.Error("Contains should be false for empty input")
	}
}

// --- loadAllowlist malformed JSON -----------------------------------------

func TestLoadAllowlist_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAllowlist(path); err == nil {
		t.Fatal("expected parse error for malformed allowlist JSON")
	}
}

// --- runMonitor end-to-end ------------------------------------------------

func TestRunMonitor_BadLogLevel(t *testing.T) {
	cfg := &Config{LogLevel: "not-a-level"}
	if err := runMonitor(context.Background(), cfg); err == nil {
		t.Fatal("expected error for invalid log level")
	}
}

func TestRunMonitor_MissingAllowlist(t *testing.T) {
	cfg := &Config{
		LogLevel:      "info",
		AllowlistPath: filepath.Join(t.TempDir(), "absent.json"),
		WatchDir:      t.TempDir(),
		CgroupRoot:    t.TempDir(),
	}
	if err := runMonitor(context.Background(), cfg); err == nil {
		t.Fatal("expected error loading a missing allowlist")
	}
}

// A monitor whose cgroup hierarchy is not writable can decide but cannot
// enforce. It must exit non-zero rather than run (and gate c8s-ready.target)
// while silently enforcing nothing — the ProtectControlGroups=yes field bug.
func TestRunMonitor_FailsWhenKillPathUnusable(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "allowlist.json")
	body, _ := json.Marshal(bootstrapAllowlistFile{Sha256Digests: []string{"sha256:" + strings.Repeat("a", 64)}})
	if err := os.WriteFile(allowlistPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		LogLevel:      "info",
		AllowlistPath: allowlistPath,
		WatchDir:      filepath.Join(dir, "watch"),
		CgroupRoot:    t.TempDir(), // no cgroup.kill: the kill path cannot work
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := runMonitor(ctx, cfg)
	if err == nil {
		t.Fatal("runMonitor started with an unusable kill path")
	}
	if !strings.Contains(err.Error(), "kill-path self-test") {
		t.Errorf("error = %v, want it to name the kill-path self-test", err)
	}
	// The self-test must gate startup, not just log: nothing should have been
	// watched.
	if _, statErr := os.Stat(cfg.WatchDir); !os.IsNotExist(statErr) {
		t.Errorf("watch dir created despite a failed self-test: stat err = %v", statErr)
	}
}

func TestRunMonitor_RunsAndStopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "allowlist.json")
	body, _ := json.Marshal(bootstrapAllowlistFile{Sha256Digests: []string{"sha256:" + strings.Repeat("a", 64)}})
	if err := os.WriteFile(allowlistPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		LogLevel:      "info",
		AllowlistPath: allowlistPath,
		WatchDir:      filepath.Join(dir, "watch"), // created by runMonitor
		CgroupRoot:    writableCgroupRoot(t),
		// CDSURL empty: stays baked-seed-only, never touches the network.
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runMonitor(ctx, cfg) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runMonitor returned err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runMonitor did not stop after context cancel")
	}
	// The watch dir should have been created.
	if _, err := os.Stat(cfg.WatchDir); err != nil {
		t.Errorf("watch dir not created: %v", err)
	}
}

// --- run() overflow rescan recovery (drives seedExisting via Errors) ------

func TestMonitorRun_AllowedContainerNotKilled(t *testing.T) {
	digest := strings.Repeat("a", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()
	time.Sleep(50 * time.Millisecond)

	writeConfigJSON(t, watchDir, "allowed-live", map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/ok@sha256:" + digest,
	})
	time.Sleep(200 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run err: %v", err)
	}
	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("allowed container should not be killed, got %+v", calls)
	}
}

// run() creates a missing watch dir itself — it has to, to re-establish the
// watch after kata-agent replaces the dir at sandbox creation — so "missing"
// is not an error. "Uncreatable" still must be: a regular file where the
// parent dir should be.
func TestMonitorRun_WatchDirUncreatable(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	blocker := filepath.Join(watchDir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	m.cfg.WatchDir = filepath.Join(blocker, "absent")
	if err := m.run(context.Background()); err == nil {
		t.Fatal("expected error when the watch dir cannot be created")
	}
}

// --- newMonitorCommand flag parsing ---------------------------------------

func TestNewMonitorCommand_FlagParsing(t *testing.T) {
	cmd := newMonitorCommand()
	err := cmd.Flags().Parse([]string{
		"--allowlist", "/tmp/a.json",
		"--watch-dir", "/tmp/watch",
		"--cgroup-root", "/tmp/cg",
		"--log-level", "warn",
		"--cds-url", "https://cds",
		"--cds-measurements", "abc,def",
		"--attestation-service-url", "http://127.0.0.1:9000",
		"--allowlist-refresh-interval", "5s",
	})
	if err != nil {
		t.Fatalf("flag parse: %v", err)
	}
	get := func(name string) string {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			t.Fatalf("flag %q missing", name)
		}
		return f.Value.String()
	}
	if got := get("allowlist"); got != "/tmp/a.json" {
		t.Errorf("allowlist = %q", got)
	}
	if got := get("allowlist-refresh-interval"); got != "5s" {
		t.Errorf("refresh-interval = %q", got)
	}
	if got := get("cds-url"); got != "https://cds" {
		t.Errorf("cds-url = %q", got)
	}
}

func TestNewMonitorCommand_RunEErrorsOnMissingAllowlist(t *testing.T) {
	cmd := newMonitorCommand()
	// Force a deterministic failure: a non-existent allowlist path. Use a
	// short-lived already-cancelled context so the run never blocks even if
	// it somehow got past the allowlist load.
	if err := cmd.Flags().Parse([]string{
		"--allowlist", filepath.Join(t.TempDir(), "absent.json"),
		"--watch-dir", t.TempDir(),
		"--cgroup-root", t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd.SetContext(ctx)
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("expected RunE to error on missing allowlist")
	}
}

func TestConfig_FillDefaults_FromEnv(t *testing.T) {
	t.Setenv("C8S_CDS_URL", "https://cds.from.env")
	t.Setenv("C8S_CDS_MEASUREMENTS", "aabb")
	t.Setenv("C8S_ATTESTATION_SERVICE_URL", "http://attester.env")
	var c Config
	c.fillDefaults()
	if c.CDSURL != "https://cds.from.env" {
		t.Errorf("CDSURL = %q", c.CDSURL)
	}
	if c.CDSMeasurements != "aabb" {
		t.Errorf("CDSMeasurements = %q", c.CDSMeasurements)
	}
	if c.AttestationServiceURL != "http://attester.env" {
		t.Errorf("AttestationServiceURL = %q", c.AttestationServiceURL)
	}
	if c.RefreshInterval != defaultRefreshInterval {
		t.Errorf("RefreshInterval = %v, want default", c.RefreshInterval)
	}
}

func TestConfig_FillDefaults_AttestationFallback(t *testing.T) {
	t.Setenv("C8S_CDS_URL", "")
	t.Setenv("C8S_CDS_MEASUREMENTS", "")
	t.Setenv("C8S_ATTESTATION_SERVICE_URL", "")
	var c Config
	c.fillDefaults()
	if c.AttestationServiceURL != defaultAttestationServiceURL {
		t.Errorf("AttestationServiceURL = %q, want %q", c.AttestationServiceURL, defaultAttestationServiceURL)
	}
}

// --- Run() top-level ------------------------------------------------------

func TestRun_UnknownSubcommandErrors(t *testing.T) {
	if err := Run([]string{"nonexistent-subcommand"}); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}
