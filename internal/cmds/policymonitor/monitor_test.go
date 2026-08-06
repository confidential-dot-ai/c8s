//go:build linux

package policymonitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	allowlistpkg "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// testCID derives a distinct container id of the shape the CRI generates (32
// random bytes, hex-encoded) from a descriptive name.
func testCID(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

// mustParseDigest parses a canonical digest or fails the test.
func mustParseDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("ParseDigest(%q): %v", s, err)
	}
	return d
}

// writeConfigJSONArgs writes a config.json carrying both annotations and the
// container's effective process.args.
func writeConfigJSONArgs(t *testing.T, watchDir, cid string, annotations map[string]string, args []string) {
	t.Helper()
	dir := filepath.Join(watchDir, cid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ociSpec{Annotations: annotations, Process: &ociProcess{Args: args}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// exactEntrypointOverlay builds a workload overlay pinning wlDigest to an exact
// entrypoint (cmd unconstrained).
func exactEntrypointOverlay(t *testing.T, wlDigest string, entrypoint []string) *allowlistpkg.Allowlist {
	t.Helper()
	return &allowlistpkg.Allowlist{
		Schema: allowlistpkg.Schema,
		Workloads: map[string]allowlistpkg.Workload{
			"w": {Containers: []allowlistpkg.Container{{
				Digest:  mustParseDigest(t, wlDigest),
				Command: allowlistpkg.ArgvPolicy{Policy: allowlistpkg.PolicyExact, Argv: entrypoint},
				Args:    allowlistpkg.ArgvPolicy{Policy: allowlistpkg.PolicyAny},
			}}},
		},
	}
}

// writeConfigJSON synthesises an OCI spec config.json with the given
// annotations and writes it under <watchDir>/<cid>/config.json.
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

// newTestMonitor wires the monitor against tempdirs + fakes.
func newTestMonitor(t *testing.T, allowlistEntries []string) (*monitor, *fakeKiller, string) {
	t.Helper()
	watchDir := t.TempDir()

	allowlistDir := t.TempDir()
	allowlistPath := filepath.Join(allowlistDir, "allowlist.json")
	body, err := json.Marshal(bootstrapAllowlistFile{Sha256Digests: allowlistEntries})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allowlistPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	a, _, err := loadAllowlist(allowlistPath)
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}

	killer := &fakeKiller{}
	killer.ok = true

	logger, err := certutil.NewJSONLogger("debug")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	m := &monitor{
		cfg: &Config{
			AllowlistPath: allowlistPath,
			WatchDir:      watchDir,
			CgroupRoot:    "/sys/fs/cgroup",
			LogLevel:      "debug",
		},
		logger:                logger,
		allowlist:             a,
		overlay:               &policyOverlay{},
		killer:                killer,
		configReadDeadline:    200 * time.Millisecond,
		configReadInterval:    10 * time.Millisecond,
		configPendingInterval: 10 * time.Millisecond,
		killRetryDeadline:     50 * time.Millisecond,
		killRetryInterval:     time.Millisecond,
		killPendingInterval:   5 * time.Millisecond,
		// Far longer than any interval above, so only the tests that shorten it
		// exercise the escalation path.
		killEscalateAfter: time.Minute,
		fatal:             make(chan error, 1),
	}
	return m, killer, watchDir
}

func TestHandleNewContainer_AllowedDigest(t *testing.T) {
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})

	cid := testCID("allowed-digest")
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "container",
		"io.kubernetes.cri.image-name":     "ghcr.io/confidential-dot-ai/assam@sha256:" + digest,
	})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("unexpected kill calls: %+v", calls)
	}
}

// A baked floor digest is admitted regardless of the effective argv.
func TestHandleNewContainer_FloorDigestAdmitsAnyArgv(t *testing.T) {
	digest := strings.Repeat("a", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})

	cid := testCID("floor-weird-argv")
	writeConfigJSONArgs(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "container",
		"io.kubernetes.cri.image-name":     "ghcr.io/confidential-dot-ai/assam@sha256:" + digest,
	}, []string{"/bin/anything", "--wild"})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("floor digest should admit any argv, got kills: %+v", calls)
	}
}

// A workload digest (not on the floor) is admitted when the effective argv
// satisfies the overlay's entrypoint policy.
func TestHandleNewContainer_WorkloadArgvMatchAdmits(t *testing.T) {
	floor := strings.Repeat("a", 64)
	wl := strings.Repeat("b", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + floor})
	m.overlay.apply(exactEntrypointOverlay(t, "sha256:"+wl, []string{"/bin/app"}), 1)

	cid := testCID("wl-match")
	writeConfigJSONArgs(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "container",
		"io.kubernetes.cri.image-name":     "ghcr.io/tenant/app@sha256:" + wl,
	}, []string{"/bin/app", "--serve"})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("matching argv should admit workload digest, got kills: %+v", calls)
	}
}

// A workload digest whose effective argv violates the overlay policy is killed.
func TestHandleNewContainer_WorkloadArgvMismatchKills(t *testing.T) {
	floor := strings.Repeat("a", 64)
	wl := strings.Repeat("b", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + floor})
	m.overlay.apply(exactEntrypointOverlay(t, "sha256:"+wl, []string{"/bin/app"}), 1)

	cid := testCID("wl-mismatch")
	writeConfigJSONArgs(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "container",
		"io.kubernetes.cri.image-name":     "ghcr.io/tenant/app@sha256:" + wl,
	}, []string{"/bin/evil"})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	calls := killer.snapshot()
	if len(calls) != 1 || calls[0] != cid {
		t.Fatalf("non-matching argv should kill workload container, got: %+v", calls)
	}
}

// The overlay honors epoch anti-rollback: a lower version is ignored, so the
// argv policy applied at the higher version still governs.
func TestPolicyOverlayAntiRollback(t *testing.T) {
	wl := "sha256:" + strings.Repeat("b", 64)
	o := &policyOverlay{}
	if !o.apply(exactEntrypointOverlay(t, wl, []string{"/bin/app"}), 5) {
		t.Fatal("apply of version 5 rejected")
	}
	if o.apply(exactEntrypointOverlay(t, wl, []string{"/bin/other"}), 3) {
		t.Fatal("rolled-back version 3 was applied")
	}
	if o.version != 5 {
		t.Fatalf("version = %d, want 5 (rollback ignored)", o.version)
	}
	// The version-5 policy still governs: /bin/app matches, /bin/other does not.
	if !o.index().AdmitsContainer(wl, []string{"/bin/app"}) {
		t.Fatal("version-5 argv policy dropped by rollback attempt")
	}
	if o.index().AdmitsContainer(wl, []string{"/bin/other"}) {
		t.Fatal("rolled-back argv policy took effect")
	}
}

// Re-applying the same version is a no-op: only a strictly higher version may
// replace the installed policy, so a replayed pull can't swap in a different
// document at the current epoch.
func TestPolicyOverlayIgnoresEqualVersion(t *testing.T) {
	wl := "sha256:" + strings.Repeat("b", 64)
	o := &policyOverlay{}
	if !o.apply(exactEntrypointOverlay(t, wl, []string{"/bin/app"}), 5) {
		t.Fatal("first apply of version 5 rejected")
	}
	if o.apply(exactEntrypointOverlay(t, wl, []string{"/bin/other"}), 5) {
		t.Fatal("replayed version 5 was applied")
	}
	if !o.index().AdmitsContainer(wl, []string{"/bin/app"}) {
		t.Fatal("original version-5 policy dropped by equal-version replay")
	}
	if o.index().AdmitsContainer(wl, []string{"/bin/other"}) {
		t.Fatal("equal-version replay policy took effect")
	}
}

// A guest reboot / process restart is a fresh overlay (version 0), so it trusts
// the first pull whatever its version — even one below a prior lifetime's.
// Rollback protection is per-process-lifetime; state re-syncs from CDS.
func TestPolicyOverlayTrustsFirstVersionAfterRestart(t *testing.T) {
	wl := "sha256:" + strings.Repeat("b", 64)
	prior := &policyOverlay{}
	prior.apply(exactEntrypointOverlay(t, wl, []string{"/bin/app"}), 9)

	fresh := &policyOverlay{}
	if !fresh.apply(exactEntrypointOverlay(t, wl, []string{"/bin/other"}), 3) {
		t.Fatal("fresh overlay must trust the first version seen after a restart")
	}
	if fresh.version != 3 {
		t.Fatalf("version = %d, want 3", fresh.version)
	}
}

func TestHandleNewContainer_DeniedDigest(t *testing.T) {
	allowed := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	denied := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + allowed})

	cid := testCID("denied-digest")
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "container",
		"io.kubernetes.cri.image-name":     "ghcr.io/evil/badimage@sha256:" + denied,
	})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	calls := killer.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 kill, got %d: %+v", len(calls), calls)
	}
	if calls[0] != cid {
		t.Errorf("container ID = %q, want %q", calls[0], cid)
	}
}

func TestHandleNewContainer_NoDigestAnnotation_Denies(t *testing.T) {
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	cid := testCID("no-anno")
	writeConfigJSON(t, watchDir, cid, map[string]string{})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected deny+kill on missing annotation, got %d calls", len(calls))
	}
}

func TestHandleNewContainer_UnreadableConfigDenies(t *testing.T) {
	// config.json exists but cannot be read as a file (a directory in its
	// place): the bundle is clearly present but its digest is undeterminable,
	// so the monitor must fail closed (deny+kill) rather than let it run (H-01).
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	m.configReadDeadline = 50 * time.Millisecond
	cid := testCID("unreadable-config")
	dir := filepath.Join(watchDir, cid)
	if err := os.MkdirAll(filepath.Join(dir, "config.json"), 0o755); err != nil {
		t.Fatal(err)
	}

	m.handleNewContainer(context.Background(), dir)

	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected deny+kill on present-but-unreadable config.json, got %d calls: %+v", len(calls), calls)
	}
}

func TestKataOwnDirectoriesAreNotContainers(t *testing.T) {
	// /run/kata-containers/{shared,sandbox,image} are kata's own; they never
	// grow a config.json, so the watcher must not wait on one for a decision.
	// The baked policy refuses these as container ids, so nothing can hide here.
	m, _, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	for _, name := range []string{"shared", "sandbox", "image"} {
		if err := os.MkdirAll(filepath.Join(watchDir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if m.pathLooksLikeContainer(filepath.Join(watchDir, name)) {
			t.Errorf("%q treated as a container bundle", name)
		}
	}
}

func TestHandleNewContainer_MalformedConfigDenies(t *testing.T) {
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	m.configReadDeadline = 50 * time.Millisecond
	cid := testCID("bad-config")
	dir := filepath.Join(watchDir, cid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{ not valid json"), 0o644); err != nil {
		t.Fatal(err)
	}

	m.handleNewContainer(context.Background(), dir)

	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected deny+kill on malformed config.json, got %d calls: %+v", len(calls), calls)
	}
}

func TestHandleNewContainer_SandboxSkipped(t *testing.T) {
	// The pod sandbox (pause) container carries container-type=sandbox and
	// no image digest. kata runs the measured baked pause for it, so
	// policy-monitor must skip it rather than deny — otherwise every pod's
	// sandbox gets killed and no pod can start.
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	cid := testCID("sandbox0")
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "sandbox",
	})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("sandbox container should be skipped, got %d kill calls: %+v", len(calls), calls)
	}
}

func TestHandleNewContainer_SandboxSkippedEvenWithUnallowlistedDigest(t *testing.T) {
	// Safety property: a container marked as the sandbox is skipped even
	// when it also carries a non-allowlisted image digest. That's safe
	// because kata-agent runs the measured baked pause for any sandbox
	// regardless of the requested image, so a host that mislabels a
	// workload as a sandbox to dodge enforcement gains nothing — its image
	// never runs. policy-monitor identifies the sandbox the same way kata
	// does (isSandbox), keeping the two in lockstep.
	denied := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	cid := testCID("sandbox-evil")
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "sandbox",
		"io.kubernetes.cri.image-name":     "ghcr.io/evil/badimage@sha256:" + denied,
	})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("sandbox should be skipped even with a non-allowlisted digest, got %d kill calls: %+v", len(calls), calls)
	}
}

func TestHandleNewContainer_ConfigJSONAppearsLate(t *testing.T) {
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})

	cid := testCID("late-config")
	// Create only the directory; spawn a goroutine to drop config.json
	// in after a short delay (mirrors the kata-agent race between mkdir
	// and write).
	dir := filepath.Join(watchDir, cid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		body, _ := json.Marshal(ociSpec{
			Annotations: map[string]string{
				"io.kubernetes.cri.container-type": "container",
				"io.kubernetes.cri.image-name":     "ghcr.io/confidential-dot-ai/assam@sha256:" + digest,
			},
		})
		_ = os.WriteFile(filepath.Join(dir, "config.json"), body, 0o644)
	}()
	m.handleNewContainer(context.Background(), dir)
	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("expected allow (no kills) after late config.json, got %+v", calls)
	}
}

// A valid annotation-less spec is a complete policy input and must not wait
// for an attacker-controlled annotation to appear.
func TestReadConfigJSON_ValidAnnotationlessSpecReturnsImmediately(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	cid := testCID("annotationless")
	writeConfigJSON(t, watchDir, cid, map[string]string{"unrelated": "x"})
	m.configReadDeadline = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	spec, err := m.readConfigJSON(ctx, filepath.Join(watchDir, cid))
	if err != nil {
		t.Fatalf("readConfigJSON: %v", err)
	}
	if spec == nil || spec.Annotations["unrelated"] != "x" {
		t.Fatalf("got spec %+v, want complete annotationless spec", spec)
	}
}

func TestRun_DetectsCreatedContainer(t *testing.T) {
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	denied := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()

	// Give the watcher time to install.
	time.Sleep(50 * time.Millisecond)

	cid := testCID("live-deny")
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/evil/badimage@sha256:" + denied,
	})

	// Poll for the kill (the watcher dispatches to a goroutine, so
	// we don't have a synchronisation point; one second is generous).
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if killSeen(killer) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !killSeen(killer) {
		t.Fatal("denied container did not trigger SIGKILL via inotify event")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run returned err: %v", err)
	}
}

func killSeen(k *fakeKiller) bool {
	return len(k.snapshot()) > 0
}

// TestRun_SurvivesWatchDirReplacement reproduces what kata-agent's
// create_sandbox does to the watch dir at every first sandbox:
// remove_dir_all + create_dir_all (rpc.rs), which orphans an
// inode-bound inotify watch. The monitor must notice, re-establish the
// watch on the new inode, and still deny a non-allowlisted container
// created afterwards — this was the "silently inert enforcement" field
// failure.
func TestRun_SurvivesWatchDirReplacement(t *testing.T) {
	allowed := strings.Repeat("a", 64)
	denied := strings.Repeat("b", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + allowed})
	// Shrink the revalidation backstop so the test doesn't depend on
	// the Remove event being delivered (either recovery path must work).
	m.revalidateInterval = 25 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()

	// Give the first watch generation time to install.
	time.Sleep(50 * time.Millisecond)

	// kata-agent create_sandbox equivalent: replace the dir wholesale,
	// then immediately drop a bundle in — no pause, exactly like the
	// agent writing bundles right after create_dir_all.
	if err := os.RemoveAll(watchDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(watchDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfigJSON(t, watchDir, testCID("post-replace-deny"), map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/evil/badimage@sha256:" + denied,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if killSeen(killer) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !killSeen(killer) {
		t.Fatal("denied container created after watch-dir replacement was not killed — watch was not re-established")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run returned err: %v", err)
	}
}

func TestSeedExisting_DeniesPreexistingContainer(t *testing.T) {
	denied := strings.Repeat("b", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})

	// A container directory already present when the monitor starts (e.g.
	// systemd restarted policy-monitor while a workload was live).
	writeConfigJSON(t, watchDir, testCID("preexisting"), map[string]string{
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

func TestReadConfigJSON_ContextCancelled(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 5 * time.Second
	m.configReadInterval = 10 * time.Millisecond
	dir := filepath.Join(watchDir, testCID("pending"))
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
	dir := filepath.Join(watchDir, testCID("isadir"))
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

func TestMonitorRun_AllowedContainerNotKilled(t *testing.T) {
	digest := strings.Repeat("a", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()
	time.Sleep(50 * time.Millisecond)

	writeConfigJSON(t, watchDir, testCID("allowed-live"), map[string]string{
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

// run() creates a missing watch dir itself, as it must to re-establish the
// watch after kata-agent replaces the dir at sandbox creation, so "missing"
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

// kata-agent creating config.json between readConfigJSON's open and its
// follow-up Lstat must not read as a host-planted name. The loop below spins
// the poll hot across the write so the window is hit repeatedly: treating any
// Lstat-visible name as unresolvable denied a legitimate container here.
func TestHandleNewContainer_ConfigAppearingDuringPollIsNotDenied(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for i := 0; i < 20; i++ {
		m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})
		m.configReadInterval = 50 * time.Microsecond

		cid := testCID("poll-race")
		dir := filepath.Join(watchDir, cid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(ociSpec{
			Annotations: map[string]string{
				"io.kubernetes.cri.container-type": "container",
				"io.kubernetes.cri.image-name":     "ghcr.io/confidential-dot-ai/assam@sha256:" + digest,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			time.Sleep(20 * time.Millisecond)
			_ = os.WriteFile(filepath.Join(dir, "config.json"), body, 0o644)
		}()
		m.handleNewContainer(context.Background(), dir)

		if calls := killer.snapshot(); len(calls) != 0 {
			t.Fatalf("iteration %d: denied a container whose config.json appeared mid-poll, got %+v", i, calls)
		}
	}
}

func TestReadConfigJSON_BundleGoneGivesUp(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 20 * time.Millisecond
	m.configReadInterval = 5 * time.Millisecond
	m.configPendingInterval = 5 * time.Millisecond
	_, err := m.readConfigJSON(context.Background(), filepath.Join(watchDir, testCID("nope")))
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

	slowPullCID := testCID("slowpull")
	dir := filepath.Join(watchDir, slowPullCID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		writeConfigJSON(t, watchDir, slowPullCID, map[string]string{
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

// A symlink the host planted that resolves nowhere is a name that exists: the
// container has a bundle whose spec cannot be read, which is a deny, not a
// reason to keep waiting.
func TestReadConfigJSON_DanglingSymlinkIsUnrecoverable(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 20 * time.Millisecond
	m.configReadInterval = 5 * time.Millisecond
	m.configPendingInterval = 5 * time.Millisecond
	dir := filepath.Join(watchDir, testCID("dangling"))
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

// The bundle directory is created when the guest pull starts, so a container
// whose config.json has not landed yet is undecided, not admitted: the decision
// has to survive a pull longer than configReadDeadline.
func TestHandleNewContainer_SlowPullStillDenies(t *testing.T) {
	denied := strings.Repeat("b", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 20 * time.Millisecond
	m.configReadInterval = 5 * time.Millisecond
	m.configPendingInterval = 5 * time.Millisecond

	slowPullCID := testCID("slowpull")
	dir := filepath.Join(watchDir, slowPullCID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(120 * time.Millisecond)
		writeConfigJSON(t, watchDir, slowPullCID, map[string]string{
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

	dir := filepath.Join(watchDir, testCID("ghost"))
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
	taggedCID := testCID("tagged")
	writeConfigJSON(t, watchDir, taggedCID, map[string]string{
		"io.kubernetes.cri.image-name": "nginx:1.27-alpine",
	})
	m.handleNewContainer(context.Background(), filepath.Join(watchDir, taggedCID))
	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected a kill for a tag-form image reference, got %+v", calls)
	}
}

// The digest kata pulls is the one in image-name. A digest parked on image-id
// describes bytes the guest never fetches, so it must not admit anything.
func TestHandleNewContainer_AllowlistedImageIDDoesNotAdmit(t *testing.T) {
	allowed := strings.Repeat("a", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + allowed})
	spoofedCID := testCID("spoofed")
	writeConfigJSON(t, watchDir, spoofedCID, map[string]string{
		"io.kubernetes.cri.image-name": "attacker.example/evil:latest",
		"io.kubernetes.cri.image-id":   "sha256:" + allowed,
	})
	m.handleNewContainer(context.Background(), filepath.Join(watchDir, spoofedCID))
	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected a kill: the allowlisted digest is not the reference the guest pulls, got %+v", calls)
	}
}
