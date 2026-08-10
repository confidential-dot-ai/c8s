//go:build linux

package policymonitor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	pmDigestApp     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pmDigestSidecar = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	pmSandboxID     = "8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f"
)

// The sandbox inventory reports every recorded container, injected sidecars
// included: it answers what runs in the sandbox, and CDS drops the injected
// images itself (they are allowlist floor entries).
func TestKataInventoryIncludesInjectedSidecars(t *testing.T) {
	b := newAdmissionInventory()
	b.recordSandboxID(pmSandboxID)
	b.record(testCID("app"), pmDigestApp, nil)
	b.record(testCID("cert"), pmDigestSidecar, nil)

	digests, _, known, err := b.DigestsForSandbox(pmSandboxID)
	if err != nil || !known {
		t.Fatalf("known=%v err=%v", known, err)
	}
	want := []string{pmDigestSidecar, pmDigestApp}
	slices.Sort(want)
	if !slices.Equal(digests, want) {
		t.Fatalf("inventory = %v, want %v (sidecar included)", digests, want)
	}
}

// The guest holds one pod: only its own sandbox ID is known, the first
// observed ID wins, and a token request before any container is observed
// fails closed.
func TestKataInventorySandboxIdentity(t *testing.T) {
	b := newAdmissionInventory()

	if _, err := b.SandboxForPeer(workloadclaims.PeerForPID(0)); err == nil {
		t.Fatal("sandbox resolved before any container was observed")
	}
	if _, _, known, _ := b.DigestsForSandbox(pmSandboxID); known {
		t.Fatal("sandbox known before any container was observed")
	}

	b.recordSandboxID(pmSandboxID)
	b.recordSandboxID("some-other-id") // can't happen in a one-pod guest; first wins
	got, err := b.SandboxForPeer(workloadclaims.PeerForPID(0))
	if err != nil || got != pmSandboxID {
		t.Fatalf("sandbox = %q, %v; want %q", got, err, pmSandboxID)
	}
	if _, _, known, _ := b.DigestsForSandbox("some-other-id"); known {
		t.Fatal("foreign sandbox ID answered")
	}
	if digests, _, known, err := b.DigestsForSandbox(pmSandboxID); err != nil || !known || len(digests) != 0 {
		t.Fatalf("own sandbox: digests=%v known=%v err=%v, want empty inventory", digests, known, err)
	}
}

func TestSandboxIDFromAnnotations(t *testing.T) {
	if got := sandboxIDFromAnnotations(map[string]string{"io.kubernetes.cri.sandbox-id": pmSandboxID}); got != pmSandboxID {
		t.Fatalf("containerd key: got %q", got)
	}
	if got := sandboxIDFromAnnotations(map[string]string{"io.kubernetes.cri-o.SandboxID": pmSandboxID}); got != pmSandboxID {
		t.Fatalf("cri-o key: got %q", got)
	}
	if got := sandboxIDFromAnnotations(map[string]string{}); got != "" {
		t.Fatalf("no key: got %q", got)
	}
}

// A container whose bundle kata-agent tore down stays in the guest's admission
// record: /digests reports everything the guest ever ran, so a pod cannot hide
// a container by arranging for it to be absent when asked (docs/secrets.md).
func TestKataInventoryRemoveKeepsAdmissionRecord(t *testing.T) {
	b := newAdmissionInventory()
	b.recordSandboxID(pmSandboxID)
	b.record(testCID("app"), pmDigestApp, nil)
	b.record(testCID("gone"), pmDigestSidecar, nil)

	b.remove(testCID("gone"))

	digests, _, known, err := b.DigestsForSandbox(pmSandboxID)
	if err != nil || !known {
		t.Fatalf("known=%v err=%v", known, err)
	}
	want := []string{pmDigestApp, pmDigestSidecar}
	slices.Sort(want)
	if !slices.Equal(digests, want) {
		t.Fatalf("digests = %v, want the removed container still recorded (%v)", digests, want)
	}
}

// The advertise host CDS dials back: explicit config wins, and a host it could
// never reach is rejected where it is configured rather than at issuance.
func TestSandboxDigestsHost(t *testing.T) {
	got, err := sandboxDigestsHost(&Config{
		SandboxDigestsAdvertiseHost: "10.2.3.4",
		CDSURL:                      "https://cds.invalid:8443",
	})
	if err != nil || got != "10.2.3.4" {
		t.Fatalf("host = %q, err = %v; want 10.2.3.4", got, err)
	}
	if _, err := sandboxDigestsHost(&Config{
		SandboxDigestsAdvertiseHost: "127.0.0.1",
		CDSURL:                      "https://cds.invalid:8443",
	}); err == nil {
		t.Fatal("loopback accepted as an advertise host")
	}
}

// The guest inventory keys its high-water mark the same way, and must not lose
// an admission to a separator byte in argv either.
func TestKataInventoryArgvSeparatorDoesNotEraseAdmissions(t *testing.T) {
	b := newAdmissionInventory()
	b.recordSandboxID(pmSandboxID)
	b.record(testCID("a"), pmDigestApp, []string{"/app\x1f--serve"})
	b.record(testCID("b"), pmDigestApp, []string{"/app", "--serve"})

	_, containers, known, err := b.DigestsForSandbox(pmSandboxID)
	if err != nil || !known {
		t.Fatalf("known=%v err=%v", known, err)
	}
	if len(containers) != 2 {
		t.Fatalf("containers = %+v, want both admissions recorded", containers)
	}
}

// A configured advertise host bypasses retry entirely: the routing-table
// lookup never happens, so the CDS URL not resolving does not matter.
func TestResolveSandboxDigestsHostLate_ExplicitHostSkipsRetry(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	got, err := resolveSandboxDigestsHostLate(context.Background(), &Config{
		SandboxDigestsAdvertiseHost: "10.2.3.4",
		CDSURL:                      "https://cds.invalid:8443",
	}, logger, sandboxDigestsHost)
	if err != nil || got != "10.2.3.4" {
		t.Fatalf("host = %q, err = %v; want 10.2.3.4 with no error", got, err)
	}
	if strings.Contains(buf.String(), "retrying") {
		t.Fatalf("explicit host should not retry; log:\n%s", buf.String())
	}
}

// failingLookup fails every inference attempt instantly, so a test's retry
// count follows from the budget rather than from resolver latency.
func failingLookup(*Config) (string, error) {
	return "", errors.New("no route to the CDS host")
}

func shortAdvertiseHostWait(t *testing.T, budget, interval time.Duration) {
	t.Helper()
	prevBudget, prevInterval := advertiseHostLateBudget, advertiseHostRetryInterval
	advertiseHostLateBudget, advertiseHostRetryInterval = budget, interval
	t.Cleanup(func() { advertiseHostLateBudget, advertiseHostRetryInterval = prevBudget, prevInterval })
}

// A lookup that keeps failing keeps retrying to the budget rather than latching
// tokens off on the first failure — the whole point of running late is that the
// network arrives after the first attempt.
//
// The lookup is stubbed rather than pointed at an unresolvable host: a real
// resolver makes each attempt cost whatever the runner's DNS takes, so the
// retries a millisecond budget affords vary by machine (CI saw one). The
// budget dwarfs the interval for the same reason: a scheduler stall must not
// eat every retry. That an unresolvable CDS URL fails at all is covered by
// _StopsAtBudget.
func TestResolveSandboxDigestsHostLate_RetriesUntilBudget(t *testing.T) {
	shortAdvertiseHostWait(t, 250*time.Millisecond, time.Millisecond)

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	_, err := resolveSandboxDigestsHostLate(context.Background(), &Config{}, logger, failingLookup)
	if err == nil {
		t.Fatal("want an error after the budget is exhausted")
	}
	if got := strings.Count(buf.String(), `"msg":"advertise-host inference failed; retrying"`); got < 2 {
		t.Fatalf("got %d retry log lines, want repeated retries; log:\n%s", got, buf.String())
	}
}

// The budget bounds the wait: a guest that never gets a network must reach
// "no signer" rather than hold every fetcher open indefinitely.
func TestResolveSandboxDigestsHostLate_StopsAtBudget(t *testing.T) {
	shortAdvertiseHostWait(t, 50*time.Millisecond, 5*time.Millisecond)

	start := time.Now()
	_, err := resolveSandboxDigestsHostLate(context.Background(), &Config{},
		slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), failingLookup)
	if err == nil {
		t.Fatal("want an error after the budget is exhausted")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("ran for %s, want the %s budget to stop it", elapsed, advertiseHostLateBudget)
	}
}

// A cancelled context stops the wait, so guest shutdown is not held up by a
// lookup that will never succeed.
func TestResolveSandboxDigestsHostLate_StopsOnContextCancel(t *testing.T) {
	shortAdvertiseHostWait(t, time.Hour, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := resolveSandboxDigestsHostLate(ctx, &Config{},
		slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), failingLookup); err == nil {
		t.Fatal("want an error when the context ends")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("ran for %s after cancellation", elapsed)
	}
}

// Replaces TestAdvertiseHostBudgetFitsUnitStartTimeout, which pinned this
// lookup UNDER the unit's start timeout because it ran before READY=1. It now
// runs after, so the budget is deliberately longer - and that is only safe
// while it stays off the startup path. If the lookup is ever moved back,
// systemd fails the unit at TimeoutStartSec and FailureAction=poweroff-force
// kills the guest, which is #258 all over again.
func TestAdvertiseHostRunsOffTheStartupPath(t *testing.T) {
	unit := filepath.Join("..", "..", "..", "kata-guest-base", "extra", "etc", "systemd", "system", "policy-monitor.service")
	raw, err := os.ReadFile(unit)
	if err != nil {
		t.Fatalf("read %s: %v", unit, err)
	}
	m := regexp.MustCompile(`(?m)^TimeoutStartSec=(\S+)$`).FindSubmatch(raw)
	if m == nil {
		t.Fatalf("no TimeoutStartSec= in %s; if the unit no longer bounds startup, this test needs rewriting rather than deleting", unit)
	}
	timeout, err := time.ParseDuration(string(m[1]))
	if err != nil {
		t.Fatalf("parse TimeoutStartSec=%q: %v", m[1], err)
	}

	if advertiseHostLateBudget <= timeout {
		t.Fatalf("advertiseHostLateBudget = %s fits inside TimeoutStartSec=%s; either the lookup moved back onto "+
			"the startup path, or the budget shrank to where waiting for the pod network no longer works",
			advertiseHostLateBudget, timeout)
	}
}
