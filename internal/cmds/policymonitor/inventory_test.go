//go:build linux

package policymonitor

import (
	"bytes"
	"log/slog"
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
func TestResolveSandboxDigestsHostWithRetry_ExplicitHostSkipsRetry(t *testing.T) {
	prev := advertiseHostAttempts
	advertiseHostAttempts = 3
	t.Cleanup(func() { advertiseHostAttempts = prev })

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	got, err := resolveSandboxDigestsHostWithRetry(&Config{
		SandboxDigestsAdvertiseHost: "10.2.3.4",
		CDSURL:                      "https://cds.invalid:8443",
	}, logger)
	if err != nil || got != "10.2.3.4" {
		t.Fatalf("host = %q, err = %v; want 10.2.3.4 with no error", got, err)
	}
	if strings.Contains(buf.String(), "retrying") {
		t.Fatalf("explicit host should not retry; log:\n%s", buf.String())
	}
}

// A CDS URL that does not resolve exhausts the retry budget rather than
// latching tokens off on the first failure.
func TestResolveSandboxDigestsHostWithRetry_ExhaustsBudget(t *testing.T) {
	prevAttempts := advertiseHostAttempts
	prevBackoff := advertiseHostBackoff
	advertiseHostAttempts = 3
	advertiseHostBackoff = time.Millisecond
	t.Cleanup(func() {
		advertiseHostAttempts = prevAttempts
		advertiseHostBackoff = prevBackoff
	})

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	_, err := resolveSandboxDigestsHostWithRetry(&Config{
		CDSURL: "https://this.host.does.not.resolve.invalid:8443",
	}, logger)
	if err == nil {
		t.Fatal("want an error after retry budget exhausted")
	}
	// Every attempt but the last logs a retry line — proves we did not latch
	// off on the first failure the way the old code did.
	if got := strings.Count(buf.String(), `"msg":"advertise-host inference failed; retrying"`); got != advertiseHostAttempts-1 {
		t.Fatalf("got %d retry log lines, want %d; log:\n%s", got, advertiseHostAttempts-1, buf.String())
	}
}
