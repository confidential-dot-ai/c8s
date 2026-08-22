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
	// The additive floor still grows: a floor digest, once seen, is never dropped.
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

func TestRunAllowlistRefresh_InvalidMeasurements(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	a := newSeededAllowlist(t, seed)
	cfg := &Config{
		CDSURL:          "https://cds.example",
		CDSMeasurements: "not-valid-hex!!",
		RefreshInterval: time.Second,
	}
	// Returns promptly (refresh disabled) and never touches the network.
	state := &refreshState{}
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
	state := &refreshState{}
	runAllowlistRefresh(context.Background(), testLogger(t), cfg, a, &policyOverlay{}, state)
	if a.Size() != 1 {
		t.Fatalf("size = %d, want 1", a.Size())
	}
}

// A malformed RTMR pin disables refresh the same way a malformed measurement
// does: the baked seed keeps enforcing, nothing is silently unpinned.
func TestRunAllowlistRefresh_InvalidRTMRs(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	a := newSeededAllowlist(t, seed)
	cfg := &Config{
		CDSURL:          "https://cds.example",
		CDSMeasurements: strings.Repeat("ab", 48),
		CDSRTMRs:        "0=" + strings.Repeat("cd", 48),
		RefreshInterval: time.Second,
	}
	state := &refreshState{}
	runAllowlistRefresh(context.Background(), testLogger(t), cfg, a, &policyOverlay{}, state)
	if a.Size() != 1 {
		t.Fatalf("size = %d, want 1 (seed unchanged)", a.Size())
	}
	if got := state.frozenReason(); got != reasonBadMeasurements {
		t.Fatalf("frozenReason = %q, want %q", got, reasonBadMeasurements)
	}
}
