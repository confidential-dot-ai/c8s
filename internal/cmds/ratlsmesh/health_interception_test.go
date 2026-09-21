//go:build linux

package ratlsmesh

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHostHealthInterceptionReadiness(t *testing.T) {
	now := time.Now().UnixNano()
	stale := time.Now().Add(-2 * time.Minute).UnixNano()
	future := time.Now().Add(time.Minute).UnixNano()
	for _, tc := range []struct {
		name      string
		published int64
		read      int64
		pods      int64
		packets   int64
		want      int
	}{
		{"observed interception", now, now, 2, 1, http.StatusOK},
		{"no pods", now, now, 0, 0, http.StatusOK},
		{"unproven interception", now, now, 2, 0, http.StatusServiceUnavailable},
		{"failed counter read", now, 0, 2, 1, http.StatusServiceUnavailable},
		{"stale counter read", now, stale, 2, 1, http.StatusServiceUnavailable},
		{"stale snapshot", stale, now, 2, 1, http.StatusServiceUnavailable},
		{"missing snapshot timestamp", 0, now, 2, 1, http.StatusServiceUnavailable},
		{"future snapshot", future, now, 2, 1, http.StatusServiceUnavailable},
		{"future counter read", now, future, 2, 1, http.StatusServiceUnavailable},
		{"no pods but failed read", now, 0, 0, 0, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "metrics.json")
			snapshot := iptablesMetricsSnapshot{
				UpdatedAtUnixNano: tc.published, InterceptionCountersReadAtUnixNano: tc.read,
				InterceptionEvidenceMaxAgeNano: int64(90 * time.Second),
				IPv4Interception:               interceptionFamilySnapshot{PodIPSetMembers: tc.pods, PreroutingInterceptedPackets: tc.packets},
			}
			if err := writeIptablesMetricsFile(path, snapshot); err != nil {
				t.Fatal(err)
			}
			h := configuredHostHealth(t, path)
			assertHealthStatus(t, h, "/ready", tc.want)
			assertHealthStatus(t, h, "/live", http.StatusOK)
		})
	}
}

func TestHostHealthInterceptionEvidenceLost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	h := configuredHostHealth(t, path)
	assertHealthStatus(t, h, "/ready", http.StatusServiceUnavailable)
	snapshot := iptablesMetricsSnapshot{
		UpdatedAtUnixNano: time.Now().UnixNano(), InterceptionCountersReadAtUnixNano: time.Now().UnixNano(),
		InterceptionEvidenceMaxAgeNano: int64(90 * time.Second),
		IPv4Interception:               interceptionFamilySnapshot{PodIPSetMembers: 2, PreroutingInterceptedPackets: 1},
	}
	if err := writeIptablesMetricsFile(path, snapshot); err != nil {
		t.Fatal(err)
	}
	assertHealthStatus(t, h, "/ready", http.StatusOK)
	if err := os.WriteFile(path, []byte("invalid JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertHealthStatus(t, h, "/ready", http.StatusServiceUnavailable)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	assertHealthStatus(t, h, "/ready", http.StatusServiceUnavailable)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	assertHealthStatus(t, h, "/ready", http.StatusServiceUnavailable)
	assertHealthStatus(t, h, "/live", http.StatusOK)
}

func TestHostHealthInterceptionRequiresEveryPopulatedFamily(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	h := configuredHostHealth(t, path)
	snapshot := iptablesMetricsSnapshot{
		UpdatedAtUnixNano: time.Now().UnixNano(), InterceptionCountersReadAtUnixNano: time.Now().UnixNano(),
		InterceptionEvidenceMaxAgeNano: int64(90 * time.Second),
		PodIPSetMembers:                4, PreroutingInterceptedPackets: 1,
		IPv4Interception: interceptionFamilySnapshot{PodIPSetMembers: 2, PreroutingInterceptedPackets: 1},
		IPv6Interception: interceptionFamilySnapshot{PodIPSetMembers: 2},
	}
	if err := writeIptablesMetricsFile(path, snapshot); err != nil {
		t.Fatal(err)
	}
	assertHealthStatus(t, h, "/ready", http.StatusServiceUnavailable)
	snapshot.IPv6Interception.PreroutingInterceptedPackets = 1
	if err := writeIptablesMetricsFile(path, snapshot); err != nil {
		t.Fatal(err)
	}
	assertHealthStatus(t, h, "/ready", http.StatusOK)
	snapshot.IPv4Interception.PreroutingInterceptedPackets = 0
	if err := writeIptablesMetricsFile(path, snapshot); err != nil {
		t.Fatal(err)
	}
	assertHealthStatus(t, h, "/ready", http.StatusServiceUnavailable)
}

func TestHostHealthInterceptionFreshnessUsesSyncCadence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	h := configuredHostHealth(t, path)
	snapshot := iptablesMetricsSnapshot{
		UpdatedAtUnixNano:                  time.Now().UnixNano(),
		InterceptionCountersReadAtUnixNano: time.Now().Add(-2 * time.Minute).UnixNano(),
		IPv4Interception:                   interceptionFamilySnapshot{PodIPSetMembers: 2, PreroutingInterceptedPackets: 1},
	}
	for _, tc := range []struct {
		maximumAge time.Duration
		want       int
	}{
		{9 * time.Minute, http.StatusOK},
		{90 * time.Second, http.StatusServiceUnavailable},
		{0, http.StatusServiceUnavailable},
		{-time.Second, http.StatusServiceUnavailable},
	} {
		snapshot.InterceptionEvidenceMaxAgeNano = int64(tc.maximumAge)
		if err := writeIptablesMetricsFile(path, snapshot); err != nil {
			t.Fatal(err)
		}
		assertHealthStatus(t, h, "/ready", tc.want)
	}
}

func TestHostHealthInterceptionExplicitlyDisabled(t *testing.T) {
	h := configuredHostHealth(t, "")
	assertHealthStatus(t, h, "/ready", http.StatusOK)
}

func configuredHostHealth(t *testing.T, path string) *healthServer {
	t.Helper()
	cfg := defaultTestProxyConfig(t)
	cfg.iptablesMetricsFile = path
	r := &meshRuntime{metrics: testMetrics()}
	hostMesh{c: cfg}.configure(r)
	r.health.ready.Store(true)
	return r.health
}

func assertHealthStatus(t *testing.T, h *healthServer, path string, want int) {
	t.Helper()
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	if w.Code != want {
		t.Fatalf("GET %s = %d (%s), want %d", path, w.Code, w.Body.String(), want)
	}
}
