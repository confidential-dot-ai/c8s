package nriimagepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
)

// writeConfigYAML writes a config file and returns its path.
func writeConfigYAML(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image-policy.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// runWithDeadline runs Run in a goroutine and fails the test if it does not
// return within timeout.
func runWithDeadline(t *testing.T, timeout time.Duration, args []string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- Run(args) }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		t.Fatal("Run did not return within the deadline")
		return nil
	}
}

// baseConfigYAML is a minimal valid config: static floor only, a containerd
// socket nobody listens on (resolution is lazy), and a health server on a
// private unix socket. In the test environment the NRI socket does not exist,
// so a full Run always ends with the plugin failing to register.
func baseConfigYAML(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return fmt.Sprintf(`
plugin:
  health_addr: unix://%s/health.sock
containerd:
  socket: %s/ctr.sock
allowlist:
  always_allow:
    "%s": image-a
policy:
  mode: fail-closed
  enforce_existing: false
logging:
  level: error
`, dir, dir, pushDigestA)
}

// --- Run: startup plumbing --------------------------------------------------

func TestRun_MissingConfigFileErrors(t *testing.T) {
	err := runWithDeadline(t, 10*time.Second, []string{
		"-config", filepath.Join(t.TempDir(), "absent.yaml"),
	})
	if err == nil || !strings.Contains(err.Error(), "load config") {
		t.Fatalf("err = %v, want a load-config failure", err)
	}
}

// A valid config carries Run all the way to the NRI registration, whose
// failure (no NRI socket here) must surface as the plugin error, proving no
// earlier startup step misreported success as failure.
func TestRun_NRIConnectFailureSurfacesAsPluginError(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	err := runWithDeadline(t, 15*time.Second, []string{
		"-config", writeConfigYAML(t, baseConfigYAML(t)),
	})
	if err == nil || !strings.HasPrefix(err.Error(), "plugin: ") {
		t.Fatalf("err = %v, want the NRI plugin run failure", err)
	}
}

// The config file's health_addr must win over the flag default: an invalid
// config address has to fail the health server start rather than being
// silently ignored in favor of the flag.
func TestRun_ConfigHealthAddrOverridesFlagDefault(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	dir := t.TempDir()
	cfgYAML := fmt.Sprintf(`
plugin:
  health_addr: "###not-an-addr###"
containerd:
  socket: %s/ctr.sock
allowlist:
  always_allow:
    "%s": image-a
policy:
  mode: fail-closed
  enforce_existing: false
logging:
  level: error
`, dir, pushDigestA)
	err := runWithDeadline(t, 10*time.Second, []string{"-config", writeConfigYAML(t, cfgYAML)})
	if err == nil || !strings.Contains(err.Error(), "start health server") {
		t.Fatalf("err = %v, want a health server start failure on the config address", err)
	}
}

// With workload_claims configured, a broker that cannot listen must fail Run:
// continuing without it would leave every get-cert fetch unanswered.
func TestRun_WorkloadClaimsListenFailureSurfaces(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	dir := t.TempDir()
	cfgYAML := fmt.Sprintf(`
plugin:
  health_addr: unix://%s/health.sock
containerd:
  socket: %s/ctr.sock
allowlist:
  always_allow:
    "%s": image-a
policy:
  mode: fail-closed
  enforce_existing: false
workload_claims:
  socket_dir: %s/absent/deeper
logging:
  level: error
`, dir, dir, pushDigestA, dir)
	err := runWithDeadline(t, 10*time.Second, []string{"-config", writeConfigYAML(t, cfgYAML)})
	if err == nil || !strings.Contains(err.Error(), "start workload-claims broker") {
		t.Fatalf("err = %v, want a workload-claims broker start failure", err)
	}
}

// A plugin death during the initial pull is fatal (errPluginDied), not a
// degrade-to-floor condition.
func TestRun_PluginDeathDuringInitialPullIsFatal(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	origDelay, origRetries := allowlistApiInitialDelay, allowlistApiMaxRetries
	allowlistApiInitialDelay = 5 * time.Millisecond
	// Keep retrying until the plugin death is observed; each fetch attempt
	// fails instantly against the closed port.
	allowlistApiMaxRetries = 1000
	defer func() {
		allowlistApiInitialDelay, allowlistApiMaxRetries = origDelay, origRetries
	}()

	dir := t.TempDir()
	cfgYAML := fmt.Sprintf(`
plugin:
  health_addr: unix://%s/health.sock
containerd:
  socket: %s/ctr.sock
allowlist:
  always_allow:
    "%s": image-a
  pull:
    url: https://127.0.0.1:1/
    attestation_api_url: http://127.0.0.1:1
    cds_measurements: ["%s"]
policy:
  mode: fail-closed
  enforce_existing: false
logging:
  level: error
`, dir, dir, pushDigestA, strings.Repeat("ab", 48))
	err := runWithDeadline(t, 20*time.Second, []string{"-config", writeConfigYAML(t, cfgYAML)})
	if !errors.Is(err, errPluginDied) {
		t.Fatalf("err = %v, want errPluginDied", err)
	}
}

// --- allowlistPullHTTPClient ------------------------------------------------

func TestAllowlistPullHTTPClient_ValidMeasurements(t *testing.T) {
	timeout := 7 * time.Second
	client, err := allowlistPullHTTPClient(pullConfig{
		CDSMeasurements:   []string{strings.Repeat("ab", 48)},
		AttestationApiURL: "http://127.0.0.1:30840",
		Timeout:           timeout,
	})
	if err != nil {
		t.Fatalf("allowlistPullHTTPClient: %v", err)
	}
	if client == nil || client.Timeout != timeout {
		t.Fatalf("client = %+v, want non-nil with Timeout %v", client, timeout)
	}
}

// The accept-any-measurement warning is a security signal: it must fire
// exactly when no measurement is pinned.
func TestAllowlistPullHTTPClient_WarnsOnlyWithoutPins(t *testing.T) {
	const warning = "accepts any RA-TLS-attested CDS measurement"
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(orig)

	if _, err := allowlistPullHTTPClient(pullConfig{
		CDSMeasurements:   []string{strings.Repeat("ab", 48)},
		AttestationApiURL: "http://127.0.0.1:30840",
		Timeout:           time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), warning) {
		t.Fatal("pinned measurements must not warn about accepting any measurement")
	}

	buf.Reset()
	if _, err := allowlistPullHTTPClient(pullConfig{
		AttestationApiURL: "http://127.0.0.1:30840",
		Timeout:           time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), warning) {
		t.Fatal("missing warning when no measurements are pinned")
	}
}

// --- pullInitial backoff ----------------------------------------------------

// Failed attempts must be separated by the configured startup backoff; a zero
// gap would hammer CDS on every cold boot across the fleet.
func TestPullInitial_BacksOffBetweenAttempts(t *testing.T) {
	origRetries := allowlistApiMaxRetries
	allowlistApiMaxRetries = 2
	defer func() { allowlistApiMaxRetries = origRetries }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: time.Second})
	store := newPolicyStore(floorAllowlist(map[string]string{}))

	start := time.Now()
	_, err := pullInitial(context.Background(), pullArgs{
		client:      client,
		store:       store,
		timeout:     time.Second,
		pluginErrCh: make(chan error, 1),
		logger:      discardLogger(),
	})
	if err == nil {
		t.Fatal("expected failure from a 5xx CDS")
	}
	// One inter-attempt gap at the default 2s backoff (with slack).
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond {
		t.Fatalf("attempts not separated by the startup backoff: elapsed %v", elapsed)
	}
}

// --- newPlugin: workload-claims wiring ---------------------------------------

func TestNewPlugin_WorkloadClaimsWiring(t *testing.T) {
	t.Setenv("NRI_PLUGIN_NAME", "")
	store := newPolicyStore(floorAllowlist(map[string]string{}))
	for _, tc := range []struct {
		name         string
		socketDir    string
		procRoot     string
		wantBroker   bool
		wantProcRoot string
	}{
		{"broker disabled without socket dir", "", "", false, ""},
		{"default proc root", "/run/c8s", "", true, "/proc"},
		{"explicit proc root", "/run/c8s", "/hostproc", true, "/hostproc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config{
				Policy:         policyConfig{Mode: ModeFailClosed},
				WorkloadClaims: workloadClaimsConfig{SocketDir: tc.socketDir, ProcRoot: tc.procRoot},
			}
			p, err := newPlugin(cfg, &ctrdresolver.Resolver{}, store, audit.NewLogger(), discardLogger())
			if err != nil {
				t.Fatalf("newPlugin: %v", err)
			}
			if (p.broker != nil) != tc.wantBroker {
				t.Fatalf("broker configured = %v, want %v", p.broker != nil, tc.wantBroker)
			}
			if tc.wantBroker && p.broker.procRoot != tc.wantProcRoot {
				t.Fatalf("procRoot = %q, want %q", p.broker.procRoot, tc.wantProcRoot)
			}
		})
	}
}

// --- checkExisting: enforcement accounting -----------------------------------

// The completion summary is the operator's record of startup enforcement:
// a kill that could not be delivered must count as failed, not killed.
func TestCheckExisting_CountsFailedKill(t *testing.T) {
	p, _ := newCachedPlugin(&config{
		Allowlist: allowlistConfig{AlwaysAllow: map[string]string{pushDigestA: "image-a"}},
		Policy:    policyConfig{Mode: ModeFailClosed, EnforceExisting: true},
	}, &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-a"}})
	p.resolver = deadResolver(t)
	var buf bytes.Buffer
	p.logger = slog.New(slog.NewJSONHandler(&buf, nil))
	p.SetReady()

	pod := makePod("default", "pod1")
	denied := makeCtrWithImage(pod.Id, "ctr1", "registry/repo@"+pushDigestB)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := p.Synchronize(ctx, []*api.PodSandbox{pod}, []*api.Container{denied}); err != nil {
		t.Fatalf("Synchronize: %v", err)
	}

	type summaryRecord struct {
		Msg    string `json:"msg"`
		Killed int    `json:"killed"`
		Failed int    `json:"failed"`
	}
	var summary *summaryRecord
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec summaryRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec.Msg == "existing-container check complete" {
			summary = &rec
		}
	}
	if summary == nil {
		t.Fatal("completion summary not logged")
	}
	if summary.Killed != 0 || summary.Failed != 1 {
		t.Fatalf("killed=%d failed=%d, want killed=0 failed=1 for an undeliverable kill",
			summary.Killed, summary.Failed)
	}
}
