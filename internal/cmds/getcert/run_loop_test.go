package getcert

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// capturedRecord is one captured slog record: message plus resolved attrs.
type capturedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]slog.Value
}

// logCapture is a slog.Handler that stores records and wakes waiters, so tests
// can wait for a specific message without polling or sleeping.
type logCapture struct {
	mu      sync.Mutex
	records []capturedRecord
	arrived chan struct{}
}

func newLogCapture() *logCapture {
	return &logCapture{arrived: make(chan struct{}, 1)}
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{level: r.Level, msg: r.Message, attrs: map[string]slog.Value{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.Resolve()
		return true
	})
	c.mu.Lock()
	c.records = append(c.records, rec)
	c.mu.Unlock()
	select {
	case c.arrived <- struct{}{}:
	default:
	}
	return nil
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

func (c *logCapture) find(msg string) (capturedRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rec := range c.records {
		if rec.msg == msg {
			return rec, true
		}
	}
	return capturedRecord{}, false
}

func (c *logCapture) waitFor(t *testing.T, msg string) capturedRecord {
	t.Helper()
	deadline := time.After(15 * time.Second)
	for {
		if rec, ok := c.find(msg); ok {
			return rec
		}
		select {
		case <-c.arrived:
		case <-deadline:
			t.Fatalf("log message %q never appeared", msg)
		}
	}
}

// captureDefaultLogger swaps the process default logger for a capture handler
// and restores it on cleanup.
func captureDefaultLogger(t *testing.T) *logCapture {
	t.Helper()
	c := newLogCapture()
	old := slog.Default()
	slog.SetDefault(slog.New(c))
	t.Cleanup(func() { slog.SetDefault(old) })
	return c
}

// holdSIGTERM keeps a test-side SIGTERM subscription for the test's lifetime,
// so signalling the process can never hit the default terminate action.
func holdSIGTERM(t *testing.T) {
	t.Helper()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM)
	t.Cleanup(func() { signal.Stop(ch) })
}

// unreachableRenewalConfig is a config whose certificate requests always fail
// fast (nothing listens on port 1) but whose validation passes, carrying run
// into the renewal loop via continue-on-initial-error.
func unreachableRenewalConfig() config {
	return config{
		CDSURL:                 "https://127.0.0.1:1",
		AttestationApiURL:      "http://127.0.0.1:1",
		SAN:                    "host.example.com",
		InitialRetryTimeout:    0,
		ContinueOnInitialError: true,
		RenewInterval:          time.Hour,
	}
}

func terminateRun(t *testing.T, done <-chan error) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v, want nil on graceful shutdown", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not shut down after SIGTERM")
	}
}

func TestCDSHTTPClientWarnsOnlyWithoutMeasurements(t *testing.T) {
	base := config{CDSURL: "https://cds:8443", AttestationApiURL: "http://attestation-api:8400"}
	const warnMsg = "--cds-measurements not set; get-cert accepts any RA-TLS-attested CDS measurement"

	t.Run("unpinned warns", func(t *testing.T) {
		c := captureDefaultLogger(t)
		if _, err := cdsHTTPClient(base); err != nil {
			t.Fatalf("cdsHTTPClient: %v", err)
		}
		if _, ok := c.find(warnMsg); !ok {
			t.Fatal("no warning logged for an unpinned CDS measurement set")
		}
	})

	t.Run("pinned does not warn", func(t *testing.T) {
		c := captureDefaultLogger(t)
		cfg := base
		cfg.CDSMeasurements = strings.Repeat("ab", 48)
		if _, err := cdsHTTPClient(cfg); err != nil {
			t.Fatalf("cdsHTTPClient: %v", err)
		}
		if _, ok := c.find(warnMsg); ok {
			t.Fatal("warning logged despite pinned measurements")
		}
	})
}

// The request log reports whether a sandbox token is bound; the token-free
// flow must report false.
func TestObtainCertLogsTokenFreeRequest(t *testing.T) {
	c := captureDefaultLogger(t)
	chain := testIssuedChainPEM(t)
	cdsURL, attURL := startFakeServers(t, chain)

	cfg := config{
		CDSURL:            cdsURL,
		AttestationApiURL: attURL,
		SAN:               "host.example.com",
		OutPath:           filepath.Join(t.TempDir(), "cert.pem"),
	}
	if _, err := obtainCert(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL)); err != nil {
		t.Fatalf("obtainCert: %v", err)
	}

	rec, ok := c.find("requesting certificate from cds")
	if !ok {
		t.Fatal("request log record missing")
	}
	v, ok := rec.attrs["sandbox_token"]
	if !ok || v.Kind() != slog.KindBool {
		t.Fatalf("sandbox_token attr = %v, want a bool", v)
	}
	if v.Bool() {
		t.Fatal("sandbox_token = true for a token-free request, want false")
	}
}

// With no certificate installed a failed tick is the first request still
// failing, not a renewal, and it re-asks on the initial-retry backoff.
func TestRunRenewalLoopLogsFailedInitialRequest(t *testing.T) {
	holdSIGTERM(t)
	c := captureDefaultLogger(t)

	cfg := unreachableRenewalConfig()
	cfg.InitialRetryInterval = 5 * time.Millisecond
	cfg.ReloadNginx = false

	done := make(chan error, 1)
	go func() { done <- run(cfg) }()

	// --renew-interval is an hour here, so this record can only have come from
	// the initial-retry backoff.
	c.waitFor(t, "certificate request failed, still no certificate")
	terminateRun(t, done)
}

// A failing renewal tick logs and retries instead of being treated as success.
func TestRenewLoopLogsFailedRenewal(t *testing.T) {
	c := captureDefaultLogger(t)

	cfg := unreachableRenewalConfig()
	cfg.RenewInterval = 25 * time.Millisecond
	cfg.ReloadNginx = false

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- renewLoop(ctx, cfg, plaintextCDSClient(cfg.CDSURL), nil, true) }()

	// A failed renewal no longer sleeps a whole interval: it backs off from
	// renewalRetryBase, so the pod re-attempts long before the leaf it is
	// still serving expires.
	c.waitFor(t, "certificate renewal failed, retrying")
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("renewLoop returned %v, want nil on shutdown", err)
	}
}

// A changed watch file triggers the reload path, and a failed reload is
// surfaced as a warning rather than swallowed.
func TestRunRenewalLoopReloadsOnWatchChange(t *testing.T) {
	overrideProcRoot(t, t.TempDir()) // no nginx master: reloads fail softly
	holdSIGTERM(t)
	c := captureDefaultLogger(t)

	watched := filepath.Join(t.TempDir(), "tls.crt")
	if err := os.WriteFile(watched, []byte("v1"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := unreachableRenewalConfig()
	cfg.ReloadNginx = true
	cfg.ReloadWatchPaths = []string{watched}
	cfg.ReloadWatchInterval = 20 * time.Millisecond

	done := make(chan error, 1)
	go func() { done <- run(cfg) }()

	// The snapshot is taken before this record, so a change written now is seen.
	c.waitFor(t, "watching files for nginx reload")
	if err := os.WriteFile(watched, []byte("v2"), 0644); err != nil {
		t.Fatal(err)
	}
	c.waitFor(t, "watched file changed, reloading nginx")
	c.waitFor(t, "watched file changed but nginx reload failed")
	terminateRun(t, done)
}

// Without watch paths the loop must not set up a watch ticker: a zero watch
// interval is only rejected (or used) when paths are configured, so run must
// come up and shut down cleanly.
func TestRunRenewalLoopWithoutWatchPathsIgnoresWatchInterval(t *testing.T) {
	holdSIGTERM(t)
	c := captureDefaultLogger(t)

	cfg := unreachableRenewalConfig()
	cfg.ReloadNginx = true
	cfg.ReloadWatchPaths = nil
	cfg.ReloadWatchInterval = 0

	done := make(chan error, 1)
	go func() { done <- run(cfg) }()

	c.waitFor(t, "entering renewal loop")
	terminateRun(t, done)
}

func TestWriteOutputsWarnsOnUnpersistedEphemeralKey(t *testing.T) {
	const warnMsg = "ephemeral key used but --key-out not set, private key will be lost"
	result := attestclient.CertificateResult{Certificate: "CHAIN-PEM"}

	t.Run("ephemeral without key-out warns", func(t *testing.T) {
		c := captureDefaultLogger(t)
		cfg := config{OutPath: filepath.Join(t.TempDir(), "cert.pem")}
		if err := writeOutputs(cfg, nil, result); err != nil {
			t.Fatalf("writeOutputs: %v", err)
		}
		if _, ok := c.find(warnMsg); !ok {
			t.Fatal("no warning logged for an unpersisted ephemeral key")
		}
	})

	t.Run("loaded key does not warn", func(t *testing.T) {
		c := captureDefaultLogger(t)
		cfg := config{KeyPath: "/keys/tls.key", OutPath: filepath.Join(t.TempDir(), "cert.pem")}
		if err := writeOutputs(cfg, nil, result); err != nil {
			t.Fatalf("writeOutputs: %v", err)
		}
		if _, ok := c.find(warnMsg); ok {
			t.Fatal("warning logged despite a caller-provided key")
		}
	})
}

func TestLoadOrGenerateKeyKeyOutEdgeCases(t *testing.T) {
	t.Run("empty file generates a fresh key", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "tls.key")
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		key, keyPEM, err := loadOrGenerateKey(config{KeyOutPath: path})
		if err != nil {
			t.Fatalf("loadOrGenerateKey: %v", err)
		}
		if key == nil || len(keyPEM) == 0 {
			t.Fatal("expected a freshly generated key for an empty key-out file")
		}
	})

	t.Run("unstatable path fails", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "afile")
		if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		// A regular file as a path component makes Stat fail with ENOTDIR,
		// which is not ErrNotExist and must be surfaced.
		_, _, err := loadOrGenerateKey(config{KeyOutPath: filepath.Join(file, "tls.key")})
		if err == nil || !strings.Contains(err.Error(), "stat") {
			t.Fatalf("error = %v, want stat error", err)
		}
	})
}

// overrideProcRoot substitutes a fake /proc tree and restores the real one on
// cleanup.
func overrideProcRoot(t *testing.T, root string) {
	t.Helper()
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

func TestFindNginxMasterPID(t *testing.T) {
	t.Run("finds the master among decoys", func(t *testing.T) {
		root := t.TempDir()
		writeProcEntry := func(pid, comm, cmdline string) {
			t.Helper()
			dir := filepath.Join(root, pid)
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if comm != "" {
				if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if cmdline != "" {
				if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0644); err != nil {
					t.Fatal(err)
				}
			}
		}
		// Decoys exercising every skip branch: a non-pid dir, a plain file, a
		// non-nginx process, an nginx worker, an nginx without cmdline.
		writeProcEntry("self", "nginx\n", "nginx: master process\x00")
		if err := os.WriteFile(filepath.Join(root, "42"), []byte("file"), 0644); err != nil {
			t.Fatal(err)
		}
		writeProcEntry("100", "bash\n", "bash\x00")
		writeProcEntry("101", "nginx\n", "nginx: worker process\x00")
		writeProcEntry("102", "nginx\n", "")
		writeProcEntry("103", "", "nginx: master process\x00")
		writeProcEntry("200", "nginx\n", "nginx: master process /etc/nginx/nginx.conf\x00")
		overrideProcRoot(t, root)

		pid, err := findNginxMasterPID()
		if err != nil {
			t.Fatalf("findNginxMasterPID: %v", err)
		}
		if pid != 200 {
			t.Fatalf("pid = %d, want 200", pid)
		}
	})

	t.Run("no master present", func(t *testing.T) {
		overrideProcRoot(t, t.TempDir())
		if _, err := findNginxMasterPID(); err == nil {
			t.Fatal("findNginxMasterPID succeeded, want no-master error")
		}
	})

	t.Run("proc root unreadable", func(t *testing.T) {
		overrideProcRoot(t, filepath.Join(t.TempDir(), "missing"))
		if _, err := findNginxMasterPID(); err == nil {
			t.Fatal("findNginxMasterPID succeeded, want read error")
		}
	})
}

func TestReloadNginx(t *testing.T) {
	t.Run("signals the master", func(t *testing.T) {
		// Present this test process as the nginx master and swallow the SIGHUP
		// reloadNginx sends it.
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		defer signal.Stop(hup)

		root := t.TempDir()
		pidDir := filepath.Join(root, strconv.Itoa(os.Getpid()))
		if err := os.MkdirAll(pidDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("nginx\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("nginx: master process\x00"), 0644); err != nil {
			t.Fatal(err)
		}
		overrideProcRoot(t, root)

		if err := reloadNginx(); err != nil {
			t.Fatalf("reloadNginx: %v", err)
		}
		select {
		case <-hup:
		case <-time.After(5 * time.Second):
			t.Fatal("SIGHUP not delivered")
		}
	})

	t.Run("no master", func(t *testing.T) {
		overrideProcRoot(t, t.TempDir())
		if err := reloadNginx(); err == nil {
			t.Fatal("reloadNginx succeeded, want no-master error")
		}
	})
}

func TestRunRenewalModeFailsOnBadWatchSnapshot(t *testing.T) {
	// continue-on-initial-error carries run past the failed first request, and
	// the missing watch path then fails the loop setup.
	err := run(config{
		CDSURL:                 "https://127.0.0.1:1",
		AttestationApiURL:      "http://127.0.0.1:1",
		SAN:                    "host.example.com",
		InitialRetryTimeout:    0,
		ContinueOnInitialError: true,
		RenewInterval:          time.Hour,
		ReloadNginx:            true,
		ReloadWatchPaths:       []string{filepath.Join(t.TempDir(), "missing.crt")},
		ReloadWatchInterval:    time.Minute,
	})
	if err == nil || !strings.Contains(err.Error(), "stat reload watch path") {
		t.Fatalf("error = %v, want watch snapshot error", err)
	}
}

// A CDS that refuses the first refusals times of asking and then issues, so a
// test can watch get-cert recover on its own.
func flakyCDS(t *testing.T, chain string, refusals int) (cdsURL, attURL string) {
	t.Helper()

	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		report := base64.StdEncoding.EncodeToString([]byte("fake-snp-report"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"platform": "snp",
			"evidence": json.RawMessage(`{"attestation_report":"` + report + `"}`),
		})
	}))
	t.Cleanup(att.Close)

	var mu sync.Mutex
	var asked int
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authenticate":
			mu.Lock()
			asked++
			refuse := asked <= refusals
			mu.Unlock()
			if refuse {
				http.Error(w, `{"error":"csr_denied"}`, http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"challenge": base64.StdEncoding.EncodeToString([]byte("the-challenge")),
			})
		case "/attest":
			_, _ = w.Write([]byte(chain))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cds.Close)
	return cds.URL, att.URL
}

// A workload is gated on the first certificate by c8s-cert-wait, so when the
// initial request fails get-cert must keep asking on its own cadence. Pinning
// RenewInterval to an hour means the certificate here can only have arrived via
// the initial-retry backoff.
func TestRenewLoopRetriesInitialCertBeforeRenewInterval(t *testing.T) {
	dir := t.TempDir()
	cdsURL, attURL := flakyCDS(t, testIssuedChainPEM(t), 2)

	cfg := config{
		CDSURL:                 cdsURL,
		AttestationApiURL:      attURL,
		SAN:                    "host.example.com",
		OutPath:                filepath.Join(dir, "cert.pem"),
		ContinueOnInitialError: true,
		InitialRetryInterval:   5 * time.Millisecond,
		RenewInterval:          time.Hour,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- renewLoop(ctx, cfg, plaintextCDSClient(cfg.CDSURL), nil, false) }()

	deadline := time.After(10 * time.Second)
	for {
		if _, err := os.Stat(cfg.OutPath); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("renewLoop returned early: %v", err)
		case <-deadline:
			t.Fatal("no certificate: get-cert waited out RenewInterval instead of retrying")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("renewLoop returned %v, want nil on shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("renewLoop did not shut down when the context was cancelled")
	}
}

// Once the first certificate lands the cadence goes back to the ordinary
// pacing: the backoff must not keep re-requesting for the life of the process.
func TestRenewLoopStopsRetryingAfterFirstCert(t *testing.T) {
	dir := t.TempDir()
	cdsURL, attURL := flakyCDS(t, testIssuedChainPEM(t), 0)

	cfg := config{
		CDSURL:               cdsURL,
		AttestationApiURL:    attURL,
		SAN:                  "host.example.com",
		OutPath:              filepath.Join(dir, "cert.pem"),
		InitialRetryInterval: time.Millisecond,
		RenewInterval:        time.Hour,
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- renewLoop(ctx, cfg, plaintextCDSClient(cfg.CDSURL), nil, false) }()

	waitForFile(t, cfg.OutPath)
	info, err := os.Stat(cfg.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // many backoff periods, no renewal tick
	after, err := os.Stat(cfg.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(info.ModTime()) {
		t.Fatal("certificate rewritten after the first success: the loop is still on the retry cadence")
	}

	cancel()
	<-done
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	for range 2000 {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}
