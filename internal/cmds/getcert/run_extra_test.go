package getcert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// testCSRKey returns a throwaway public key standing in for the CSR key a
// sandbox token would be bound to.
func testCSRKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey
}

// overrideInventoryEndpoint points the compiled inventory endpoint at a test socket
// and restores the production value on cleanup.
func overrideInventoryEndpoint(t *testing.T, endpoint string) {
	t.Helper()
	old := inventoryEndpoint
	inventoryEndpoint = func() string { return endpoint }
	t.Cleanup(func() { inventoryEndpoint = old })
}

// overrideProcRoot substitutes a fake /proc tree and restores the real one on
// cleanup.
func overrideProcRoot(t *testing.T, root string) {
	t.Helper()
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

// fakeResolver answers the inventory's ContainersForPeer with fixed data.
type fakeResolver struct {
	containers []workloadclaims.Container
	err        error
}

func (f fakeResolver) ContainersForPeer(int) ([]workloadclaims.Container, error) {
	return f.containers, f.err
}

// startFakeInventory serves the admission inventory protocol on a unix socket
// and returns its unix:// endpoint.
func startFakeInventory(t *testing.T, resolver workloadclaims.Resolver) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sock, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = workloadclaims.Serve(ctx, l, resolver, nil)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return "unix://" + sock
}

func TestWorkloadClaimsWithInventoryBindsAndPartitions(t *testing.T) {
	endpoint := startFakeInventory(t, fakeResolver{containers: []workloadclaims.Container{
		{Name: "setup", Digest: "sha256:" + strings.Repeat("a", 64)},
		{Name: "app", Digest: "sha256:" + strings.Repeat("b", 64)},
	}})
	overrideInventoryEndpoint(t, endpoint)

	res, err := workloadClaims(context.Background(), config{
		WorkloadClaims:         true,
		WorkloadClaimsTimeout:  2 * time.Second,
		WorkloadInitContainers: []string{"setup"},
	}, testCSRKey(t), []byte("test-nonce"))
	if err != nil {
		t.Fatalf("workloadClaims: %v", err)
	}
	if len(res.claimsDER) == 0 {
		t.Fatal("claimsDER empty, want a bound config-claims extension")
	}
	if len(res.initDigests) != 1 || res.initDigests[0] != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("initDigests = %v, want the setup container digest", res.initDigests)
	}
	if len(res.mainDigests) != 1 || res.mainDigests[0] != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("mainDigests = %v, want the app container digest", res.mainDigests)
	}

	// The bound claim must verify against the same digest partition.
	if _, err := workloadclaims.VerifyWorkloadDigest(res.claimsDER, res.initDigests, res.mainDigests); err != nil {
		t.Fatalf("VerifyWorkloadDigest: %v", err)
	}
}

// First issuance: the inventory has admitted no app containers yet, so get-cert
// issues without a claim instead of failing.
func TestWorkloadClaimsWithInventoryNoContainersIsClaimFree(t *testing.T) {
	endpoint := startFakeInventory(t, fakeResolver{})
	overrideInventoryEndpoint(t, endpoint)

	res, err := workloadClaims(context.Background(), config{
		WorkloadClaims:        true,
		WorkloadClaimsTimeout: 2 * time.Second,
	}, testCSRKey(t), []byte("test-nonce"))
	if err != nil {
		t.Fatalf("workloadClaims: %v", err)
	}
	if res.claimsDER != nil || res.initDigests != nil || res.mainDigests != nil {
		t.Fatalf("expected claims-free result, got %+v", res)
	}
}

// An inventory error is fail-closed: issuance aborts rather than silently dropping
// the workload binding.
func TestWorkloadClaimsWithInventoryUnreachableFailsClosed(t *testing.T) {
	overrideInventoryEndpoint(t, "unix://"+filepath.Join(t.TempDir(), "missing.sock"))

	_, err := workloadClaims(context.Background(), config{
		WorkloadClaims:        true,
		WorkloadClaimsTimeout: time.Second,
	}, testCSRKey(t), []byte("test-nonce"))
	if err == nil {
		t.Fatal("workloadClaims succeeded, want fail-closed error for unreachable inventory")
	}
	// The sandbox-token fetch runs first and hits the dead socket.
	if !strings.Contains(err.Error(), "fetch sandbox token") {
		t.Fatalf("error = %v, want fetch sandbox token", err)
	}
}

func TestObtainCertAttestationExtensionError(t *testing.T) {
	// CDS answers /authenticate (obtainCert fetches the challenge first), so the
	// flow reaches the attestation-api, which is down — the error under test.
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: "dGVzdC1jaGFsbGVuZ2U="})
	}))
	t.Cleanup(cds.Close)
	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "attestation down", http.StatusInternalServerError)
	}))
	t.Cleanup(att.Close)

	cfg := config{
		CDSURL:            cds.URL,
		AttestationApiURL: att.URL,
		SAN:               "host.example.com",
	}
	err := obtainCert(context.Background(), cfg, plaintextCDSClient(cds.URL))
	if err == nil {
		t.Fatal("obtainCert succeeded, want attestation extension error")
	}
	if !strings.Contains(err.Error(), "build RA-TLS attestation extension") {
		t.Fatalf("error = %v, want attestation extension error", err)
	}
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

func TestWriteOutputsPrintsToStdoutWithoutOutPath(t *testing.T) {
	// OutPath "" prints the chain to stdout; capture it via a pipe.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = w
	writeErr := writeOutputs(config{}, nil, attestclient.CertificateResult{Certificate: "CHAIN-PEM"})
	os.Stdout = oldStdout
	w.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if writeErr != nil {
		t.Fatalf("writeOutputs: %v", writeErr)
	}
	if string(out) != "CHAIN-PEM" {
		t.Fatalf("stdout = %q, want CHAIN-PEM", out)
	}
}

func TestBuildDiscoveryDocumentRejectsUnparseableCert(t *testing.T) {
	if _, err := buildDiscoveryDocument(config{}, attestclient.CertificateResult{Certificate: "junk"}); err == nil {
		t.Fatal("buildDiscoveryDocument succeeded, want parse error")
	}
}

func TestRunFailsOnUnwritableOutputPath(t *testing.T) {
	err := run(config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
		OutPath:           filepath.Join(t.TempDir(), "missing", "cert.pem"),
	})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("error = %v, want missing output directory error", err)
	}
}

func TestRunFailsOnBadCDSMeasurements(t *testing.T) {
	err := run(config{
		CDSURL:            "https://cds:8443",
		CDSMeasurements:   "zz",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	})
	if err == nil || !strings.Contains(err.Error(), "--cds-measurements") {
		t.Fatalf("error = %v, want measurements error", err)
	}
}

func TestRunOnceReturnsInitialError(t *testing.T) {
	// Run-once mode (RenewInterval 0): the initial failure is returned as-is.
	err := run(config{
		CDSURL:              "https://127.0.0.1:1",
		AttestationApiURL:   "http://127.0.0.1:1",
		SAN:                 "host.example.com",
		InitialRetryTimeout: 0,
	})
	if err == nil {
		t.Fatal("run succeeded, want initial certificate request error")
	}
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

// Drives the full renewal loop: a failing renewal tick, an unchanged watch
// tick, a changed watch tick (nginx reload attempted and failed — no master in
// the fake proc root), and finally SIGTERM-triggered graceful shutdown.
func TestRunRenewalLoopWatchAndShutdown(t *testing.T) {
	overrideProcRoot(t, t.TempDir()) // no nginx master: reload attempts fail softly

	watched := filepath.Join(t.TempDir(), "tls.crt")
	if err := os.WriteFile(watched, []byte("v1"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config{
		CDSURL:                 "https://127.0.0.1:1",
		AttestationApiURL:      "http://127.0.0.1:1",
		SAN:                    "host.example.com",
		InitialRetryTimeout:    0,
		ContinueOnInitialError: true,
		RenewInterval:          40 * time.Millisecond,
		ReloadNginx:            true,
		ReloadWatchPaths:       []string{watched},
		ReloadWatchInterval:    20 * time.Millisecond,
	}

	done := make(chan error, 1)
	go func() { done <- run(cfg) }()

	// Let the renewal and watch tickers fire a few times, then change the
	// watched file so the change branch fires too.
	time.Sleep(150 * time.Millisecond)
	if err := os.WriteFile(watched, []byte("v2 renewed"), 0644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	// run installs a SIGTERM handler via signal.NotifyContext, so signalling
	// ourselves triggers graceful shutdown without killing the test binary.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v, want nil on graceful shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not shut down after SIGTERM")
	}
}
