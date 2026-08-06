package getcert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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

// fakeResolver answers the inventory's sandbox routes with fixed data.
type fakeResolver struct {
	sandboxID string
	err       error
}

func (f fakeResolver) SandboxForPeer(workloadclaims.Peer) (string, error) {
	return f.sandboxID, f.err
}

func (f fakeResolver) DigestsForSandbox(string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	return nil, nil, false, nil
}

// startFakeInventory serves the inventory token socket and returns its unix://
// endpoint.
func startFakeInventory(t *testing.T, resolver workloadclaims.SandboxResolver, signer *workloadclaims.SandboxTokenSigner) string {
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
		_ = workloadclaims.ServeTokens(ctx, l, resolver, signer)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return "unix://" + sock
}

func testTokenSigner(t *testing.T) *workloadclaims.SandboxTokenSigner {
	t.Helper()
	signer, err := workloadclaims.NewSandboxTokenSigner("10.0.0.7")
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// get-cert forwards the inventory-signed token verbatim and reports no images
// of its own — CDS resolves those from the inventory.
func TestFetchSandboxTokenForwardsSignedToken(t *testing.T) {
	endpoint := startFakeInventory(t, fakeResolver{sandboxID: "sandbox-1"}, testTokenSigner(t))
	overrideInventoryEndpoint(t, endpoint)

	raw, err := fetchSandboxToken(context.Background(), config{
		WorkloadClaims:        true,
		WorkloadClaimsTimeout: 2 * time.Second,
	}, testCSRKey(t), []byte("test-nonce"))
	if err != nil {
		t.Fatalf("fetchSandboxToken: %v", err)
	}
	var token workloadclaims.SignedSandboxToken
	if err := json.Unmarshal(raw, &token); err != nil {
		t.Fatalf("token is not a SignedSandboxToken: %v", err)
	}
	if len(token.Token) == 0 || len(token.Signature) == 0 {
		t.Fatalf("incomplete token forwarded: %+v", token)
	}
}

// An inventory without the token route is not a failure: get-cert issues
// without a sandbox ID.
func TestFetchSandboxTokenRouteAbsentIsTokenFree(t *testing.T) {
	endpoint := startFakeInventory(t, fakeResolver{sandboxID: "sandbox-1"}, nil)
	overrideInventoryEndpoint(t, endpoint)

	raw, err := fetchSandboxToken(context.Background(), config{
		WorkloadClaims:        true,
		WorkloadClaimsTimeout: 2 * time.Second,
	}, testCSRKey(t), []byte("test-nonce"))
	if err != nil {
		t.Fatalf("fetchSandboxToken: %v", err)
	}
	if raw != nil {
		t.Fatalf("expected no token, got %s", raw)
	}
}

// An inventory error is fail-closed: issuance aborts rather than silently dropping
// the workload binding.
func TestWorkloadClaimsWithInventoryUnreachableFailsClosed(t *testing.T) {
	overrideInventoryEndpoint(t, "unix://"+filepath.Join(t.TempDir(), "missing.sock"))

	_, err := fetchSandboxToken(context.Background(), config{
		WorkloadClaims:        true,
		WorkloadClaimsTimeout: time.Second,
	}, testCSRKey(t), []byte("test-nonce"))
	if err == nil {
		t.Fatal("fetchSandboxToken succeeded, want fail-closed error for unreachable inventory")
	}
	// The sandbox-token fetch runs first and hits the dead socket.
	if !strings.Contains(err.Error(), "fetch sandbox token") {
		t.Fatalf("error = %v, want fetch sandbox token", err)
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

// Empty measurements accept any RA-TLS-attested CDS. Under kata the host writes
// this argv, so dropping the flag is how it points the sidecar at a CDS it runs.
func TestUnpinnedCDSRefusedInsideAKataGuest(t *testing.T) {
	cfg := config{
		CDSURL:              "https://cds:8443",
		AttestationApiURL:   "http://attestation-api:8400",
		SAN:                 "host.example.com",
		WorkloadClaimsGuest: true,
	}
	_, err := cdsHTTPClient(cfg)
	if err == nil || !strings.Contains(err.Error(), "--measurements is empty") {
		t.Fatalf("error = %v, want a refusal to use an unpinned CDS", err)
	}
}

// Outside kata "no pinning" stays a supported development shape.
func TestUnpinnedCDSAllowedOutsideAKataGuest(t *testing.T) {
	cfg := config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	}
	if _, err := cdsHTTPClient(cfg); err != nil {
		t.Fatalf("cdsHTTPClient: %v", err)
	}
}

// A pinned measurement is what the flag is for; it must still work under kata.
func TestPinnedCDSAcceptedInsideAKataGuest(t *testing.T) {
	cfg := config{
		CDSURL:              "https://cds:8443",
		AttestationApiURL:   "http://attestation-api:8400",
		SAN:                 "host.example.com",
		CDSMeasurements:     strings.Repeat("ab", 48),
		WorkloadClaimsGuest: true,
	}
	if _, err := cdsHTTPClient(cfg); err != nil {
		t.Fatalf("cdsHTTPClient: %v", err)
	}
}
