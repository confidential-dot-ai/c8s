package getcert

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// overrideBrokerEndpoint points the compiled broker endpoint at a test socket
// and restores the production value on cleanup.
func overrideBrokerEndpoint(t *testing.T, endpoint string) {
	t.Helper()
	old := brokerEndpoint
	brokerEndpoint = func() string { return endpoint }
	t.Cleanup(func() { brokerEndpoint = old })
}

// fakeResolver answers the broker's ContainersForPeer with fixed data.
type fakeResolver struct {
	containers []workloadclaims.Container
	err        error
}

func (f fakeResolver) ContainersForPeer(int) ([]workloadclaims.Container, error) {
	return f.containers, f.err
}

// startFakeBroker serves the workload-claims broker protocol on a unix socket
// and returns its unix:// endpoint.
func startFakeBroker(t *testing.T, resolver workloadclaims.Resolver) string {
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
		_ = workloadclaims.Serve(ctx, l, resolver)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return "unix://" + sock
}

// The broker endpoint get-cert dials is a compiled Unix socket path, not a
// control-plane-supplied value, so the fetch can't be redirected.
func TestBrokerEndpointIsCompiledUnixPath(t *testing.T) {
	got := workloadclaims.BrokerEndpoint()
	if !strings.HasPrefix(got, "unix://") {
		t.Fatalf("broker endpoint %q is not a unix socket", got)
	}
	if !strings.HasSuffix(got, "/"+workloadclaims.SocketName) {
		t.Fatalf("broker endpoint %q does not end in the compiled socket name %q", got, workloadclaims.SocketName)
	}
}

// Without --workload-claims-broker, workloadClaims is a no-op: it returns the
// empty (claims-free) result without contacting any broker.
func TestWorkloadClaimsWithoutFlagIsClaimFree(t *testing.T) {
	res, err := workloadClaims(context.Background(), config{WorkloadClaimsBroker: false})
	if err != nil {
		t.Fatal(err)
	}
	if res.claimsDER != nil || res.initDigests != nil || res.mainDigests != nil {
		t.Fatalf("no --workload-claims-broker but a claim was produced: %+v", res)
	}
}

func TestWorkloadClaimsWithBrokerBindsAndPartitions(t *testing.T) {
	endpoint := startFakeBroker(t, fakeResolver{containers: []workloadclaims.Container{
		{Name: "setup", Digest: "sha256:" + strings.Repeat("a", 64)},
		{Name: "app", Digest: "sha256:" + strings.Repeat("b", 64)},
	}})
	overrideBrokerEndpoint(t, endpoint)

	res, err := workloadClaims(context.Background(), config{
		WorkloadClaimsBroker:   true,
		WorkloadClaimsTimeout:  2 * time.Second,
		WorkloadInitContainers: []string{"setup"},
	})
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

// First issuance: the broker has admitted no app containers yet, so get-cert
// issues without a claim instead of failing.
func TestWorkloadClaimsWithBrokerNoContainersIsClaimFree(t *testing.T) {
	endpoint := startFakeBroker(t, fakeResolver{})
	overrideBrokerEndpoint(t, endpoint)

	res, err := workloadClaims(context.Background(), config{
		WorkloadClaimsBroker:  true,
		WorkloadClaimsTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("workloadClaims: %v", err)
	}
	if res.claimsDER != nil || res.initDigests != nil || res.mainDigests != nil {
		t.Fatalf("expected claims-free result, got %+v", res)
	}
}

// A broker error is fail-closed: issuance aborts rather than silently dropping
// the workload binding.
func TestWorkloadClaimsWithBrokerUnreachableFailsClosed(t *testing.T) {
	overrideBrokerEndpoint(t, "unix://"+filepath.Join(t.TempDir(), "missing.sock"))

	_, err := workloadClaims(context.Background(), config{
		WorkloadClaimsBroker:  true,
		WorkloadClaimsTimeout: time.Second,
	})
	if err == nil {
		t.Fatal("workloadClaims succeeded, want fail-closed error for unreachable broker")
	}
	if !strings.Contains(err.Error(), "fetch workload claims") {
		t.Fatalf("error = %v, want fetch workload claims", err)
	}
}
