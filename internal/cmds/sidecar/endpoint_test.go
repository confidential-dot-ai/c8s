package sidecar

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The two endpoints are compiled: --workload-claims-guest picks a shape, never
// an address, so a wrong setting fails closed against a port nothing serves
// rather than redirecting redemption to a rogue inventory.
func TestEndpointSelectsCompiledShape(t *testing.T) {
	if got, want := (Config{}).Endpoint(), workloadclaims.InventoryEndpoint(); got != want {
		t.Errorf("node-CVM endpoint = %q, want the compiled unix socket %q", got, want)
	}
	guest := Config{WorkloadClaimsGuest: true}.Endpoint()
	if want := workloadclaims.GuestInventoryEndpoint(); guest != want {
		t.Errorf("kata endpoint = %q, want the compiled guest loopback %q", guest, want)
	}
	// workloadclaims refuses anything that is not one of the two compiled
	// endpoints, so a shape it rejects would fail every redemption. Use a real
	// key: a nil one fails at marshalling, short of the endpoint check.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = workloadclaims.FetchSandboxToken(t.Context(), guest, time.Millisecond, pub, []byte("nonce"))
	if err == nil {
		t.Fatal("expected the guest endpoint to fail with nothing listening")
	}
	if strings.Contains(err.Error(), "endpoint must be") {
		t.Fatalf("guest endpoint rejected by the compiled-endpoint check: %v", err)
	}
}
