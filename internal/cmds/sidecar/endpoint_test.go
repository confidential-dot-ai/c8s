package sidecar

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/url"
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
		t.Fatalf("node-CVM endpoint = %q, want the compiled unix socket %q", got, want)
	}
	guest := Config{WorkloadClaimsGuest: true}.Endpoint()
	if want := workloadclaims.GuestInventoryEndpoint(); guest != want {
		t.Fatalf("kata endpoint = %q, want the compiled guest loopback %q", guest, want)
	}
	u, err := url.Parse(guest)
	if err != nil {
		t.Fatalf("kata endpoint %q: %v", guest, err)
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		t.Fatalf("kata endpoint host = %q, want a loopback address", u.Hostname())
	}

	const timeout = 5 * time.Second
	// The endpoint check precedes the dial, so with a cancelled context
	// context.Canceled means workloadclaims accepted this shape. The key must be
	// real: a nil one fails at marshalling, short of the check.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = workloadclaims.FetchSandboxToken(ctx, guest, timeout, pub, []byte("nonce"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("guest endpoint not accepted by the compiled-endpoint check: %v", err)
	}
	_, err = workloadclaims.FetchSandboxToken(ctx, "http://127.0.0.1:9999", timeout, pub, []byte("nonce"))
	if err == nil || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "endpoint must be") {
		t.Fatalf("non-compiled endpoint not rejected ahead of the transport: %v", err)
	}
}
