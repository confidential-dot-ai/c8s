package sidecar

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestEndpointSelectsCompiledShape(t *testing.T) {
	if got, want := (Config{}).Endpoint(), workloadclaims.InventoryEndpoint(); got != want {
		t.Fatalf("node-CVM endpoint = %q, want the compiled unix socket %q", got, want)
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
	_, err = workloadclaims.FetchSandboxToken(ctx, workloadclaims.InventoryEndpoint(), timeout, pub, []byte("nonce"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("guest endpoint not accepted by the compiled-endpoint check: %v", err)
	}
	_, err = workloadclaims.FetchSandboxToken(ctx, "http://127.0.0.1:9999", timeout, pub, []byte("nonce"))
	if err == nil || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "endpoint must be") {
		t.Fatalf("non-compiled endpoint not rejected ahead of the transport: %v", err)
	}
}
