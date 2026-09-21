//go:build linux

package ratlsmesh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNamespaceDeliveryRejectsMissingLocalDestination(t *testing.T) {
	delivery := newLocalDelivery(t.TempDir(), time.Second, time.Second)
	for _, destination := range []string{"10.52.0.2:8080", "[fd00::2]:8080", "127.0.0.1:8080", "example.com:8080", "10.52.0.2:0", "bad"} {
		t.Run(destination, func(t *testing.T) {
			conn, err := delivery.DialContext(t.Context(), destination)
			if conn != nil {
				conn.Close()
				t.Fatal("delivered without a local runtime namespace")
			}
			if err == nil {
				t.Fatal("missing namespace was accepted")
			}
		})
	}
}

func TestNamespaceDeliveryRejectsUnreadableInventory(t *testing.T) {
	delivery := podNamespaceDelivery{directory: filepath.Join(t.TempDir(), "absent")}
	if _, err := delivery.DialContext(t.Context(), "10.52.0.2:8080"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want inventory read failure, got %v", err)
	}
}

func TestNamespaceDeliveryRejectsInvalidNamespaceFile(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "not-a-namespace"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	delivery := podNamespaceDelivery{directory: directory}
	if conn, err := delivery.DialContext(t.Context(), "10.52.0.2:8080"); err == nil || conn != nil {
		t.Fatalf("invalid runtime entry accepted: conn=%v error=%v", conn, err)
	}
}

func TestNamespaceDeliveryHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	delivery := podNamespaceDelivery{directory: t.TempDir()}
	if _, err := delivery.DialContext(ctx, "10.52.0.2:8080"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context cancellation, got %v", err)
	}
}
