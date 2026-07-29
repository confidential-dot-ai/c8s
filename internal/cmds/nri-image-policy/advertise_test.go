package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"
)

// The advertise host is what CDS dials back. Getting it wrong took the plugin
// down on a stock install once already: route inference against the chart's
// default CDS URL (the NodePort on loopback) yields loopback, which is not a
// routable address. These pin each source and that regression.
func TestDigestsAdvertiseHost(t *testing.T) {
	const loopbackCDS = "https://127.0.0.1:30808"

	t.Run("explicit config wins", func(t *testing.T) {
		cfg := &config{}
		cfg.WorkloadClaims.AdvertiseHost = "10.1.2.3"
		cfg.Allowlist.Pull.URL = loopbackCDS
		got, err := digestsAdvertiseHost(cfg)
		if err != nil || got != "10.1.2.3" {
			t.Fatalf("host = %q, err = %v; want 10.1.2.3", got, err)
		}
	})

	t.Run("installer node-ip file is used when config is empty", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, NodeIPFile), []byte("10.4.5.6\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg := &config{}
		cfg.WorkloadClaims.SocketDir = dir
		cfg.Allowlist.Pull.URL = loopbackCDS
		got, err := digestsAdvertiseHost(cfg)
		if err != nil || got != "10.4.5.6" {
			t.Fatalf("host = %q, err = %v; want 10.4.5.6", got, err)
		}
	})

	t.Run("environment is the last source, for the baked node image", func(t *testing.T) {
		t.Setenv("C8S_SANDBOX_DIGESTS_ADVERTISE_HOST", "10.7.8.9")
		cfg := &config{}
		cfg.WorkloadClaims.SocketDir = t.TempDir() // no node-ip file
		cfg.Allowlist.Pull.URL = loopbackCDS
		got, err := digestsAdvertiseHost(cfg)
		if err != nil || got != "10.7.8.9" {
			t.Fatalf("host = %q, err = %v; want 10.7.8.9", got, err)
		}
	})

	// The regression: with no source at all, inference runs against a loopback
	// CDS URL and yields loopback, which must be rejected rather than
	// advertised. It fails here, at startup, not as an unreachable callback.
	t.Run("loopback CDS URL alone is rejected", func(t *testing.T) {
		cfg := &config{}
		cfg.WorkloadClaims.SocketDir = t.TempDir()
		cfg.Allowlist.Pull.URL = loopbackCDS
		if got, err := digestsAdvertiseHost(cfg); err == nil {
			t.Fatalf("host = %q, want an error: loopback is not an address CDS can dial back", got)
		}
	})
}
