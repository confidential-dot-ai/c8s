package getcert

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

func namedLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	ext, err := ratls.MarshalMatchedWorkloadExtension(&ratls.MatchedWorkload{
		Name:             "api",
		AllowlistVersion: "1",
		AllowlistDigest:  bytes.Repeat([]byte{0x11}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{Extensions: []pkix.Extension{ext}}
}

func TestRenewalInterval(t *testing.T) {
	base := config{RenewInterval: 6 * time.Hour, UnnamedRenewInterval: 30 * time.Second, WorkloadClaims: true}

	t.Run("unnamed leaf fast-polls with bounded jitter", func(t *testing.T) {
		got := renewalInterval(base, &x509.Certificate{})
		if got < 30*time.Second || got > 38*time.Second {
			t.Fatalf("interval = %v, want [30s, ~37.5s]", got)
		}
	})
	t.Run("nil leaf counts as unnamed", func(t *testing.T) {
		if got := renewalInterval(base, nil); got >= time.Minute {
			t.Fatalf("interval = %v, want fast", got)
		}
	})
	t.Run("named leaf settles to renew-interval", func(t *testing.T) {
		if got := renewalInterval(base, namedLeaf(t)); got != 6*time.Hour {
			t.Fatalf("interval = %v, want 6h", got)
		}
	})
	t.Run("no workload-claims never fast-polls", func(t *testing.T) {
		cfg := base
		cfg.WorkloadClaims = false
		if got := renewalInterval(cfg, &x509.Certificate{}); got != 6*time.Hour {
			t.Fatalf("interval = %v, want 6h", got)
		}
	})
	t.Run("fast poll disabled by zero", func(t *testing.T) {
		cfg := base
		cfg.UnnamedRenewInterval = 0
		if got := renewalInterval(cfg, &x509.Certificate{}); got != 6*time.Hour {
			t.Fatalf("interval = %v, want 6h", got)
		}
	})
	t.Run("fast interval never exceeds renew-interval", func(t *testing.T) {
		cfg := base
		cfg.RenewInterval = 10 * time.Second
		if got := renewalInterval(cfg, &x509.Certificate{}); got != 10*time.Second {
			t.Fatalf("interval = %v, want the shorter renew-interval", got)
		}
	})
}
