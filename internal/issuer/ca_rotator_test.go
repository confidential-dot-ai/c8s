package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

func rotatorTestDeps(t *testing.T, ca *CA) CARotatorDeps {
	t.Helper()
	return CARotatorDeps{
		CACertValidity: time.Hour,
		Snapshot: func() (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, bool) {
			return ca.Cert, ca.Key, ca.Cert, true
		},
		CommitRotation: func(*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate) string {
			return "fp"
		},
	}
}

func TestNewCARotatorDefaultsNilLogger(t *testing.T) {
	ca, err := NewCA("rotator", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := NewCARotator(rotatorTestDeps(t, ca))
	if err != nil {
		t.Fatalf("NewCARotator: %v", err)
	}
	if cr.deps.Logger == nil {
		t.Fatal("nil Logger must be defaulted, not stored")
	}
}

func TestCARotatorRotateCAPublishesBundle(t *testing.T) {
	ca, err := NewCA("rotator", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bm := NewBundleManager(time.Hour, t.TempDir(), "mesh/ca-bundle", slog.Default())
	bm.SetInitial(ca.Cert)
	deps := rotatorTestDeps(t, ca)
	deps.Bundle = bm
	cr, err := NewCARotator(deps)
	if err != nil {
		t.Fatal(err)
	}

	newCert, _, err := cr.RotateCA()
	if err != nil {
		t.Fatalf("RotateCA with healthy bundle: %v", err)
	}
	certs, err := certutil.ParsePEMCertificates(bm.BundlePEM())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 || !certs[0].Equal(newCert) {
		t.Fatalf("published bundle does not start with the rotated CA (%d certs)", len(certs))
	}
}

func TestCARotatorRotateCAPropagatesBundleError(t *testing.T) {
	ca, err := NewCA("rotator", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	repoDir := t.TempDir()
	// A file where the bundle directory should be makes persistence fail.
	if err := os.WriteFile(filepath.Join(repoDir, "mesh"), []byte("not a directory"), 0644); err != nil {
		t.Fatal(err)
	}
	bm := NewBundleManager(time.Hour, repoDir, "mesh/ca-bundle", slog.Default())
	bm.SetInitial(ca.Cert)
	deps := rotatorTestDeps(t, ca)
	deps.Bundle = bm
	cr, err := NewCARotator(deps)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := cr.RotateCA(); err == nil || !strings.Contains(err.Error(), "rotate public bundle") {
		t.Fatalf("RotateCA error = %v, want rotate public bundle failure", err)
	}
}

func TestCARotatorRunLogsCompletedRotation(t *testing.T) {
	ca, err := NewCA("rotator", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	committed := make(chan struct{}, 1)
	capture := &captureHandler{}
	deps := rotatorTestDeps(t, ca)
	deps.Logger = slog.New(capture)
	deps.CommitRotation = func(*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate) string {
		select {
		case committed <- struct{}{}:
		default:
		}
		return "fp"
	}
	cr, err := NewCARotator(deps)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		cr.Run(ctx, time.Millisecond)
		close(done)
	}()
	select {
	case <-committed:
	case <-time.After(10 * time.Second):
		t.Fatal("scheduled rotation never committed")
	}
	cancel()
	<-done

	if _, ok := capture.find("scheduled CA rotation completed"); !ok {
		t.Fatal("successful scheduled rotation did not log completion")
	}
	if _, ok := capture.find("scheduled CA rotation failed"); ok {
		t.Fatal("successful scheduled rotation logged a failure")
	}
}
