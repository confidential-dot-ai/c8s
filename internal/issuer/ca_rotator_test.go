package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
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

func TestNewCARotatorValidatesDeps(t *testing.T) {
	if _, err := NewCARotator(CARotatorDeps{}); err == nil {
		t.Error("missing Snapshot: expected error")
	}
	if _, err := NewCARotator(CARotatorDeps{
		Snapshot: func() (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, bool) {
			return nil, nil, nil, false
		},
	}); err == nil {
		t.Error("missing CommitRotation: expected error")
	}
}

func TestCARotatorRotateCANoBundle(t *testing.T) {
	cr, err := NewCARotator(CARotatorDeps{
		Snapshot: func() (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, bool) {
			return nil, nil, nil, false
		},
		CommitRotation: func(*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate) string {
			return ""
		},
	})
	if err != nil {
		t.Fatalf("NewCARotator: %v", err)
	}
	if _, _, err := cr.RotateCA(); !errors.Is(err, ErrNoCertificateBundle) {
		t.Fatalf("RotateCA err = %v, want ErrNoCertificateBundle", err)
	}
}

func TestCARotatorRotateCACommits(t *testing.T) {
	ca, err := NewCA("parent", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	var committed bool
	var newCertSeen *x509.Certificate
	cr, err := NewCARotator(CARotatorDeps{
		CACertValidity: time.Hour,
		CACommonName:   "rotated ca",
		Snapshot: func() (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, bool) {
			return ca.Cert, ca.Key, ca.Cert, true
		},
		CommitRotation: func(newCert *x509.Certificate, _ *ecdsa.PrivateKey, _ *x509.Certificate, parent *x509.Certificate) string {
			committed = true
			newCertSeen = newCert
			if !parent.Equal(ca.Cert) {
				t.Error("parent passed to CommitRotation is not the snapshot CA")
			}
			return "fp-123"
		},
	})
	if err != nil {
		t.Fatalf("NewCARotator: %v", err)
	}
	newCert, fp, err := cr.RotateCA()
	if err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	if !committed {
		t.Error("CommitRotation was not invoked")
	}
	if fp != "fp-123" {
		t.Errorf("fingerprint = %q, want fp-123", fp)
	}
	if newCert.Subject.CommonName != "rotated ca" {
		t.Errorf("new CA CN = %q, want rotated ca", newCert.Subject.CommonName)
	}
	if newCertSeen == nil || !newCertSeen.Equal(newCert) {
		t.Error("CommitRotation received a different cert than returned")
	}
	// New CA must chain to the parent.
	if err := newCert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("rotated CA not signed by parent: %v", err)
	}
}
