package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestProvisionCAGeneratesWithoutPeer(t *testing.T) {
	// The puller must never be called on the cold-start path.
	pull := func(context.Context, CAProvisionConfig, *slog.Logger) (*HandoffMaterial, error) {
		t.Fatal("puller called with no peer URL")
		return nil, nil
	}
	ca, adopted, err := provisionCA(context.Background(), CAProvisionConfig{
		CommonName: "cold-start",
		Validity:   time.Hour,
	}, slog.Default(), pull)
	if err != nil {
		t.Fatalf("provisionCA: %v", err)
	}
	if adopted {
		t.Fatal("adopted=true with no peer URL; expected self-generate")
	}
	if ca == nil || ca.Cert == nil || ca.Key == nil {
		t.Fatal("provisionCA returned no CA")
	}
	if ca.Cert.Subject.CommonName != "cold-start" {
		t.Fatalf("generated CA CN = %q, want cold-start", ca.Cert.Subject.CommonName)
	}
}

func TestProvisionCAAdoptsFromPeer(t *testing.T) {
	peerCA, err := NewCAWithCurve("peer-ca", time.Hour, elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	activated := false
	pull := func(context.Context, CAProvisionConfig, *slog.Logger) (*HandoffMaterial, error) {
		return &HandoffMaterial{
			CACert:           peerCA.Cert,
			CAKey:            peerCA.Key,
			AllowlistVersion: "9",
			Allowlist:        map[types.Digest]string{handoffTestDigest(): "dynamic/image"},
			Secrets: &secrets.Snapshot{
				Version: secrets.SnapshotVersion, MaxPaths: 8, MaxPerHolder: 2, MaxValue: 64,
				Entries: []secrets.SnapshotEntry{{Path: "/api/key", Value: []byte("preserved"), Origin: secrets.OriginWorkload, HolderName: "api"}},
			},
			activate: func(context.Context) error { activated = true; return nil },
		}, nil
	}
	var restoredVersion string
	var restored *allowlist.Allowlist
	var activate func(context.Context) error
	secretStore := secrets.NewMemoryStore(8, 2, 64)
	ca, adopted, err := provisionCA(context.Background(), CAProvisionConfig{
		PeerURL:          "https://peer:8443",
		Measurements:     []string{"m"},
		OperatorKeysHash: handoffTestOperatorKeysHash,
		RestoreAllowlist: func(version string, al *allowlist.Allowlist) error {
			restoredVersion, restored = version, al
			return nil
		},
		RestoreSecrets: secretStore.RestoreSnapshot,
		OnAdopt:        func(fn func(context.Context) error) { activate = fn },
	}, slog.Default(), pull)
	if err != nil {
		t.Fatalf("provisionCA: %v", err)
	}
	if !adopted {
		t.Fatal("adopted=false; expected the peer's CA to be adopted")
	}
	if activated || activate == nil {
		t.Fatal("provisioning activated before the successor server was ready")
	}
	if err := activate(context.Background()); err != nil || !activated {
		t.Fatalf("deferred activation failed: %v", err)
	}
	if got, want := certutil.CertFingerprint(ca.Cert.Raw), certutil.CertFingerprint(peerCA.Cert.Raw); got != want {
		t.Fatalf("adopted CA fingerprint = %s, want peer's %s", got, want)
	}
	if !ca.Key.PublicKey.Equal(&peerCA.Key.PublicKey) {
		t.Fatal("adopted CA key does not match the peer's key")
	}
	if restoredVersion != "9" || restored.Digests[handoffTestDigest().String()] != "dynamic/image" {
		t.Fatalf("restored allowlist = version %q, doc %#v", restoredVersion, restored)
	}
	if got, err := secretStore.Get(context.Background(), "/api/key"); err != nil || string(got) != "preserved" {
		t.Fatalf("restored application secret = %q, %v", got, err)
	}
}

func TestProvisionCARejectsMissingApplicationSecretSnapshot(t *testing.T) {
	peerCA, err := NewCA("Peer Mesh CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pull := func(context.Context, CAProvisionConfig, *slog.Logger) (*HandoffMaterial, error) {
		return &HandoffMaterial{
			CACert: peerCA.Cert, CAKey: peerCA.Key,
			AllowlistVersion: "1", Allowlist: map[types.Digest]string{},
		}, nil
	}
	_, _, err = provisionCA(context.Background(), CAProvisionConfig{
		PeerURL: "https://peer:8443", Measurements: []string{"m"},
		OperatorKeysHash: handoffTestOperatorKeysHash,
		RestoreAllowlist: func(string, *allowlist.Allowlist) error { return nil },
		RestoreSecrets:   secrets.NewMemoryStore(8, 2, 64).RestoreSnapshot,
	}, slog.Default(), pull)
	if err == nil || !strings.Contains(err.Error(), "no application-secret state") {
		t.Fatalf("missing secret snapshot was accepted: %v", err)
	}
}

func TestProvisionCAFailsClosedWhenPullErrors(t *testing.T) {
	// A configured peer that errors (unreachable past deadline, or a denial)
	// must fail closed, never self-generate.
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"unreachable", &HandoffStatusError{Status: 503}},
		{"denied", &HandoffStatusError{Status: 403}},
		{"deadline", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pull := func(context.Context, CAProvisionConfig, *slog.Logger) (*HandoffMaterial, error) {
				return nil, tc.err
			}
			ca, adopted, err := provisionCA(context.Background(), CAProvisionConfig{
				PeerURL:          "https://peer:8443",
				Measurements:     []string{"m"},
				OperatorKeysHash: handoffTestOperatorKeysHash,
				RestoreAllowlist: func(string, *allowlist.Allowlist) error { return nil },
			}, slog.Default(), pull)
			if err == nil {
				t.Fatal("provisionCA succeeded despite a pull error; must fail closed")
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("error chain lost the pull cause: %v", err)
			}
			if ca != nil || adopted {
				t.Fatalf("fail-closed path returned a CA (ca=%v adopted=%v)", ca, adopted)
			}
		})
	}
}

func TestProvisionCAFailsClosedWhenAllowlistRestoreFails(t *testing.T) {
	peerCA, err := NewCA("Peer Mesh CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pull := func(context.Context, CAProvisionConfig, *slog.Logger) (*HandoffMaterial, error) {
		return &HandoffMaterial{
			CACert:           peerCA.Cert,
			CAKey:            peerCA.Key,
			AllowlistVersion: "9",
			Allowlist:        map[types.Digest]string{},
			activate:         func(context.Context) error { return nil },
		}, nil
	}
	wantErr := errors.New("store unavailable")
	ca, adopted, err := provisionCA(context.Background(), CAProvisionConfig{
		PeerURL:          "https://peer:8443",
		Measurements:     []string{"m"},
		OperatorKeysHash: handoffTestOperatorKeysHash,
		RestoreAllowlist: func(string, *allowlist.Allowlist) error { return wantErr },
	}, slog.Default(), pull)
	if !errors.Is(err, wantErr) {
		t.Fatalf("provisionCA error = %v, want %v", err, wantErr)
	}
	if ca != nil || adopted {
		t.Fatalf("failed restore returned ca=%v adopted=%v", ca, adopted)
	}
}

func TestProvisionCARejectsChainedOrMultiCertHandoff(t *testing.T) {
	// Adoption supports a single self-signed root; a parent cert or a
	// rotation bundle must be refused, not silently truncated.
	peerCA, err := NewCAWithCurve("peer-ca", time.Hour, elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	otherCA, err := NewCAWithCurve("retiring-ca", time.Hour, elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		material   *HandoffMaterial
		wantSubstr string
	}{
		{"parent cert", &HandoffMaterial{CACert: peerCA.Cert, CAKey: peerCA.Key, ParentCert: otherCA.Cert}, "parent=true"},
		{"multi-cert bundle", &HandoffMaterial{CACert: peerCA.Cert, CAKey: peerCA.Key, Bundle: []*x509.Certificate{peerCA.Cert, otherCA.Cert}}, "parent=false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pull := func(context.Context, CAProvisionConfig, *slog.Logger) (*HandoffMaterial, error) {
				return tc.material, nil
			}
			ca, adopted, err := provisionCA(context.Background(), CAProvisionConfig{
				PeerURL:          "https://peer:8443",
				Measurements:     []string{"m"},
				OperatorKeysHash: handoffTestOperatorKeysHash,
				RestoreAllowlist: func(string, *allowlist.Allowlist) error { return nil },
			}, slog.Default(), pull)
			if err == nil {
				t.Fatal("provisionCA adopted a chained/multi-cert handoff; must refuse")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("refusal error %q does not report %q", err.Error(), tc.wantSubstr)
			}
			if ca != nil || adopted {
				t.Fatalf("refusal path returned a CA (ca=%v adopted=%v)", ca, adopted)
			}
		})
	}
}

// TestProvisionCAAdoptsSingleCertBundle pins the boundary of the multi-cert
// refusal: a handoff whose bundle is exactly the active CA must be adopted.
func TestProvisionCAAdoptsSingleCertBundle(t *testing.T) {
	peerCA, err := NewCAWithCurve("peer-ca", time.Hour, elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	pull := func(context.Context, CAProvisionConfig, *slog.Logger) (*HandoffMaterial, error) {
		return &HandoffMaterial{
			CACert:           peerCA.Cert,
			CAKey:            peerCA.Key,
			Bundle:           []*x509.Certificate{peerCA.Cert},
			AllowlistVersion: "1",
			Allowlist:        map[types.Digest]string{},
			activate:         func(context.Context) error { return nil },
		}, nil
	}
	ca, adopted, err := provisionCA(context.Background(), CAProvisionConfig{
		PeerURL:          "https://peer:8443",
		Measurements:     []string{"m"},
		OperatorKeysHash: handoffTestOperatorKeysHash,
		RestoreAllowlist: func(string, *allowlist.Allowlist) error { return nil },
		OnAdopt:          func(func(context.Context) error) {},
	}, slog.Default(), pull)
	if err != nil {
		t.Fatalf("provisionCA refused a single-cert bundle: %v", err)
	}
	if !adopted || ca == nil || !ca.Cert.Equal(peerCA.Cert) {
		t.Fatalf("adoption result = (ca=%v adopted=%v)", ca, adopted)
	}
}

func TestProvisionCADefaultsNilLoggerForPull(t *testing.T) {
	var gotLogger *slog.Logger
	pull := func(_ context.Context, _ CAProvisionConfig, l *slog.Logger) (*HandoffMaterial, error) {
		gotLogger = l
		return nil, errors.New("stop here")
	}
	_, _, err := provisionCA(context.Background(), CAProvisionConfig{
		PeerURL:          "https://peer:8443",
		Measurements:     []string{"m"},
		OperatorKeysHash: handoffTestOperatorKeysHash,
		RestoreAllowlist: func(string, *allowlist.Allowlist) error { return nil },
	}, nil, pull)
	if err == nil {
		t.Fatal("expected the stubbed pull error")
	}
	if gotLogger == nil {
		t.Fatal("nil logger must be defaulted before reaching the puller")
	}
}

func TestAdoptFromPeerInputValidation(t *testing.T) {
	validMeasurement := strings.Repeat("ab", 48)
	identity := handoffTestClusterIdentity(t)
	identityDir := t.TempDir()
	certPath := filepath.Join(identityDir, "cert.pem")
	keyPath := filepath.Join(identityDir, "key.pem")
	if err := os.WriteFile(certPath, certutil.EncodeCertPEM(identity.Certificate[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(identity.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		cfg        CAProvisionConfig
		wantSubstr string
	}{
		{
			name:       "missing attestation-api URL",
			cfg:        CAProvisionConfig{PeerURL: "https://peer:8443", Measurements: []string{validMeasurement}},
			wantSubstr: "attestation-api URL is required",
		},
		{
			name: "invalid measurement hex",
			cfg: CAProvisionConfig{
				PeerURL:           "https://peer:8443",
				AttestationApiURL: "http://attest",
				Measurements:      []string{"zz"},
			},
			wantSubstr: "parse handoff measurements",
		},
		{
			name: "no measurements",
			cfg: CAProvisionConfig{
				PeerURL:           "https://peer:8443",
				AttestationApiURL: "http://attest",
			},
			wantSubstr: "requires pinned peer measurements",
		},
		{
			// Valid inputs but an unreachable peer: the failure must come from
			// the pull stages, not input validation.
			name: "unreachable peer fails in attest-key",
			cfg: CAProvisionConfig{
				PeerURL:                 "https://127.0.0.1:1",
				AttestationApiURL:       "http://127.0.0.1:1",
				Measurements:            []string{validMeasurement},
				OperatorKeysHash:        handoffTestOperatorKeysHash,
				ClusterIdentityCertFile: certPath,
				ClusterIdentityKeyFile:  keyPath,
				Timeout:                 100 * time.Millisecond,
			},
			wantSubstr: "attest-key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := adoptFromPeer(context.Background(), tc.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err == nil {
				t.Fatal("expected adoptFromPeer to fail")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSubstr)
			}
		})
	}
}

func TestAdoptFromPeerRequiresMeasurements(t *testing.T) {
	// The real puller must refuse to adopt without a pinned measurement.
	_, err := adoptFromPeer(context.Background(), CAProvisionConfig{
		PeerURL:           "https://peer:8443",
		AttestationApiURL: "http://attest",
	}, slog.Default())
	if err == nil {
		t.Fatal("adoptFromPeer without measurements should error")
	}
}

// A malformed handoff RTMR pin fails the adopt dial before it is attempted:
// pinning nothing is not an acceptable fallback for a typo.
func TestAdoptFromPeerRejectsBadRTMRs(t *testing.T) {
	_, err := adoptFromPeer(context.Background(), CAProvisionConfig{
		PeerURL:           "https://peer.example",
		AttestationApiURL: "http://127.0.0.1:8400",
		Measurements:      []string{strings.Repeat("ab", 48)},
		RTMRs:             []string{"1=zz"},
	}, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "RTMR") {
		t.Fatalf("err = %v, want an RTMR parse failure", err)
	}
}
