package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

func sealedDigest() []byte { return bytes.Repeat([]byte{0x33}, 32) }

func staticOutcome() *Outcome { return &Outcome{Verified: true} }

func TestApplyStaticAllowlistPolicy_FlagUnsetIsNoop(t *testing.T) {
	oc := staticOutcome()
	applyStaticAllowlistPolicy(oc, config{}, &evidence{}, nil, staticCAReport{})
	if !oc.Verified || oc.Error != "" || oc.StaticAllowlistDigest != "" {
		t.Fatalf("no-op expected, got %+v", oc)
	}
}

func TestApplyStaticAllowlistPolicy_Verdicts(t *testing.T) {
	cfg := config{staticAllowlist: true}
	heldMatching := &heldAllowlist{raw: []byte(`{"schema":"c8s.allowlist/v1"}`)}
	matchingDigest := sha256.Sum256(heldMatching.raw)

	for name, tc := range map[string]struct {
		ev      *evidence
		held    *heldAllowlist
		report  staticCAReport
		wantErr string // "" = verdict stays verified
	}{
		"bundle damage fails closed": {
			ev:      &evidence{},
			report:  staticCAReport{err: fmt.Errorf("two stamped CAs")},
			wantErr: "static_allowlist_malformed",
		},
		"absent stamp fails closed": {
			ev:      &evidence{},
			report:  staticCAReport{},
			wantErr: "static_allowlist_absent",
		},
		"unverified CA evidence fails closed": {
			ev:      &evidence{},
			report:  staticCAReport{digest: sealedDigest(), verifyErr: fmt.Errorf("no attestation extension")},
			wantErr: "static_allowlist_ca_unverified",
		},
		"held bytes mismatch fails closed": {
			ev:      &evidence{},
			held:    heldMatching,
			report:  staticCAReport{digest: sealedDigest()},
			wantErr: "static_allowlist_digest_mismatch",
		},
		"leaf stamped under another policy fails closed": {
			ev:      &evidence{workload: &ratls.MatchedWorkload{Name: "api", AllowlistVersion: "1", AllowlistDigest: bytes.Repeat([]byte{0x44}, 32)}},
			report:  staticCAReport{digest: sealedDigest()},
			wantErr: "static_allowlist_skew",
		},
		"consistent sealed policy verifies": {
			ev:      &evidence{workload: &ratls.MatchedWorkload{Name: "api", AllowlistVersion: "1", AllowlistDigest: matchingDigest[:]}},
			held:    heldMatching,
			report:  staticCAReport{digest: matchingDigest[:], launchDigest: "abc123"},
			wantErr: "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			oc := staticOutcome()
			applyStaticAllowlistPolicy(oc, cfg, tc.ev, tc.held, tc.report)
			if tc.wantErr == "" {
				if !oc.Verified || oc.Error != "" {
					t.Fatalf("verdict = %+v, want verified", oc)
				}
				if !strings.Contains(oc.StaticAllowlistNote, "static_allowlist_verified") {
					t.Fatalf("note = %q", oc.StaticAllowlistNote)
				}
				return
			}
			if oc.Verified {
				t.Fatal("verdict stayed verified")
			}
			if !strings.Contains(oc.Error, tc.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", oc.Error, tc.wantErr)
			}
		})
	}
}

// sealedCAPEM writes a PEM bundle of self-signed CAs, stamping the
// static-allowlist extension onto the certificates whose index is in stamped.
func sealedCAPEM(t *testing.T, count int, stamped ...int) string {
	t.Helper()
	stampedSet := map[int]bool{}
	for _, i := range stamped {
		stampedSet[i] = true
	}
	var pemBytes []byte
	for i := 0; i < count; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: fmt.Sprintf("test ca %d", i)},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		if stampedSet[i] {
			ext, err := ratls.MarshalStaticAllowlistExtension(&ratls.StaticAllowlist{AllowlistDigest: sealedDigest()})
			if err != nil {
				t.Fatal(err)
			}
			tmpl.ExtraExtensions = []pkix.Extension{ext}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes = append(pemBytes, certutil.EncodeCertPEM(der)...)
	}
	path := filepath.Join(t.TempDir(), "mesh-ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGatherStaticCA(t *testing.T) {
	plan := &verifyPlan{policy: &ratls.VerifyPolicy{}}

	t.Run("flag unset gathers nothing", func(t *testing.T) {
		report := gatherStaticCA(context.Background(), config{}, plan)
		if report.digest != nil || report.err != nil {
			t.Fatalf("report = %+v", report)
		}
	})

	t.Run("no stamped CA in bundle", func(t *testing.T) {
		cfg := config{staticAllowlist: true, meshCA: sealedCAPEM(t, 1)}
		report := gatherStaticCA(context.Background(), cfg, plan)
		if report.digest != nil || report.err != nil {
			t.Fatalf("report = %+v", report)
		}
	})

	t.Run("two stamped CAs are refused", func(t *testing.T) {
		cfg := config{staticAllowlist: true, meshCA: sealedCAPEM(t, 2, 0, 1)}
		report := gatherStaticCA(context.Background(), cfg, plan)
		if report.err == nil {
			t.Fatal("two stamped CAs were accepted")
		}
	})

	t.Run("stamped CA without evidence records verifyErr", func(t *testing.T) {
		cfg := config{staticAllowlist: true, meshCA: sealedCAPEM(t, 2, 1)}
		report := gatherStaticCA(context.Background(), cfg, plan)
		if report.err != nil {
			t.Fatalf("bundle-level err: %v", report.err)
		}
		if !bytes.Equal(report.digest, sealedDigest()) {
			t.Fatalf("digest = %x", report.digest)
		}
		if report.verifyErr == nil {
			t.Fatal("a stamped CA with no RA-TLS extension must not verify")
		}
	})

	t.Run("unreadable bundle records err", func(t *testing.T) {
		cfg := config{staticAllowlist: true, meshCA: filepath.Join(t.TempDir(), "missing.pem")}
		if report := gatherStaticCA(context.Background(), cfg, plan); report.err == nil {
			t.Fatal("missing bundle was accepted")
		}
	})
}

func TestBuildPolicy_StaticAllowlistRequiresMeshCA(t *testing.T) {
	_, err := buildPolicy(config{staticAllowlist: true})
	if err == nil || !strings.Contains(err.Error(), "--mesh-ca") {
		t.Fatalf("buildPolicy = %v, want --mesh-ca requirement", err)
	}
}
