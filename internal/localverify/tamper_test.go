package localverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// SNP report field offsets (AMD SEV-SNP ABI, attestation report structure).
const (
	snpReportedTCBOff = 0x180
	snpSignatureOff   = 0x2A0
)

// genoaParts is the decoded real Genoa fixture — the SNP report and its VCEK
// DER — so a tamper case can wreck either part and re-pack the evidence.
type genoaParts struct {
	report []byte
	vcek   []byte
}

func loadGenoaParts(t *testing.T) *genoaParts {
	t.Helper()
	_, evidence := envelopeFixture(t, "snp-evidence-genoa.json")
	var env struct {
		AttestationReport string `json:"attestation_report"`
		CertChain         struct {
			VCEK string `json:"vcek"`
		} `json:"cert_chain"`
	}
	if err := json.Unmarshal(evidence, &env); err != nil {
		t.Fatal(err)
	}
	report, err := base64.StdEncoding.DecodeString(env.AttestationReport)
	if err != nil {
		t.Fatal(err)
	}
	vcek, err := base64.StdEncoding.DecodeString(env.CertChain.VCEK)
	if err != nil {
		t.Fatal(err)
	}
	return &genoaParts{report: report, vcek: vcek}
}

func (p *genoaParts) evidence(t *testing.T) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(map[string]any{
		"attestation_report": base64.StdEncoding.EncodeToString(p.report),
		"cert_chain":         map[string]string{"vcek": base64.StdEncoding.EncodeToString(p.vcek)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// foreignVCEKDER mints a self-signed P-384 certificate: no AMD key material
// exists offline, so a forged or out-of-window VCEK is necessarily self-signed.
func foreignVCEKDER(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "foreign VCEK"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestVerifyRejectsTamperedEvidence feeds the verifier the real Genoa evidence
// mutated one way per case and asserts each failure is a verdict (a plain
// error, which the CLI maps to exit 2), never a CollateralError (exit 3, "no
// verdict, retry") — a host tampering with evidence must not read as an
// infrastructure hiccup.
func TestVerifyRejectsTamperedEvidence(t *testing.T) {
	now := time.Now()

	t.Run("control: the untampered fixture verifies", func(t *testing.T) {
		if _, err := Verify(context.Background(), "snp", loadGenoaParts(t).evidence(t), Params{}); err != nil {
			t.Fatalf("the unmutated fixture must verify: %v", err)
		}
	})

	for _, tc := range []struct {
		name  string
		wreck func(t *testing.T, p *genoaParts)
	}{
		{"wrong signature", func(t *testing.T, p *genoaParts) { p.report[snpSignatureOff] ^= 0x01 }},
		{"foreign VCEK", func(t *testing.T, p *genoaParts) {
			p.vcek = foreignVCEKDER(t, now.Add(-time.Hour), now.Add(time.Hour))
		}},
		{"broken chain", func(t *testing.T, p *genoaParts) { p.vcek[len(p.vcek)-20] ^= 0x01 }},
		{"expired VCEK", func(t *testing.T, p *genoaParts) {
			p.vcek = foreignVCEKDER(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
		}},
		{"truncated report", func(t *testing.T, p *genoaParts) { p.report = p.report[:len(p.report)/2] }},
		{"zero-filled report", func(t *testing.T, p *genoaParts) { p.report = make([]byte, len(p.report)) }},
		{"in-report TCB downgrade", func(t *testing.T, p *genoaParts) {
			copy(p.report[snpReportedTCBOff:snpReportedTCBOff+8], make([]byte, 8))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := loadGenoaParts(t)
			tc.wreck(t, p)
			_, err := Verify(context.Background(), "snp", p.evidence(t), Params{})
			if err == nil {
				t.Fatal("tampered evidence must be rejected")
			}
			var ce *CollateralError
			if errors.As(err, &ce) {
				t.Fatalf("tampered evidence classified as CollateralError (exit 3, no verdict): %v", err)
			}
		})
	}
}

// TestEnforceResult drives the post-verification re-checks directly. Genuine
// evidence can never reach them (the engine returns an error instead of a
// self-contradicting verdict), so only a unit call covers the branches.
func TestEnforceResult(t *testing.T) {
	digest := strings.Repeat("ab", 48)
	good := func() *teetypes.VerificationResult {
		return &teetypes.VerificationResult{
			SignatureValid:  true,
			ReportDataMatch: teetypes.Ptr(true),
			Claims:          teetypes.Claims{LaunchDigest: digest},
		}
	}
	anchor := Params{ExpectedReportData: []byte("nonce")}

	t.Run("passing verdict", func(t *testing.T) {
		if err := enforceResult(good(), anchor); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("signature_valid false", func(t *testing.T) {
		res := good()
		res.SignatureValid = false
		if err := enforceResult(res, anchor); err == nil || !strings.Contains(err.Error(), "signature_valid=false") {
			t.Fatalf("want signature_valid rejection, got %v", err)
		}
	})

	t.Run("report_data match unreported", func(t *testing.T) {
		res := good()
		res.ReportDataMatch = nil
		if err := enforceResult(res, anchor); err == nil || !strings.Contains(err.Error(), "REPORTDATA") {
			t.Fatalf("want REPORTDATA rejection, got %v", err)
		}
	})

	t.Run("report_data mismatch", func(t *testing.T) {
		res := good()
		res.ReportDataMatch = teetypes.Ptr(false)
		if err := enforceResult(res, anchor); err == nil || !strings.Contains(err.Error(), "REPORTDATA") {
			t.Fatalf("want REPORTDATA rejection, got %v", err)
		}
	})

	t.Run("no anchor skips the binding check", func(t *testing.T) {
		res := good()
		res.ReportDataMatch = nil
		if err := enforceResult(res, Params{}); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("malformed launch digest fails the pin closed", func(t *testing.T) {
		res := good()
		res.Claims.LaunchDigest = "zz"
		p := Params{Measurements: [][]byte{bytes.Repeat([]byte{0xAB}, 48)}}
		if err := enforceResult(res, p); err == nil || !strings.Contains(err.Error(), "missing or malformed") {
			t.Fatalf("want malformed-digest rejection, got %v", err)
		}
	})

	t.Run("digest outside the allowlist", func(t *testing.T) {
		p := Params{Measurements: [][]byte{bytes.Repeat([]byte{0x00}, 48)}}
		if err := enforceResult(good(), p); !errors.Is(err, ErrMeasurementNotAllowed) {
			t.Fatalf("want ErrMeasurementNotAllowed, got %v", err)
		}
	})

	t.Run("pinned digest admitted", func(t *testing.T) {
		m, err := hex.DecodeString(digest)
		if err != nil {
			t.Fatal(err)
		}
		if err := enforceResult(good(), Params{ExpectedReportData: []byte("nonce"), Measurements: [][]byte{m}}); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})
}
