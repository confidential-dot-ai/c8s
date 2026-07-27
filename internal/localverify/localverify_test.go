package localverify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// envelopeFixture loads a real captured {platform, evidence} fixture (vendored
// from attestation-go / c8s-verify-js testdata; also used by the verify
// command's tests).
func envelopeFixture(t *testing.T, name string) (platform string, evidence json.RawMessage) {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Platform string          `json:"platform"`
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	return env.Platform, env.Evidence
}

// TestVerifyRealAzSnpEvidence_MeasurementPin drives real az-snp evidence (vTPM
// quote extraData = ASCII "challenge", VCEK inline, so it verifies fully
// offline) through the engine and exercises the launch-digest pin — the policy
// this package enforces on attestation-go's claims.
func TestVerifyRealAzSnpEvidence_MeasurementPin(t *testing.T) {
	platform, evidence := envelopeFixture(t, "azsnp-evidence-v1.json")
	if platform != "az-snp" {
		t.Fatalf("platform = %q, want az-snp", platform)
	}
	anchor := Params{ExpectedReportData: []byte("challenge")}

	res, err := Verify(context.Background(), platform, evidence, anchor)
	if err != nil {
		t.Fatalf("az-snp evidence with its bound nonce must verify: %v", err)
	}
	digest, err := hex.DecodeString(res.Claims.LaunchDigest)
	if err != nil || len(digest) == 0 {
		t.Fatalf("verified evidence must report a launch digest, got %q", res.Claims.LaunchDigest)
	}

	pinned := anchor
	pinned.Measurements = [][]byte{digest}
	if _, err := Verify(context.Background(), platform, evidence, pinned); err != nil {
		t.Fatalf("the evidence's own launch digest must satisfy the pin: %v", err)
	}

	mismatched := anchor
	mismatched.Measurements = [][]byte{bytes.Repeat([]byte{0xAA}, len(digest))}
	if _, err := Verify(context.Background(), platform, evidence, mismatched); !errors.Is(err, ErrMeasurementNotAllowed) {
		t.Fatalf("want ErrMeasurementNotAllowed, got: %v", err)
	}

	wrongAnchor := Params{ExpectedReportData: []byte("not-the-nonce")}
	if _, err := Verify(context.Background(), platform, evidence, wrongAnchor); err == nil {
		t.Fatal("a wrong binding anchor must fail closed")
	}
}

// TestVerify_KDSFailureIsCollateralError proves a bare SNP report (cert_chain
// stripped, forcing the AMD KDS fetch) under an expired context classifies as
// CollateralError — no verdict — and returns promptly. A cancelled context
// aborts http before any I/O, so no network is touched.
func TestVerify_KDSFailureIsCollateralError(t *testing.T) {
	platform, evidence := envelopeFixture(t, "snp-evidence-genoa.json")
	var inner struct {
		AttestationReport string `json:"attestation_report"`
	}
	if err := json.Unmarshal(evidence, &inner); err != nil {
		t.Fatal(err)
	}
	bare, err := json.Marshal(map[string]string{"attestation_report": inner.AttestationReport})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err = Verify(ctx, platform, bare, Params{})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("expired ctx took %v, want prompt return", elapsed)
	}
	var ce *CollateralError
	if !errors.As(err, &ce) {
		t.Fatalf("KDS fetch failure must classify as CollateralError, got: %v", err)
	}
}

func TestEnvelopeFromAttestation(t *testing.T) {
	t.Run("snp raw report wraps as attestation_report, omits empty cert_chain", func(t *testing.T) {
		platform, raw, err := EnvelopeFromAttestation(&ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: []byte{9}})
		if err != nil {
			t.Fatal(err)
		}
		if platform != "snp" {
			t.Errorf("platform = %q, want snp", platform)
		}
		var inner map[string]any
		_ = json.Unmarshal(raw, &inner)
		if inner["attestation_report"] != base64.StdEncoding.EncodeToString([]byte{9}) {
			t.Errorf("attestation_report = %v", inner["attestation_report"])
		}
		// No VCEK in the cert → the verifier fetches it from KDS, so omit cert_chain.
		if _, ok := inner["cert_chain"]; ok {
			t.Errorf("bare report must omit cert_chain, got %v", inner)
		}
	})

	t.Run("snp with cert chain includes vcek", func(t *testing.T) {
		_, raw, err := EnvelopeFromAttestation(&ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: []byte{1}, CertChain: []byte{4, 5}})
		if err != nil {
			t.Fatal(err)
		}
		var inner map[string]any
		_ = json.Unmarshal(raw, &inner)
		cc, _ := inner["cert_chain"].(map[string]any)
		if cc == nil || cc["vcek"] != base64.StdEncoding.EncodeToString([]byte{4, 5}) {
			t.Errorf("cert_chain.vcek missing/wrong: %v", inner["cert_chain"])
		}
	})

	t.Run("raw TDX report is rejected (use discovery/endpoint)", func(t *testing.T) {
		if _, _, err := EnvelopeFromAttestation(&ratls.Attestation{TEEType: ratls.TEETypeTDX, Report: []byte{1}}); err == nil {
			t.Fatal("expected a raw TDX report from a cert to be rejected")
		}
	})
}
