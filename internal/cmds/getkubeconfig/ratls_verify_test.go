package getkubeconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// The guest image the tests pin: the reference registers a confos manifest
// would publish. A node reporting anything else is a different image.
const (
	testMRTD  = "93" + "09eaae9c151e766de0f97b1d1aaeb76b8c8c366080803943fb566521c8f0cf00a142d8b7b0683ed1d42c5a27198ba1"
	testRTMR1 = "7d45b1fe2b82b2bac087dd554c75b7f4cf3eacb567423afa92753b62dfb20611340840f2dd9ba0f7855de8ca5bdd2ab9"
	testRTMR2 = "5dc5581a23b2a2772adf8a80bd91c5bdeecc775a310355bc7cce8aa5cac102b741e9b977f4232bb82fe9e642712afea7"
)

// writeTestManifest writes a confos-shaped manifest.json pinning the image
// above and returns its path.
func writeTestManifest(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	body := fmt.Sprintf(`{"tdx":{"mrtd":%q,"rtmr1":%q,"rtmr2":%q}}`, testMRTD, testRTMR1, testRTMR2)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// testPins is the resolved policy for that image plus the given operator key —
// what Run derives internally, for tests that call the verify helpers directly.
func testPins(t *testing.T, operatorPubPEM []byte) pins {
	t.Helper()
	p, err := ImagePolicy{ManifestPath: writeTestManifest(t)}.resolve(operatorPubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// operatorPub is a throwaway operator public key PEM for the tests.
func operatorPub(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publicKeyPEMFromPrivate(mustKeyPEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func mustKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// attestedCert builds a genuine RA-TLS TDX cert carrying the given evidence
// envelope, bound to the cert's own key (as the real serving path does).
func attestedCert(t *testing.T, envelope types.AttestationEvidence) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	report, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	att := &ratls.Attestation{TEEType: ratls.TEETypeTDX, Report: report}
	der, err := ratls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// stubVerify replaces the in-process verifier with one that returns the given
// result/error AND enforces the pins it was handed, the way
// internal/localverify does. Emulating the comparison keeps the policy tests
// meaningful now that enforcement lives inside the stubbed function; the
// returned pointer captures the params get-kubeconfig actually asked for, so a
// test can assert the policy reaching the verifier is the full one rather than
// trusting the emulation.
func stubVerify(t *testing.T, res *teetypes.VerificationResult, err error) *localverify.Params {
	t.Helper()
	var got localverify.Params
	orig := verifyEvidenceFn
	verifyEvidenceFn = func(_ context.Context, _ string, _ json.RawMessage, p localverify.Params) (*teetypes.VerificationResult, error) {
		got = p
		if err != nil {
			return nil, err
		}
		if perr := enforceStubPins(res, p); perr != nil {
			return nil, perr
		}
		return res, nil
	}
	t.Cleanup(func() { verifyEvidenceFn = orig })
	return &got
}

// enforceStubPins mirrors internal/localverify's measurement and RTMR checks
// (which have their own tests) so a stubbed verifier still fails closed on a
// node that reports the wrong image or operator key.
func enforceStubPins(res *teetypes.VerificationResult, p localverify.Params) error {
	if res == nil {
		return nil
	}
	// Same order as localverify: the binding is judged before any pin, so a
	// substituted quote reports report_data rather than a confusing mismatch.
	if p.ExpectedReportData != nil && (res.ReportDataMatch == nil || !*res.ReportDataMatch) {
		return fmt.Errorf("REPORTDATA does not match the expected binding (report_data_match not true)")
	}
	if len(p.Measurements) > 0 {
		got, err := hex.DecodeString(res.Claims.LaunchDigest)
		if err != nil {
			return fmt.Errorf("%w: launch digest malformed", localverify.ErrMeasurementNotAllowed)
		}
		ok := false
		for _, want := range p.Measurements {
			if bytes.Equal(got, want) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w (launch digest %s)", localverify.ErrMeasurementNotAllowed, res.Claims.LaunchDigest)
		}
	}
	for i, want := range p.ExpectedRTMRs {
		if want == nil {
			continue
		}
		got, _ := res.Claims.PlatformData[fmt.Sprintf("rtmr_%d", i)].(string)
		if got == "" {
			return fmt.Errorf("%w: quote carries no rtmr_%d", localverify.ErrRTMRNotAllowed, i)
		}
		gb, err := hex.DecodeString(got)
		if err != nil || !bytes.Equal(gb, want) {
			return fmt.Errorf("%w: RTMR[%d] is %s, expected %s",
				localverify.ErrRTMRNotAllowed, i, got, hex.EncodeToString(want))
		}
	}
	return nil
}

// verifiedResult builds a passing VerificationResult for the pinned test image
// carrying the given rtmr_3.
func verifiedResult(rtmr3 string) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        teetypes.PlatformTDX,
		ReportDataMatch: teetypes.Ptr(true),
		Claims: teetypes.Claims{
			LaunchDigest: testMRTD,
			PlatformData: map[string]any{
				"rtmr_1": testRTMR1,
				"rtmr_2": testRTMR2,
				"rtmr_3": rtmr3,
			},
		},
	}
}

func TestVerifyEvidenceRejectsNonTDX(t *testing.T) {
	// A SEV-SNP node can never satisfy the RTMR[3] key binding; the gate must
	// name the platform up front, before any verification runs.
	stubVerify(t, verifiedResult("aa"), nil) // must not be reached
	_, err := verifyEvidence(context.Background(), []byte(`{"platform":"snp","evidence":{}}`), nil, testPins(t, operatorPub(t)))
	if err == nil || !strings.Contains(err.Error(), "requires a TDX guest") {
		t.Fatalf("want TDX-required error, got %v", err)
	}
}

func TestVerifyServerCertNoExtension(t *testing.T) {
	// A plain (non-RA-TLS) cert must be rejected before any verification.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	err = verifyServerCert(context.Background(), cert, testPins(t, operatorPub(t)))
	if err == nil || !strings.Contains(err.Error(), "ratls:") {
		t.Fatalf("want RA-TLS extraction error, got %v", err)
	}
}

func TestVerifyServerCertRejectsBadReportData(t *testing.T) {
	// The verifier reports the quote is valid but report_data isn't bound to
	// the cert key — a MITM presenting someone else's quote. Must fail closed.
	res := verifiedResult("aa")
	res.ReportDataMatch = teetypes.Ptr(false)
	stubVerify(t, res, nil)
	cert := attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	err := verifyServerCert(context.Background(), cert, testPins(t, operatorPub(t)))
	if err == nil || !strings.Contains(err.Error(), "report_data") {
		t.Fatalf("want report_data binding failure, got %v", err)
	}
}

func TestVerifyServerCertRejectsWrongRTMR3(t *testing.T) {
	// Genuine, key-bound quote, but rtmr_3 doesn't equal H(op_pub): the node
	// wasn't launched to trust this operator. Must fail closed.
	stubVerify(t, verifiedResult("00"), nil)
	cert := attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	err := verifyServerCert(context.Background(), cert, testPins(t, operatorPub(t)))
	if err == nil || !strings.Contains(err.Error(), "RTMR[3]") {
		t.Fatalf("want RTMR[3] mismatch, got %v", err)
	}
}

func TestVerifyServerCertAccepts(t *testing.T) {
	// Genuine quote, bound to the cert key, rtmr_3 == H(op_pub): accept.
	pub := operatorPub(t)
	stubVerify(t, verifiedResult(expectedRTMR3(pub)), nil)
	cert := attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	if err := verifyServerCert(context.Background(), cert, testPins(t, pub)); err != nil {
		t.Fatalf("want accept, got %v", err)
	}
}

// operatorPubFromKeyFile derives the public half of an operator private key on
// disk — the same derivation Run does, so a test's expected RTMR[3] matches the
// one the flow computes.
func operatorPubFromKeyFile(t *testing.T, path string) []byte {
	t.Helper()
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publicKeyPEMFromPrivate(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// attestedTDXCert is a self-signed cert carrying a TDX RA-TLS envelope bound to
// its own key — the shape cred-release serves on :8443.
func attestedTDXCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})
}
