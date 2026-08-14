package getkubeconfig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// The fixed guest-image tuple the test manifests pin.
var (
	testMRTDHex  = strings.Repeat("1a", 48)
	testRTMR1Hex = strings.Repeat("2b", 48)
	testRTMR2Hex = strings.Repeat("3c", 48)
)

// writeTestManifest writes a build-artifact manifest carrying the test tuple.
func writeTestManifest(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	content := `{"mrtd":"` + testMRTDHex + `","rtmr1":"` + testRTMR1Hex + `","rtmr2":"` + testRTMR2Hex + `"}`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// testPolicy builds the full measured policy for the test tuple + operator
// key, with no workload images (bare-seed RTMR[3]).
func testPolicy(t *testing.T, operatorPubPEM []byte) measuredPolicy {
	t.Helper()
	exp, err := policyFor(writeTestManifest(t), operatorPubPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	return exp
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

// capturedVerify records one call to the stubbed verifier: the evidence
// envelope and the params production code asked it to enforce.
type capturedVerify struct {
	envelope []byte
	params   teetypes.VerifyParams
}

// verifyRecorder collects verifier calls; the RA-TLS dial can invoke the
// verifier off the test goroutine, so reads and writes go through the mutex.
type verifyRecorder struct {
	mu    sync.Mutex
	calls []capturedVerify
}

func (r *verifyRecorder) add(envelope []byte, params teetypes.VerifyParams) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, capturedVerify{envelope, params})
}

func (r *verifyRecorder) all() []capturedVerify {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]capturedVerify(nil), r.calls...)
}

// stubVerify replaces the in-process attestation-go verifier with one that
// returns the given result/error and records what it was asked to check, so
// tests can pin the request side (the report_data binding), not just the
// verdict. Lets the tests drive verifyServerCert's post-verification logic
// deterministically without real hardware.
func stubVerify(t *testing.T, res *teetypes.VerificationResult, err error) *verifyRecorder {
	t.Helper()
	rec := &verifyRecorder{}
	orig := verifyEnvelope
	verifyEnvelope = func(envelope []byte, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
		rec.add(envelope, params)
		return res, err
	}
	t.Cleanup(func() { verifyEnvelope = orig })
	return rec
}

// verifiedResultFor builds a passing VerificationResult whose claims satisfy
// exp exactly. Tests break individual claims from here.
func verifiedResultFor(exp measuredPolicy) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        teetypes.PlatformTDX,
		ReportDataMatch: teetypes.Ptr(true),
		Claims: teetypes.Claims{
			LaunchDigest: hex.EncodeToString(exp.pins.MRTD[:]),
			PlatformData: map[string]any{
				"rtmr_1": hex.EncodeToString(exp.pins.RTMR1[:]),
				"rtmr_2": hex.EncodeToString(exp.pins.RTMR2[:]),
				"rtmr_3": hex.EncodeToString(exp.rtmr3[:]),
			},
		},
	}
}

func TestVerifyEvidenceRejectsNonTDX(t *testing.T) {
	// A SEV-SNP node can never satisfy the measured-identity gate; it must be
	// named up front, before any verification runs.
	exp := testPolicy(t, operatorPub(t))
	stubVerify(t, verifiedResultFor(exp), nil) // must not be reached
	_, err := verifyEvidence([]byte(`{"platform":"snp","evidence":{}}`), nil, exp)
	if err == nil || !strings.Contains(err.Error(), "requires a TDX guest") {
		t.Fatalf("want TDX-required error, got %v", err)
	}
}

func TestVerifyServerCertNoExtension(t *testing.T) {
	// A plain (non-RA-TLS) cert must be rejected before any verification.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	err = verifyServerCert(cert, testPolicy(t, operatorPub(t)))
	if err == nil || !strings.Contains(err.Error(), "ratls:") {
		t.Fatalf("want RA-TLS extraction error, got %v", err)
	}
}

func TestVerifyServerCertRejectsBadReportData(t *testing.T) {
	// The verifier reports the quote is valid but report_data isn't bound to
	// the cert key — a MITM presenting someone else's quote. Must fail closed.
	exp := testPolicy(t, operatorPub(t))
	res := verifiedResultFor(exp)
	res.ReportDataMatch = teetypes.Ptr(false)
	stubVerify(t, res, nil)
	cert := attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	err := verifyServerCert(cert, exp)
	if err == nil || !strings.Contains(err.Error(), "report_data") {
		t.Fatalf("want report_data binding failure, got %v", err)
	}
}

// The RA-TLS dial enforces the IDENTICAL policy as the attest gate: every
// register of the measured identity fails it independently.
func TestVerifyServerCertRejectsEachMismatchedRegister(t *testing.T) {
	pub := operatorPub(t)
	for _, tc := range []struct {
		name  string
		wreck func(res *teetypes.VerificationResult)
		want  string
	}{
		{"wrong MRTD", func(r *teetypes.VerificationResult) {
			r.Claims.LaunchDigest = strings.Repeat("00", 48)
		}, "MRTD mismatch"},
		{"wrong rtmr1", func(r *teetypes.VerificationResult) {
			r.Claims.PlatformData["rtmr_1"] = strings.Repeat("00", 48)
		}, "RTMR[1] mismatch"},
		{"wrong rtmr2", func(r *teetypes.VerificationResult) {
			r.Claims.PlatformData["rtmr_2"] = strings.Repeat("00", 48)
		}, "RTMR[2] mismatch"},
		{"wrong rtmr3", func(r *teetypes.VerificationResult) {
			r.Claims.PlatformData["rtmr_3"] = strings.Repeat("00", 48)
		}, "RTMR[3] mismatch"},
		{"absent MRTD", func(r *teetypes.VerificationResult) {
			r.Claims.LaunchDigest = ""
		}, "no launch digest"},
		{"absent rtmr3", func(r *teetypes.VerificationResult) {
			delete(r.Claims.PlatformData, "rtmr_3")
		}, "no rtmr_3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp := testPolicy(t, pub)
			res := verifiedResultFor(exp)
			tc.wreck(res)
			stubVerify(t, res, nil)
			cert := attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

			err := verifyServerCert(cert, exp)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestVerifyServerCertAccepts(t *testing.T) {
	// Genuine quote, bound to the cert key, full measured identity: accept.
	exp := testPolicy(t, operatorPub(t))
	rec := stubVerify(t, verifiedResultFor(exp), nil)
	cert := attestedCert(t, types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	if err := verifyServerCert(cert, exp); err != nil {
		t.Fatalf("want accept, got %v", err)
	}
	// The verifier must be asked to bind the quote to THIS cert's public key —
	// the check that ties the RA-TLS channel to the attested guest.
	want, err := ratls.ReportDataForKey(cert.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := rec.all()
	if len(calls) != 1 {
		t.Fatalf("verifier calls = %d, want 1", len(calls))
	}
	if !bytes.Equal(calls[0].params.ExpectedReportData, want[:]) {
		t.Errorf("report_data binding = %x, want SHA-384(cert key) %x", calls[0].params.ExpectedReportData, want[:])
	}
}

// mintServingCert builds a self-issued RA-TLS-shaped cert with chosen
// validity, embedded key from holder, and signature from signer.
func mintServingCert(t *testing.T, holder *ecdsa.PublicKey, signer *ecdsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	report, err := json.Marshal(types.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	att := &ratls.Attestation{TEEType: ratls.TEETypeTDX, Report: report}
	ext, err := att.MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(9),
		Subject:         pkix.Name{CommonName: "cred-release"},
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, holder, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The presented cert's body is authenticated before its quote is trusted:
// validity within the shared skew bound, and the self-signature under the
// cert's own key.
func TestVerifyServerCertAuthenticatesBody(t *testing.T) {
	now := time.Now()
	exp := testPolicy(t, operatorPub(t))
	stubVerify(t, verifiedResultFor(exp), nil)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("expired serving cert rejected", func(t *testing.T) {
		cert := mintServingCert(t, &key.PublicKey, key, now.Add(-2*time.Hour), now.Add(-time.Minute))
		if err := verifyServerCert(cert, exp); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("want expiry rejection, got %v", err)
		}
	})

	t.Run("future serving cert rejected", func(t *testing.T) {
		cert := mintServingCert(t, &key.PublicKey, key, now.Add(time.Hour), now.Add(2*time.Hour))
		if err := verifyServerCert(cert, exp); err == nil || !strings.Contains(err.Error(), "not yet valid") {
			t.Fatalf("want NotBefore rejection, got %v", err)
		}
	})

	t.Run("re-signed body rejected", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := mintServingCert(t, &key.PublicKey, other, now.Add(-time.Hour), now.Add(time.Hour))
		if err := verifyServerCert(cert, exp); err == nil ||
			!strings.Contains(err.Error(), "does not verify with its own key") {
			t.Fatalf("want self-signature rejection, got %v", err)
		}
	})

	t.Run("valid body accepted", func(t *testing.T) {
		cert := mintServingCert(t, &key.PublicKey, key, now.Add(-time.Hour), now.Add(time.Hour))
		if err := verifyServerCert(cert, exp); err != nil {
			t.Fatalf("want accept, got %v", err)
		}
	})
}
