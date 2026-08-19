package getkubeconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
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

func TestVerifyEvidenceRejectsPlatformMismatch(t *testing.T) {
	// A node whose platform differs from the one the manifest describes can
	// never satisfy the gate; it must be named up front, before any
	// verification runs. (An SNP node IS acceptable against an SNP manifest —
	// see the snp_variants path — but never against a TDX tuple.)
	exp := testPolicy(t, operatorPub(t))
	stubVerify(t, verifiedResultFor(exp), nil) // must not be reached
	_, err := verifyEvidence([]byte(`{"platform":"snp","evidence":{}}`), nil, exp)
	if err == nil || !strings.Contains(err.Error(), "the platform the manifest describes") {
		t.Fatalf("want platform-mismatch error, got %v", err)
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

// snpTestPolicy builds an SNP gate from a two-variant manifest carrying the
// digests confirmed against hardware on build 9ce1642 (smp2 and smp4).
func snpTestPolicy(t *testing.T, operatorPubPEM []byte) measuredPolicy {
	t.Helper()
	const smp2 = "e9dd4de2ddc59700fa8842fff7e9d80605d433d8d32e8b4112afd761b96506e4e67d97139df5cad76dfa5881c7b11ff5"
	const smp4 = "a0185a3b93d8a10438fc2c2445edf9908c6de694350a3eaf2f55277d5287fd3532a02994c1e2932809da4147d8b58c97"
	p := filepath.Join(t.TempDir(), "manifest.json")
	body := `{"version":3,"snp_variants":[
	  {"smp":2,"measurement":{"snp_launch_digest":"` + smp2 + `","algorithm":"sha384"}},
	  {"smp":4,"measurement":{"snp_launch_digest":"` + smp4 + `","algorithm":"sha384"}}]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	exp, err := policyFor(p, operatorPubPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	if exp.platform != teetypes.PlatformSNP {
		t.Fatalf("policy platform = %q, want snp", exp.platform)
	}
	return exp
}

func snpResultFor(exp measuredPolicy, smp int) *teetypes.VerificationResult {
	digest := exp.snpPins.BySMP[smp]
	return &teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        teetypes.PlatformSNP,
		ReportDataMatch: teetypes.Ptr(true),
		Claims: teetypes.Claims{
			LaunchDigest: hex.EncodeToString(digest[:]),
			InitData:     teetypes.HexBytes(exp.hostData[:]),
		},
	}
}

// Either pinned vCPU variant of the same image satisfies the gate: SNP's
// MEASUREMENT covers initial vCPU state, so one image has one digest per SMP.
func TestSNPGateAcceptsEveryPinnedVariant(t *testing.T) {
	exp := snpTestPolicy(t, operatorPub(t))
	for _, smp := range []int{2, 4} {
		if err := checkMeasuredIdentity(snpResultFor(exp, smp), exp); err != nil {
			t.Errorf("smp%d: %v", smp, err)
		}
	}
}

// Every way the SNP gate must fail closed.
func TestSNPGateFailsClosed(t *testing.T) {
	exp := snpTestPolicy(t, operatorPub(t))
	other := snpTestPolicy(t, operatorPub(t)) // a different operator key

	cases := map[string]func(*teetypes.VerificationResult){
		"unpinned launch digest (different image)": func(r *teetypes.VerificationResult) {
			r.Claims.LaunchDigest = strings.Repeat("ab", runtimemeasure.Size)
		},
		"no launch digest": func(r *teetypes.VerificationResult) {
			r.Claims.LaunchDigest = ""
		},
		"malformed launch digest": func(r *teetypes.VerificationResult) {
			r.Claims.LaunchDigest = "not-hex"
		},
		"keyless launch (all-zero HOSTDATA)": func(r *teetypes.VerificationResult) {
			r.Claims.InitData = teetypes.HexBytes(make([]byte, runtimemeasure.HostDataSize))
		},
		"HOSTDATA of a different operator key": func(r *teetypes.VerificationResult) {
			r.Claims.InitData = teetypes.HexBytes(other.hostData[:])
		},
		"no HOSTDATA": func(r *teetypes.VerificationResult) {
			r.Claims.InitData = nil
		},
		"TDX-width MRCONFIGID must not truncate": func(r *teetypes.VerificationResult) {
			r.Claims.InitData = teetypes.HexBytes(make([]byte, runtimemeasure.Size))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			res := snpResultFor(exp, 2)
			mutate(res)
			if err := checkMeasuredIdentity(res, exp); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// SNP has no runtime-extend register, so claiming workload enforcement is a
// usage error rather than a silently-ignored flag.
func TestSNPPolicyRejectsWorkloadImages(t *testing.T) {
	const smp2 = "e9dd4de2ddc59700fa8842fff7e9d80605d433d8d32e8b4112afd761b96506e4e67d97139df5cad76dfa5881c7b11ff5"
	p := filepath.Join(t.TempDir(), "manifest.json")
	body := `{"snp_variants":[{"smp":2,"measurement":{"snp_launch_digest":"` + smp2 + `","algorithm":"sha384"}}]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policyFor(p, operatorPub(t), []string{"repo@sha256:" + strings.Repeat("c", 64)})
	if err == nil || !strings.Contains(err.Error(), "requires a TDX node") {
		t.Fatalf("want workload-image rejection, got %v", err)
	}
}

// stubSNPRATLS replaces the localverify call the SNP dial uses, so the arm is
// testable without AMD KDS. Records the params it was asked to enforce.
func stubSNPRATLS(t *testing.T, res *teetypes.VerificationResult, err error) *localverify.Params {
	t.Helper()
	var got localverify.Params
	orig := verifySNPRATLS
	verifySNPRATLS = func(_ context.Context, _ string, _ json.RawMessage, p localverify.Params) (*teetypes.VerificationResult, error) {
		got = p
		return res, err
	}
	t.Cleanup(func() { verifySNPRATLS = orig })
	return &got
}

// snpAttestedCert builds an RA-TLS cert carrying a RAW SNP report — the shape
// bare-metal SNP guests actually present (no JSON envelope), which is why the
// dial has its own arm.
func snpAttestedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := ratls.ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Minimal raw report: REPORTDATA at its fixed offset is what CertEnvelope
	// reads; the rest stays zero (the stubbed verifier supplies the verdict).
	report := make([]byte, 1184)
	copy(report[0x50:], rd[:])
	att := &ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: report}
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

// The SNP dial must enforce the SAME two pins as the attest gate — this is
// the leg that silently could not run before, since bare-metal SNP certs
// carry no embedded envelope.
func TestVerifyServerCertSNPEnforcesBothPins(t *testing.T) {
	exp := snpTestPolicy(t, operatorPub(t))
	params := stubSNPRATLS(t, snpResultFor(exp, 2), nil)

	if err := verifyServerCert(snpAttestedCert(t), exp); err != nil {
		t.Fatalf("verifyServerCert: %v", err)
	}
	// Both pins must have been handed to the verifier, not just checked after.
	if len(params.Measurements) != len(exp.snpPins.BySMP) {
		t.Errorf("passed %d measurements, want %d (every pinned SMP variant)", len(params.Measurements), len(exp.snpPins.BySMP))
	}
	if !bytes.Equal(params.ExpectedInitDataHash, exp.hostData[:]) {
		t.Errorf("ExpectedInitDataHash = %x, want the operator-key binding %x", params.ExpectedInitDataHash, exp.hostData)
	}
	if len(params.ExpectedReportData) == 0 {
		t.Error("ExpectedReportData empty: the quote would not be bound to this TLS channel")
	}
}

// A verdict that contradicts the pins must be refused even if the engine
// returned success (defense in depth).
func TestVerifyServerCertSNPRejectsContradictoryClaims(t *testing.T) {
	exp := snpTestPolicy(t, operatorPub(t))
	other := snpTestPolicy(t, operatorPub(t))

	for name, res := range map[string]*teetypes.VerificationResult{
		"wrong HOSTDATA": func() *teetypes.VerificationResult {
			r := snpResultFor(exp, 2)
			r.Claims.InitData = teetypes.HexBytes(other.hostData[:])
			return r
		}(),
		"unpinned launch digest": func() *teetypes.VerificationResult {
			r := snpResultFor(exp, 2)
			r.Claims.LaunchDigest = strings.Repeat("ab", runtimemeasure.Size)
			return r
		}(),
		"signature not valid": func() *teetypes.VerificationResult {
			r := snpResultFor(exp, 2)
			r.SignatureValid = false
			return r
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			stubSNPRATLS(t, res, nil)
			if err := verifyServerCert(snpAttestedCert(t), exp); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// A verifier refusal (bad evidence, KDS failure) must fail the dial closed.
func TestVerifyServerCertSNPPropagatesVerifierError(t *testing.T) {
	exp := snpTestPolicy(t, operatorPub(t))
	stubSNPRATLS(t, nil, fmt.Errorf("collateral unavailable"))
	if err := verifyServerCert(snpAttestedCert(t), exp); err == nil {
		t.Fatal("expected error, got nil")
	}
}
