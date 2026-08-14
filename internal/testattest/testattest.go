// Package testattest serves a fake attestation-api for tests.
//
// POST /attest records its request and answers fake SNP evidence: a report of
// ratls.SNPReportSize bytes with the requested report data clamped into the
// 64-byte REPORTDATA field, carried under attestation_report as standard
// base64 — the shape production evidence extraction
// (attestclient.ExtractSNPReport) consumes.
// The response platform resolves like the real api's: an explicit request
// platform is honored; "auto" or empty resolves to the platform the stub
// detects — snp, unless SetPlatform says otherwise.
//
// POST /verify decodes the types.VerifyRequest, records it
// (Params.ExpectedReportData included), and answers the configured Verdict.
// Tests assert on the recorded requests, so the report-data binding
// production code asks the verifier to check is pinned.
package testattest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Verdict is what the stub's /verify answers for every request; the response
// platform echoes the request's, like the real api. The fields map onto
// types.VerificationResult; ReportDataMatch is a pointer so the no-check wire
// shape (the real api's explicit null) is expressible next to true and false.
type Verdict struct {
	SignatureValid  bool
	ReportDataMatch *bool
	Claims          types.Claims
}

// PassingVerdict is the verdict for evidence that verified: signature valid,
// REPORTDATA bound, and launchDigest reported as claims.launch_digest.
func PassingVerdict(launchDigest string) Verdict {
	match := true
	return Verdict{
		SignatureValid:  true,
		ReportDataMatch: &match,
		Claims:          types.Claims{LaunchDigest: launchDigest},
	}
}

// Stub is an httptest.Server speaking the attestation-api wire protocol. The
// default verdict is PassingVerdict("") and the detected platform snp; change
// them with SetVerdict and SetPlatform.
type Stub struct {
	*httptest.Server

	mu       sync.Mutex
	verdict  Verdict
	platform types.Platform
	attest   []types.AttestRequest
	verify   []types.VerifyRequest
}

// New starts a stub attestation-api, closed at test cleanup.
func New(t testing.TB) *Stub {
	t.Helper()
	s := &Stub{verdict: PassingVerdict(""), platform: types.PlatformSnp}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /attest", s.handleAttest)
	mux.HandleFunc("POST /verify", s.handleVerify)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// SetVerdict swaps the verdict /verify answers with.
func (s *Stub) SetVerdict(v Verdict) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verdict = v
}

// SetPlatform sets the platform the stub reports detecting: what /attest
// resolves an "auto" or empty request platform to. The evidence bytes stay
// an SNP report whatever the platform label.
func (s *Stub) SetPlatform(p types.Platform) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.platform = p
}

// AttestRequests returns the /attest requests received so far, in order.
func (s *Stub) AttestRequests() []types.AttestRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]types.AttestRequest(nil), s.attest...)
}

// VerifyRequests returns the /verify requests received so far, in order.
func (s *Stub) VerifyRequests() []types.VerifyRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]types.VerifyRequest(nil), s.verify...)
}

func (s *Stub) handleAttest(w http.ResponseWriter, r *http.Request) {
	var req types.AttestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	s.attest = append(s.attest, req)
	platform := s.platform
	s.mu.Unlock()

	if req.Platform != "" && req.Platform != types.PlatformAuto {
		platform = req.Platform
	}
	writeJSON(w, types.AttestResponse{
		Platform: string(platform),
		Evidence: fakeSNPEvidence(req.ReportData.Bytes()),
	})
}

// fakeSNPEvidence wraps a minimal SEV-SNP report — version 2, SMT-allowed
// policy, the requested report data in the 64-byte REPORTDATA field at
// 0x50 — in the attestation_report envelope ExtractSNPReport reads.
func fakeSNPEvidence(reportData []byte) json.RawMessage {
	report := make([]byte, 1184) // AMD SEV-SNP report size (ratls.SNPReportSize)
	report[0] = 0x02
	report[0x0A] = 0x03
	copy(report[0x50:0x90], reportData)
	evidence, _ := json.Marshal(map[string]string{
		"attestation_report": base64.StdEncoding.EncodeToString(report),
	})
	return evidence
}

func (s *Stub) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req types.VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	s.verify = append(s.verify, req)
	verdict := s.verdict
	s.mu.Unlock()

	writeJSON(w, types.VerifyResponse{
		Result: types.VerificationResult{
			Platform:        req.Platform,
			SignatureValid:  verdict.SignatureValid,
			ReportDataMatch: verdict.ReportDataMatch,
			Claims:          verdict.Claims,
		},
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(types.ErrorResponse{Error: "bad_request", Message: message})
}
