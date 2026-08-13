// Package testattest serves a fake attestation-api for tests. POST /attest
// records its request and returns fake SNP evidence; POST /verify decodes
// the types.VerifyRequest, records it (Params.ExpectedReportData included),
// and answers with the configured Verdict. Tests assert on the recorded
// requests, so the report-data binding production code asks the verifier to
// check is pinned rather than answered blindly.
package testattest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Verdict is what the stub's /verify answers for every request. The fields
// map onto types.VerificationResult; ReportDataMatch is a pointer so a test
// can send the omitted-field shape the real api returns when no
// expected_report_data was checked.
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
// default verdict is PassingVerdict(""); change it with SetVerdict.
type Stub struct {
	*httptest.Server

	mu      sync.Mutex
	verdict Verdict
	attest  []types.AttestRequest
	verify  []types.VerifyRequest
}

// New starts a stub attestation-api, closed at test cleanup.
func New(t testing.TB) *Stub {
	t.Helper()
	s := &Stub{verdict: PassingVerdict("")}
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
	s.mu.Unlock()

	// The fake evidence carries the report data it was minted over, so what a
	// caller asked to bind stays visible in the evidence itself.
	evidence, err := json.Marshal(map[string]any{
		"report_data": req.ReportData,
		"stub":        true,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, types.AttestResponse{
		Platform: string(types.PlatformSnp),
		Evidence: evidence,
	})
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
