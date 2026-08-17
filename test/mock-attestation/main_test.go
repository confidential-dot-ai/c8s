package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// TestWriteDecodeErrorShapes mirrors internal/testattest.TestStubRejectsUndecodableBody:
// axum splits the rejection 400 for a body that is not valid JSON, 422 for one
// that does not fit the request type; both text/plain with no error code, so
// callers see UnexpectedError, not APIError. Wired into /attest and /verify.
func TestWriteDecodeErrorShapes(t *testing.T) {
	for _, ep := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/attest", handleAttest},
		{"/verify", handleVerify},
	} {
		for _, tc := range []struct {
			name       string
			body       string
			wantStatus int
			wantPrefix string
		}{
			{"not valid JSON", `not json`, http.StatusBadRequest, "Failed to parse the request body as JSON"},
			{"wrong field type", `{"platform": 123}`, http.StatusUnprocessableEntity, "Failed to deserialize the JSON body into the target type"},
		} {
			t.Run(ep.path+" "+tc.name, func(t *testing.T) {
				rec := httptest.NewRecorder()
				ep.handler(rec, httptest.NewRequest(http.MethodPost, ep.path, strings.NewReader(tc.body)))

				res := rec.Result()
				body, _ := io.ReadAll(res.Body)
				if res.StatusCode != tc.wantStatus {
					t.Fatalf("status = %d, want %d (body %q)", res.StatusCode, tc.wantStatus, body)
				}
				if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
					t.Fatalf("content-type = %q, want text/plain", ct)
				}
				if !strings.HasPrefix(string(body), tc.wantPrefix) {
					t.Fatalf("body = %q, want prefix %q", body, tc.wantPrefix)
				}
				var er types.ErrorResponse
				if json.Unmarshal(body, &er) == nil && er.Error != "" {
					t.Fatalf("decode error carried code %q, want none", er.Error)
				}
			})
		}
	}
}

// TestVerifyRefusesMismatchAndGarbage pins the /verify refusal: a report-data
// mismatch or unparseable evidence is a 422 verification_failed JSON envelope —
// the real api's shape mock-cds classifies (never a 200+false verdict).
func TestVerifyRefusesMismatchAndGarbage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		evidence json.RawMessage
		expected []byte
	}{
		{
			name:     "report data mismatch",
			evidence: snpEvidence(t, bytes.Repeat([]byte{0xAA}, reportDataSize)),
			expected: bytes.Repeat([]byte{0xBB}, reportDataSize),
		},
		{
			name:     "garbage evidence",
			evidence: json.RawMessage(`{"attestation_report":"AAAA"}`),
			expected: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := types.VerifyRequest{Platform: string(types.PlatformSnp), Evidence: tc.evidence}
			if tc.expected != nil {
				rd := types.NewBase64Bytes(tc.expected)
				req.Params = &types.VerifyParams{ExpectedReportData: &rd}
			}
			body, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			handleVerify(rec, httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body)))

			res := rec.Result()
			raw, _ := io.ReadAll(res.Body)
			if res.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422 (body %q)", res.StatusCode, raw)
			}
			if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("content-type = %q, want application/json", ct)
			}
			var er types.ErrorResponse
			if err := json.Unmarshal(raw, &er); err != nil {
				t.Fatalf("body %q is not an error envelope: %v", raw, err)
			}
			if er.Error != types.ErrorCodeVerificationFailed {
				t.Fatalf("error = %q, want %q", er.Error, types.ErrorCodeVerificationFailed)
			}
		})
	}
}

// snpEvidence builds an SNP evidence envelope carrying a version-2 report with
// the given REPORTDATA, the shape the mock's /attest issues.
func snpEvidence(t *testing.T, reportData []byte) json.RawMessage {
	t.Helper()
	report := make([]byte, snpReportSize)
	report[0] = 0x02
	copy(report[reportDataOffset:reportDataOffset+reportDataSize], reportData)
	env, err := json.Marshal(map[string]string{
		"attestation_report": base64.StdEncoding.EncodeToString(report),
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}
