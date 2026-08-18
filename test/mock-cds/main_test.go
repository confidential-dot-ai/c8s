package main

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// TestClassifyVerifyError mirrors internal/cmds/cds.TestClassifyVerifyError: a
// rejected verdict is the caller's 401/422, only a transport or 5xx/408/429
// outage is a 502. The api-422 row is the shape mock-attestation returns for a
// report-data mismatch or garbage evidence.
func TestClassifyVerifyError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "signature invalid",
			err:        fmt.Errorf("wrap: %w", attestationclient.ErrSignatureInvalid),
			wantStatus: http.StatusUnauthorized,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "report data mismatch",
			err:        fmt.Errorf("wrap: %w", attestationclient.ErrReportDataMismatch),
			wantStatus: http.StatusUnauthorized,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "api 400 is client fault",
			err:        &attestationclient.APIError{Status: http.StatusBadRequest},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "api 403 is client fault",
			err:        &attestationclient.APIError{Status: http.StatusForbidden},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "api 422 is a mismatch or garbage refusal",
			err:        &attestationclient.APIError{Status: http.StatusUnprocessableEntity},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   types.ErrorCodeVerificationFailed,
		},
		{
			name:       "api 500 is upstream outage",
			err:        &attestationclient.APIError{Status: http.StatusInternalServerError},
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
		},
		{
			name:       "api 408 is retryable unavailability",
			err:        &attestationclient.APIError{Status: http.StatusRequestTimeout},
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
		},
		{
			name:       "api 429 is retryable unavailability",
			err:        &attestationclient.APIError{Status: http.StatusTooManyRequests},
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
		},
		{
			name:       "transport failure is unreachable",
			err:        errors.New("dial tcp: connection refused"),
			wantStatus: http.StatusBadGateway,
			wantCode:   types.ErrorCodeAttestationApiUnreachable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, code, msg := classifyVerifyError(tc.err)
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
			if msg == "" {
				t.Error("message empty")
			}
		})
	}
}
