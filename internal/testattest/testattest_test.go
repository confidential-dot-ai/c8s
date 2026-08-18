package testattest_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// The stub's /attest evidence must pass the production evidence-extraction
// path: an adopting test drives attestclient against the stub without a local
// fake.
func TestStubAttestRecordsAndReturnsSNPEvidence(t *testing.T) {
	stub := testattest.New(t)
	client := attestationclient.NewClient(stub.URL)

	reportData := types.NewBase64Bytes([]byte("0123456789abcdef0123456789abcdef0123456789abcdef"))
	resp, err := client.Attest(context.Background(), types.AttestRequest{
		ReportData: reportData,
		Platform:   types.PlatformAuto,
	})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if resp.Platform != string(types.PlatformSnp) {
		t.Fatalf("platform = %q, want snp", resp.Platform)
	}

	report, err := attestclient.ExtractSNPReport(resp)
	if err != nil {
		t.Fatalf("ExtractSNPReport: %v", err)
	}
	if len(report) != ratls.SNPReportSize {
		t.Fatalf("report = %d bytes, want %d", len(report), ratls.SNPReportSize)
	}
	var wantReportData [64]byte
	copy(wantReportData[:], reportData.Bytes())
	if got := []byte(report[0x50:0x90]); !bytes.Equal(got, wantReportData[:]) {
		t.Fatalf("REPORTDATA = %x, want %x", got, wantReportData)
	}

	reqs := stub.AttestRequests()
	if len(reqs) != 1 {
		t.Fatalf("/attest calls = %d, want 1", len(reqs))
	}
	if got := reqs[0].ReportData.Bytes(); string(got) != string(reportData.Bytes()) {
		t.Fatalf("recorded report_data = %x, want %x", got, reportData.Bytes())
	}
}

func TestStubAttestClampsReportDataToTheField(t *testing.T) {
	stub := testattest.New(t)
	client := attestationclient.NewClient(stub.URL)

	oversize := types.NewBase64Bytes(bytes.Repeat([]byte{0xAB}, 100))
	resp, err := client.Attest(context.Background(), types.AttestRequest{
		ReportData: oversize,
		Platform:   types.PlatformAuto,
	})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	report, err := attestclient.ExtractSNPReport(resp)
	if err != nil {
		t.Fatalf("ExtractSNPReport: %v", err)
	}
	if got := []byte(report[0x50:0x90]); !bytes.Equal(got, oversize.Bytes()[:64]) {
		t.Fatalf("REPORTDATA = %x, want the leading 64 bytes %x", got, oversize.Bytes()[:64])
	}
}

func TestStubAttestPlatformResolution(t *testing.T) {
	client := func(s *testattest.Stub) attestationclient.Client { return attestationclient.NewClient(s.URL) }
	attest := func(t *testing.T, s *testattest.Stub, platform types.Platform) string {
		t.Helper()
		resp, err := client(s).Attest(context.Background(), types.AttestRequest{
			ReportData: types.NewBase64Bytes([]byte("x")),
			Platform:   platform,
		})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		return resp.Platform
	}

	t.Run("auto resolves to the detected platform", func(t *testing.T) {
		stub := testattest.New(t)
		if got := attest(t, stub, types.PlatformAuto); got != string(types.PlatformSnp) {
			t.Fatalf("platform = %q, want snp", got)
		}
		stub.SetPlatform(types.PlatformTdx)
		if got := attest(t, stub, types.PlatformAuto); got != string(types.PlatformTdx) {
			t.Fatalf("platform = %q after SetPlatform(tdx), want tdx", got)
		}
	})
	t.Run("explicit platform is honored", func(t *testing.T) {
		stub := testattest.New(t)
		if got := attest(t, stub, types.PlatformGcpSnp); got != string(types.PlatformGcpSnp) {
			t.Fatalf("platform = %q, want gcp-snp", got)
		}
	})
}

func TestStubVerifyRecordsAndAnswersVerdict(t *testing.T) {
	stub := testattest.New(t)
	stub.SetVerdict(testattest.PassingVerdict("deadbeef"))
	client := attestationclient.NewClient(stub.URL)

	expected := types.NewBase64Bytes([]byte("expected-report-data"))
	req := types.VerifyReportData(types.AttestationEvidence{
		Platform: "gcp-snp",
		Evidence: []byte(`{"quote":"x"}`),
	}, expected, false, nil)
	resp, err := client.VerifyEnforced(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyEnforced against a passing verdict: %v", err)
	}
	// The response platform echoes the request's.
	if resp.Result.Platform != req.Platform {
		t.Fatalf("response platform = %q, want the request's %q", resp.Result.Platform, req.Platform)
	}

	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatalf("/verify calls = %d, want 1", len(reqs))
	}
	if reqs[0].Params == nil || reqs[0].Params.ExpectedReportData == nil {
		t.Fatal("recorded request carries no expected_report_data")
	}
	if got := reqs[0].Params.ExpectedReportData.Bytes(); string(got) != string(expected.Bytes()) {
		t.Fatalf("recorded expected_report_data = %x, want %x", got, expected.Bytes())
	}
	if reqs[0].Platform != "gcp-snp" {
		t.Fatalf("recorded platform = %q, want gcp-snp", reqs[0].Platform)
	}
}

// Defense in depth: a mismatch verdict on a 200 is a non-production shape
// (Verdict); enforcement must still fail closed on it.
func TestStubVerifyMismatchFailsEnforcement(t *testing.T) {
	stub := testattest.New(t)
	verdict := testattest.PassingVerdict("")
	match := false
	verdict.ReportDataMatch = &match
	stub.SetVerdict(verdict)
	client := attestationclient.NewClient(stub.URL)

	expected := types.NewBase64Bytes([]byte("expected-report-data"))
	req := types.VerifyReportData(types.AttestationEvidence{Platform: "snp", Evidence: []byte(`{}`)}, expected, false, nil)
	_, err := client.VerifyEnforced(context.Background(), req)
	if !errors.Is(err, attestationclient.ErrReportDataMismatch) {
		t.Fatalf("err = %v, want ErrReportDataMismatch", err)
	}
}

// The shape a refused report arrives in: HTTP 422 carrying the
// attestation-api's verification_failed envelope, which reaches Go callers as
// *attestationclient.APIError — a different branch from every verdict sentinel.
func TestStubVerifyErrorAnswersTheRefusalShape(t *testing.T) {
	stub := testattest.New(t)
	stub.SetVerifyError(testattest.VerificationFailed("report signature does not verify"))
	client := attestationclient.NewClient(stub.URL)

	expected := types.NewBase64Bytes([]byte("expected-report-data"))
	req := types.VerifyReportData(types.AttestationEvidence{Platform: "snp", Evidence: []byte(`{}`)}, expected, false, nil)
	_, err := client.VerifyEnforced(context.Background(), req)

	var apiErr *attestationclient.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %#v, want *attestationclient.APIError", err)
	}
	if apiErr.Status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", apiErr.Status)
	}
	if apiErr.Response.Error != "verification_failed" {
		t.Fatalf("error code = %q, want verification_failed", apiErr.Response.Error)
	}
	if errors.Is(err, attestationclient.ErrSignatureInvalid) || errors.Is(err, attestationclient.ErrReportDataMismatch) {
		t.Fatalf("a 422 refusal matched a verdict sentinel: %v", err)
	}

	// The refusal is decided after the body is parsed, so the request stays recorded.
	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatalf("/verify calls = %d, want 1", len(reqs))
	}
	if reqs[0].Params == nil || reqs[0].Params.ExpectedReportData == nil {
		t.Fatal("recorded request carries no expected_report_data")
	}

	// A zero reply restores the verdict.
	stub.SetVerifyError(testattest.ErrorReply{})
	if _, err := client.VerifyEnforced(context.Background(), req); err != nil {
		t.Fatalf("VerifyEnforced after a zero-Status reset: %v", err)
	}
}

// A codeless ErrorReply is the axum rejection: a status with a text/plain
// body, which the client cannot decode into the error envelope.
func TestStubVerifyErrorPlainTextBody(t *testing.T) {
	stub := testattest.New(t)
	stub.SetVerifyError(testattest.ErrorReply{
		Status:  http.StatusUnprocessableEntity,
		Message: "Failed to deserialize the JSON body into the target type",
	})
	client := attestationclient.NewClient(stub.URL)

	req := types.VerifyReportData(
		types.AttestationEvidence{Platform: "snp", Evidence: []byte(`{}`)},
		types.NewBase64Bytes([]byte("expected-report-data")),
		false,
		nil,
	)
	_, err := client.VerifyEnforced(context.Background(), req)

	var unexpected *attestationclient.UnexpectedError
	if !errors.As(err, &unexpected) {
		t.Fatalf("err = %#v, want *attestationclient.UnexpectedError", err)
	}
	if unexpected.Status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", unexpected.Status)
	}
	if !strings.Contains(unexpected.Text, "Failed to deserialize") {
		t.Fatalf("body = %q, want the plain-text rejection", unexpected.Text)
	}
}

func TestStubRejectsUnknownPaths(t *testing.T) {
	stub := testattest.New(t)
	resp, err := http.Post(stub.URL+"/nope", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// axum splits the rejection: 400 for a body that is not valid JSON, 422 for
// one that does not fit the request type.
func TestStubRejectsUndecodableBody(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		wantStatus int
		wantPrefix string
	}{
		{"not valid JSON", `not json`, http.StatusBadRequest, "Failed to parse the request body as JSON"},
		{"wrong field type", `{"platform": 123}`, http.StatusUnprocessableEntity, "Failed to deserialize the JSON body into the target type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := testattest.New(t)
			resp, err := http.Post(stub.URL+"/verify", "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", resp.StatusCode, tc.wantStatus, body)
			}
			if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
				t.Fatalf("content-type = %q, want the text/plain axum rejection", got)
			}
			if !strings.HasPrefix(string(body), tc.wantPrefix) {
				t.Fatalf("body = %q, want the axum rejection prefix %q", body, tc.wantPrefix)
			}
			if got := len(stub.VerifyRequests()); got != 0 {
				t.Fatalf("an undecodable body was recorded as %d request(s)", got)
			}
		})
	}
}
