package testattest_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

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
	if !strings.Contains(string(resp.Evidence), "report_data") {
		t.Fatalf("evidence does not carry the report data: %s", resp.Evidence)
	}

	reqs := stub.AttestRequests()
	if len(reqs) != 1 {
		t.Fatalf("/attest calls = %d, want 1", len(reqs))
	}
	if got := reqs[0].ReportData.Bytes(); string(got) != string(reportData.Bytes()) {
		t.Fatalf("recorded report_data = %x, want %x", got, reportData.Bytes())
	}
}

func TestStubVerifyRecordsAndAnswersVerdict(t *testing.T) {
	stub := testattest.New(t)
	stub.SetVerdict(testattest.PassingVerdict("deadbeef"))
	client := attestationclient.NewClient(stub.URL)

	expected := types.NewBase64Bytes([]byte("expected-report-data"))
	req := types.VerifyReportData(types.AttestationEvidence{
		Platform: "snp",
		Evidence: []byte(`{"quote":"x"}`),
	}, expected)
	if _, err := client.VerifyEnforced(context.Background(), req); err != nil {
		t.Fatalf("VerifyEnforced against a passing verdict: %v", err)
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
	if reqs[0].Platform != "snp" {
		t.Fatalf("recorded platform = %q, want snp", reqs[0].Platform)
	}
}

func TestStubVerifyMismatchFailsEnforcement(t *testing.T) {
	stub := testattest.New(t)
	verdict := testattest.PassingVerdict("")
	match := false
	verdict.ReportDataMatch = &match
	stub.SetVerdict(verdict)
	client := attestationclient.NewClient(stub.URL)

	expected := types.NewBase64Bytes([]byte("expected-report-data"))
	req := types.VerifyReportData(types.AttestationEvidence{Platform: "snp", Evidence: []byte(`{}`)}, expected)
	_, err := client.VerifyEnforced(context.Background(), req)
	if !errors.Is(err, attestationclient.ErrReportDataMismatch) {
		t.Fatalf("err = %v, want ErrReportDataMismatch", err)
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

func TestStubRejectsUndecodableBody(t *testing.T) {
	stub := testattest.New(t)
	resp, err := http.Post(stub.URL+"/verify", "application/json", strings.NewReader(`not json`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := len(stub.VerifyRequests()); got != 0 {
		t.Fatalf("an undecodable body was recorded as %d request(s)", got)
	}
}
