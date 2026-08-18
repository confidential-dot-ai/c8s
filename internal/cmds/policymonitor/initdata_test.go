package policymonitor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/initdata"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// hostDataVerdict passes verification and reports hostData as the HOST_DATA claim.
func hostDataVerdict(hostData []byte) testattest.Verdict {
	v := testattest.PassingVerdict("")
	v.Claims.InitData = hex.EncodeToString(hostData)
	return v
}

// testHostData is an arbitrary well-formed anchor.
func testHostData() []byte { return bytes.Repeat([]byte{0xa5}, initdata.DigestSize) }

// attesterServing returns the URL of a stub in-guest attestation-api that
// verifies this guest's report and reports hostData as its HOST_DATA.
func attesterServing(t *testing.T, hostData []byte) string {
	t.Helper()
	return attesterWithVerdict(t, hostDataVerdict(hostData))
}

func attesterWithVerdict(t *testing.T, v testattest.Verdict) string {
	t.Helper()
	stub := testattest.New(t)
	stub.SetVerdict(v)
	return stub.URL
}

// scriptedVerifier is an in-guest attestation-api whose /attest comes from the
// shared stub and whose /verify answers status for its first `failures` calls
// before proxying to the stub; failures < 0 fails every call. Verify calls are
// counted here because a refused one never reaches the stub.
type scriptedVerifier struct {
	url      string
	attester *testattest.Stub

	mu    sync.Mutex
	calls int
}

func newScriptedVerifier(t *testing.T, status, failures int) *scriptedVerifier {
	t.Helper()
	v := &scriptedVerifier{attester: testattest.New(t)}
	v.attester.SetVerdict(hostDataVerdict(testHostData()))

	target, err := url.Parse(v.attester.URL)
	if err != nil {
		t.Fatalf("parse stub URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	mux := http.NewServeMux()
	mux.Handle("POST /attest", proxy)
	mux.HandleFunc("POST /verify", func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		v.calls++
		n := v.calls
		v.mu.Unlock()
		if failures >= 0 && n > failures {
			proxy.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(types.ErrorResponse{Error: "verification_failed", Message: "evidence rejected"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	v.url = srv.URL
	return v
}

func (v *scriptedVerifier) verifyCalls() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

// levelRecorder captures each record's level so a test can pin the operator
// signal, not only the outcome.
type levelRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (l *levelRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (l *levelRecorder) WithAttrs([]slog.Attr) slog.Handler       { return l }
func (l *levelRecorder) WithGroup(string) slog.Handler            { return l }

func (l *levelRecorder) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, r)
	return nil
}

// levelOf is the level of the first record whose message contains substr.
func (l *levelRecorder) levelOf(t *testing.T, substr string) slog.Level {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.records {
		if strings.Contains(r.Message, substr) {
			return r.Level
		}
	}
	t.Fatalf("no log record mentioning %q", substr)
	return 0
}

// writeInitData points initDataDocumentPath at a tempdir holding raw.
func writeInitData(t *testing.T, raw []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "initdata.toml")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write init-data: %v", err)
	}
	old := initDataDocumentPath
	initDataDocumentPath = path
	t.Cleanup(func() { initDataDocumentPath = old })
}

func testDocument(t *testing.T, measurements string) []byte {
	t.Helper()
	raw, err := initdata.New(map[string]string{
		initdata.KeyRole:            initdata.RoleWorkload,
		initdata.KeyCDSMeasurements: measurements,
	}).Render()
	if err != nil {
		t.Fatalf("render document: %v", err)
	}
	return raw
}

// testDocumentWithFloor renders the shape the c8s webhook stamps on a
// floored cluster: measurements plus the minimum-TCB key.
func testDocumentWithFloor(t *testing.T, measurements, floor string) []byte {
	t.Helper()
	raw, err := initdata.New(map[string]string{
		initdata.KeyRole:            initdata.RoleWorkload,
		initdata.KeyCDSMeasurements: measurements,
		initdata.KeyCDSMinTCB:       floor,
	}).Render()
	if err != nil {
		t.Fatalf("render document: %v", err)
	}
	return raw
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestResolveInitDataHonoursCommittedDocument(t *testing.T) {
	raw := testDocument(t, "aabb,ccdd")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)

	cfg := &Config{AttestationServiceURL: attesterServing(t, digest[:])}
	got, err := resolveInitData(context.Background(), cfg)
	if err != nil {
		t.Fatalf("resolveInitData: %v", err)
	}
	if got[initdata.KeyCDSMeasurements] != "aabb,ccdd" {
		t.Fatalf("measurements = %q, want %q", got[initdata.KeyCDSMeasurements], "aabb,ccdd")
	}
}

// The whole trust anchor: a host that writes one document and commits another
// must not have its measurements believed.
func TestResolveInitDataRejectsUncommittedDocument(t *testing.T) {
	writeInitData(t, testDocument(t, "aabb"))

	// HOST_DATA commits some other document.
	other := initdata.Digest(testDocument(t, "deadbeef"))
	cfg := &Config{AttestationServiceURL: attesterServing(t, other[:])}

	_, err := resolveInitData(context.Background(), cfg)
	if err == nil {
		t.Fatal("accepted a document HOST_DATA does not commit")
	}
	if !strings.Contains(err.Error(), "HOST_DATA") {
		t.Fatalf("error = %v, want it to name HOST_DATA", err)
	}
}

// HOST_DATA agreeing with the digest on every byte but one is still not the
// commitment.
func TestResolveInitDataRejectsNearCollision(t *testing.T) {
	raw := testDocument(t, "aabb")
	writeInitData(t, raw)

	near := initdata.Digest(raw)
	near[len(near)-1] ^= 0xff
	cfg := &Config{AttestationServiceURL: attesterServing(t, near[:])}

	if _, err := resolveInitData(context.Background(), cfg); err == nil {
		t.Fatal("accepted a HOST_DATA that matches the digest only on its prefix")
	}
}

// A guest whose HOST_DATA was never set (all-zero) must not pass either.
func TestResolveInitDataRejectsZeroHostData(t *testing.T) {
	writeInitData(t, testDocument(t, "aabb"))
	cfg := &Config{AttestationServiceURL: attesterServing(t, make([]byte, initdata.DigestSize))}

	if _, err := resolveInitData(context.Background(), cfg); err == nil {
		t.Fatal("accepted a document against zero HOST_DATA")
	}
}

func TestResolveInitDataNoDocument(t *testing.T) {
	old := initDataDocumentPath
	initDataDocumentPath = filepath.Join(t.TempDir(), "absent.toml")
	t.Cleanup(func() { initDataDocumentPath = old })

	_, err := resolveInitData(context.Background(), &Config{})
	if !errors.Is(err, errNoInitData) {
		t.Fatalf("err = %v, want errNoInitData", err)
	}
}

// Verification precedes parsing, so malformed bytes that HOST_DATA does commit
// still fail — as a parse error, not silently.
func TestResolveInitDataMalformedDocument(t *testing.T) {
	raw := []byte("this is not an init-data document\n")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)

	cfg := &Config{AttestationServiceURL: attesterServing(t, digest[:])}
	_, err := resolveInitData(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "parse init-data") {
		t.Fatalf("err = %v, want a parse failure", err)
	}
}

func TestResolveInitDataAttesterUnreachable(t *testing.T) {
	writeInitData(t, testDocument(t, "aabb"))
	cfg := &Config{AttestationServiceURL: "http://127.0.0.1:1"}

	if _, err := resolveInitData(context.Background(), cfg); err == nil {
		t.Fatal("succeeded with no reachable attester")
	}
}

func TestApplyInitDataSetsFromDocument(t *testing.T) {
	raw := testDocumentWithFloor(t, "aabb,ccdd", "3,0,8,0")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)

	cfg := &Config{AttestationServiceURL: attesterServing(t, digest[:])}
	applyInitData(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "aabb,ccdd" {
		t.Fatalf("CDSMeasurements = %q, want it taken from the document", cfg.CDSMeasurements)
	}
}

// An operator pinning measurements out-of-band must not be re-pointed by the
// host, so the attester is never even consulted.
func TestApplyInitDataExplicitValueWins(t *testing.T) {
	raw := testDocument(t, "fromdocument")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)

	cfg := &Config{
		CDSMeasurements:       "explicit",
		AttestationServiceURL: attesterServing(t, digest[:]),
	}
	applyInitData(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "explicit" {
		t.Fatalf("CDSMeasurements = %q, want the explicit value kept", cfg.CDSMeasurements)
	}
}

// The floor rides the same launch-committed document as the measurements: a
// host cannot strip it from the guest's env, because there is no env to strip.
func TestApplyInitDataSetsMinTCBFromDocument(t *testing.T) {
	raw := testDocumentWithFloor(t, "aabb,ccdd", "3,0,8,0")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)

	cfg := &Config{AttestationServiceURL: attesterServing(t, digest[:])}
	applyInitData(context.Background(), quietLogger(), cfg)

	if cfg.MinTCB != "3,0,8,0" {
		t.Fatalf("MinTCB = %q, want it taken from the document", cfg.MinTCB)
	}
	if cfg.CDSMeasurements != "aabb,ccdd" {
		t.Fatalf("CDSMeasurements = %q, want it taken from the document", cfg.CDSMeasurements)
	}
}

// An operator-set floor is not re-pointed by the host's document; per-key,
// the measurements the operator left unset still come from the document.
func TestApplyInitDataExplicitMinTCBWins(t *testing.T) {
	raw := testDocumentWithFloor(t, "aabb", "9,9,9,9")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)

	cfg := &Config{
		MinTCB:                "3,0,8,0",
		AttestationServiceURL: attesterServing(t, digest[:]),
	}
	applyInitData(context.Background(), quietLogger(), cfg)

	if cfg.MinTCB != "3,0,8,0" {
		t.Fatalf("MinTCB = %q, want the explicit value kept", cfg.MinTCB)
	}
	if cfg.CDSMeasurements != "aabb" {
		t.Fatalf("CDSMeasurements = %q, want it taken from the document", cfg.CDSMeasurements)
	}
}

// A document carrying measurements but no floor key is the shape a host
// writes when it strips the floor from the annotation: refusing it keeps
// refresh disabled rather than refreshing CDS evidence from any TCB level.
func TestApplyInitDataRejectsFloorlessMeasurementsDocument(t *testing.T) {
	raw := testDocument(t, "aabb")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)

	recorder := &levelRecorder{}
	logger := slog.New(recorder)
	cfg := &Config{AttestationServiceURL: attesterServing(t, digest[:])}
	applyInitData(context.Background(), logger, cfg)

	if cfg.CDSMeasurements != "" {
		t.Fatalf("CDSMeasurements = %q, want empty so refresh stays disabled", cfg.CDSMeasurements)
	}
	if cfg.MinTCB != "" {
		t.Fatalf("MinTCB = %q, want empty from a floorless document", cfg.MinTCB)
	}
	if got := recorder.levelOf(t, "no TCB floor"); got != slog.LevelError {
		t.Fatalf("floorless-measurements refusal logged at %v, want error", got)
	}
}

// An explicit floor covers a floorless document: the operator pinned the
// floor out of band, so the document's measurements still deliver.
func TestApplyInitDataExplicitFloorAdmitsFloorlessDocument(t *testing.T) {
	raw := testDocument(t, "aabb")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)

	cfg := &Config{
		MinTCB:                "3,0,8,0",
		AttestationServiceURL: attesterServing(t, digest[:]),
	}
	applyInitData(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "aabb" {
		t.Fatalf("CDSMeasurements = %q, want it taken from the document", cfg.CDSMeasurements)
	}
	if cfg.MinTCB != "3,0,8,0" {
		t.Fatalf("MinTCB = %q, want the explicit value kept", cfg.MinTCB)
	}
}

// Every failure path must leave cfg untouched: empty measurements is what makes
// runAllowlistRefresh fail closed onto the baked seed.
func TestApplyInitDataFailuresLeaveConfigEmpty(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) *Config
	}{
		{"no document", func(t *testing.T) *Config {
			old := initDataDocumentPath
			initDataDocumentPath = filepath.Join(t.TempDir(), "absent.toml")
			t.Cleanup(func() { initDataDocumentPath = old })
			return &Config{}
		}},
		{"uncommitted document", func(t *testing.T) *Config {
			writeInitData(t, testDocument(t, "aabb"))
			other := initdata.Digest(testDocument(t, "other"))
			return &Config{AttestationServiceURL: attesterServing(t, other[:])}
		}},
		{"document without measurements", func(t *testing.T) *Config {
			raw, err := initdata.New(map[string]string{initdata.KeyRole: initdata.RoleWorkload}).Render()
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			writeInitData(t, raw)
			digest := initdata.Digest(raw)
			return &Config{AttestationServiceURL: attesterServing(t, digest[:])}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.setup(t)
			applyInitData(context.Background(), quietLogger(), cfg)
			if cfg.CDSMeasurements != "" {
				t.Fatalf("CDSMeasurements = %q, want empty so refresh fails closed", cfg.CDSMeasurements)
			}
		})
	}
}

// The stub's report bytes carry an all-zero HOST_DATA, so a non-zero result can
// only have come from the verified claim.
func TestVerifiedSelfHostDataReadsTheVerifiedClaim(t *testing.T) {
	want := testHostData()
	cfg := &Config{AttestationServiceURL: attesterServing(t, want)}

	got, err := verifiedSelfHostData(context.Background(), cfg)
	if err != nil {
		t.Fatalf("verifiedSelfHostData: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("HOST_DATA = %x, want %x", got, want)
	}
}

// Each way a report can be refused on a 200 response: no HOST_DATA reaches the
// caller, and the refusal carries both the verifier's sentinel and the terminal
// classification.
func TestVerifiedSelfHostDataRejectsUnverifiedReport(t *testing.T) {
	no := false
	for _, tc := range []struct {
		name  string
		setup func(*testing.T) string
		want  error
	}{
		{"signature invalid on a 200 (defense in depth)", refusing(func(v *testattest.Verdict) { v.SignatureValid = false }), attestationclient.ErrSignatureInvalid},
		{"report data unchecked", refusing(func(v *testattest.Verdict) { v.ReportDataMatch = nil }), attestationclient.ErrReportDataMismatch},
		{"report data mismatch on a 200 (defense in depth)", refusing(func(v *testattest.Verdict) { v.ReportDataMatch = &no }), attestationclient.ErrReportDataMismatch},
		{"launch digest malformed", refusing(func(v *testattest.Verdict) { v.Claims.LaunchDigest = "not-hex" }), attestationclient.ErrInvalidLaunchDigest},
		{"platform with no verification rules", unsupportedPlatformAttester, attestationclient.ErrUnsupportedPlatform},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := verifiedSelfHostData(context.Background(), &Config{AttestationServiceURL: tc.setup(t)})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if !errors.Is(err, errAttestVerdict) {
				t.Fatalf("err = %v, want it classified as a terminal verdict", err)
			}
			if got != nil {
				t.Fatalf("returned HOST_DATA %x alongside an error", got)
			}
		})
	}
}

// refusing builds an attester whose /verify answers a passing verdict with
// reject applied.
func refusing(reject func(*testattest.Verdict)) func(*testing.T) string {
	return func(t *testing.T) string {
		v := hostDataVerdict(testHostData())
		reject(&v)
		return attesterWithVerdict(t, v)
	}
}

// unsupportedPlatformAttester labels its evidence with a platform VerifyEvidence
// has no rules for, which is refused before any claim is read.
func unsupportedPlatformAttester(t *testing.T) string {
	t.Helper()
	stub := testattest.New(t)
	stub.SetVerdict(hostDataVerdict(testHostData()))
	stub.SetPlatform(types.Platform("gcp-tdx"))
	return stub.URL
}

// A 422 refusal is terminal, not an outage.
func TestVerifiedSelfHostDataRejectsAStatusRefusal(t *testing.T) {
	v := newScriptedVerifier(t, http.StatusUnprocessableEntity, -1)

	got, err := verifiedSelfHostData(context.Background(), &Config{AttestationServiceURL: v.url})
	if !errors.Is(err, errAttestVerdict) {
		t.Fatalf("err = %v, want a terminal verdict", err)
	}
	if got != nil {
		t.Fatalf("returned HOST_DATA %x alongside an error", got)
	}
}

// A verifier that cannot answer is retryable, and the attest-leg assertion is
// what makes this the verify leg's classification.
func TestVerifiedSelfHostDataTreatsAVerifierOutageAsRetryable(t *testing.T) {
	v := newScriptedVerifier(t, http.StatusServiceUnavailable, -1)

	got, err := verifiedSelfHostData(context.Background(), &Config{AttestationServiceURL: v.url})
	if !errors.Is(err, errAttestUnavailable) {
		t.Fatalf("err = %v, want errAttestUnavailable", err)
	}
	if got != nil {
		t.Fatalf("returned HOST_DATA %x alongside an error", got)
	}
	if n := len(v.attester.AttestRequests()); n != 1 {
		t.Fatalf("attest requests = %d, want 1: the attest leg must have succeeded", n)
	}
	if n := v.verifyCalls(); n != 1 {
		t.Fatalf("verify calls = %d, want 1", n)
	}
}

// classifyVerifyError is what decides retry-versus-give-up, and most of its
// inputs cannot be produced end to end from this call site (no measurement or
// RTMR pin is sent), so the mapping is pinned directly.
func TestClassifyVerifyError(t *testing.T) {
	apiErr := func(status int) error {
		return &attestationclient.APIError{Status: status, Response: types.ErrorResponse{Error: "verification_failed"}}
	}
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"signature invalid", attestationclient.ErrSignatureInvalid, errAttestVerdict},
		{"report data mismatch", attestationclient.ErrReportDataMismatch, errAttestVerdict},
		{"measurement not allowed", attestationclient.ErrMeasurementNotAllowed, errAttestVerdict},
		{"launch digest malformed", attestationclient.ErrInvalidLaunchDigest, errAttestVerdict},
		{"rtmr not allowed", attestationclient.ErrRTMRNotAllowed, errAttestVerdict},
		{"unsupported platform", attestationclient.ErrUnsupportedPlatform, errAttestVerdict},
		{"api 422", apiErr(http.StatusUnprocessableEntity), errAttestVerdict},
		{"api 400", apiErr(http.StatusBadRequest), errAttestVerdict},
		{"non-json 422", &attestationclient.UnexpectedError{Status: http.StatusUnprocessableEntity, Text: "Expected request with `Content-Type: application/json`"}, errAttestVerdict},
		{"non-json 408", &attestationclient.UnexpectedError{Status: http.StatusRequestTimeout}, errAttestUnavailable},
		{"non-json 429", &attestationclient.UnexpectedError{Status: http.StatusTooManyRequests}, errAttestUnavailable},
		{"non-json 503", &attestationclient.UnexpectedError{Status: http.StatusServiceUnavailable, Text: "<html>502 Bad Gateway</html>"}, errAttestUnavailable},
		{"api 408", apiErr(http.StatusRequestTimeout), errAttestUnavailable},
		{"api 429", apiErr(http.StatusTooManyRequests), errAttestUnavailable},
		{"api 500", apiErr(http.StatusInternalServerError), errAttestUnavailable},
		{"transport", &attestationclient.RequestError{Err: errors.New("connection refused")}, errAttestUnavailable},
		{"deadline", context.DeadlineExceeded, errAttestUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Wrapped, because the call site never sees a bare sentinel.
			if got := classifyVerifyError(fmt.Errorf("verify self report: %w", tc.err)); got != tc.want {
				t.Fatalf("classifyVerifyError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// The attester is asked for the 48-byte anchor and the verifier is told to
// expect its 64-byte zero-extension. Both are zero, so this pins the widths and
// the value, not that one leg is derived from the other: when the anchor stops
// being zero, this test must start asserting derivation.
func TestVerifiedSelfHostDataBindsTheAnchorItRequested(t *testing.T) {
	stub := testattest.New(t)
	stub.SetVerdict(hostDataVerdict(testHostData()))

	if _, err := verifiedSelfHostData(context.Background(), &Config{AttestationServiceURL: stub.URL}); err != nil {
		t.Fatalf("verifiedSelfHostData: %v", err)
	}

	attested, verified := stub.AttestRequests(), stub.VerifyRequests()
	if len(attested) != 1 || len(verified) != 1 {
		t.Fatalf("attest requests = %d, verify requests = %d, want 1 each", len(attested), len(verified))
	}
	if verified[0].Params == nil || verified[0].Params.ExpectedReportData == nil {
		t.Fatal("the verifier was not asked to check any REPORTDATA binding")
	}

	if n := len(attested[0].ReportData.Bytes()); n != 48 {
		t.Fatalf("attested report data = %d bytes, want the 48-byte anchor", n)
	}
	got := verified[0].Params.ExpectedReportData.Bytes()
	if !bytes.Equal(got, make([]byte, 64)) {
		t.Fatalf("expected_report_data = %x, want 64 zero bytes", got)
	}
}

// A claim that is not a 32-byte anchor is refused rather than padded or
// truncated, and is not a verifier refusal.
func TestVerifiedSelfHostDataRejectsIllShapedClaim(t *testing.T) {
	for _, tc := range []struct{ name, claim string }{
		{"absent", ""},
		{"tdx mrconfigid", strings.Repeat("00", 48)},
		{"not hex", "not-hex"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := testattest.PassingVerdict("")
			v.Claims.InitData = tc.claim

			got, err := verifiedSelfHostData(context.Background(), &Config{AttestationServiceURL: attesterWithVerdict(t, v)})
			if !errors.Is(err, errNoHostDataAnchor) {
				t.Fatalf("err = %v for claim %q, want errNoHostDataAnchor", err, tc.claim)
			}
			if errors.Is(err, errAttestVerdict) {
				t.Fatalf("err = %v for claim %q, must not read as a verifier refusal", err, tc.claim)
			}
			if got != nil {
				t.Fatalf("returned HOST_DATA %x alongside an error", got)
			}
		})
	}
}

// A forged report committing the document on disk still fails, because the
// forgery is what the verifier rejects: a 422, terminal rather than retryable.
func TestResolveInitDataRejectsUnverifiedReport(t *testing.T) {
	writeInitData(t, testDocument(t, "aabb"))

	stub := testattest.New(t)
	stub.SetVerifyError(testattest.VerificationFailed("report signature does not verify"))

	data, err := resolveInitData(context.Background(), &Config{AttestationServiceURL: stub.URL})
	if !errors.Is(err, errAttestVerdict) {
		t.Fatalf("err = %v, want the refusal classified as a terminal verdict", err)
	}
	if data != nil {
		t.Fatalf("data = %v, want none from an unverified report", data)
	}
}

// pointInitDataAt aims initDataDocumentPath at a path that does not exist yet,
// the state every guest is in until kata-agent writes the document.
func pointInitDataAt(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "initdata.toml")
	old := initDataDocumentPath
	initDataDocumentPath = path
	t.Cleanup(func() { initDataDocumentPath = old })
	return path
}

func shortInitDataWait(t *testing.T, budget, interval time.Duration) {
	t.Helper()
	prevBudget, prevInterval := initDataWaitBudget, initDataWaitInterval
	initDataWaitBudget, initDataWaitInterval = budget, interval
	t.Cleanup(func() { initDataWaitBudget, initDataWaitInterval = prevBudget, prevInterval })
}

// The regression this fixes: kata-agent writes the document during its own
// startup, and systemd orders kata-agent.service behind this unit's READY=1,
// so a single read on the startup path could only ever miss it. The wait has
// to survive an initially-absent file.
func TestAwaitInitDataWaitsForKataAgent(t *testing.T) {
	raw := testDocumentWithFloor(t, "aabb,ccdd", "3,0,8,0")
	digest := initdata.Digest(raw)
	path := pointInitDataAt(t)
	shortInitDataWait(t, 5*time.Second, 10*time.Millisecond)

	// Written a beat late, in place, the way kata-agent does.
	written := make(chan struct{})
	go func() {
		defer close(written)
		time.Sleep(50 * time.Millisecond)
		_ = os.WriteFile(path, raw, 0o644)
	}()
	t.Cleanup(func() { <-written })

	cfg := &Config{AttestationServiceURL: attesterServing(t, digest[:])}
	awaitInitData(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "aabb,ccdd" {
		t.Fatalf("CDSMeasurements = %q, want it picked up once kata-agent wrote the document", cfg.CDSMeasurements)
	}
}

// kata-agent writes the document in place, so a poll can catch it half-written.
// That short file's digest cannot match the launch-committed one, which is also
// what tampering looks like — the wait has to outlast it rather than call it a
// verdict on the first read.
func TestAwaitInitDataOutlastsAPartialWrite(t *testing.T) {
	raw := testDocumentWithFloor(t, "aabb,ccdd", "3,0,8,0")
	digest := initdata.Digest(raw)
	path := pointInitDataAt(t)
	shortInitDataWait(t, 5*time.Second, 10*time.Millisecond)

	// The half-written document is already there; the whole one lands a beat later.
	if err := os.WriteFile(path, raw[:len(raw)/2], 0o644); err != nil {
		t.Fatalf("seed a half-written document: %v", err)
	}
	written := make(chan struct{})
	go func() {
		defer close(written)
		time.Sleep(50 * time.Millisecond)
		_ = os.WriteFile(path, raw, 0o644)
	}()
	t.Cleanup(func() { <-written })

	cfg := &Config{AttestationServiceURL: attesterServing(t, digest[:])}
	awaitInitData(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "aabb,ccdd" {
		t.Fatalf("CDSMeasurements = %q, want the wait to outlast a half-written document", cfg.CDSMeasurements)
	}
}

// A document HOST_DATA does not commit is a verdict, not a timing problem, so
// the wait must abandon it promptly rather than retry until the budget runs
// out — otherwise a tampering host delays every guest's refresh.
func TestAwaitInitDataStopsOnUncommittedDocument(t *testing.T) {
	writeInitData(t, testDocument(t, "aabb"))
	other := initdata.Digest(testDocument(t, "deadbeef"))
	// A budget that would dominate the test if the tamper path retried.
	shortInitDataWait(t, time.Minute, 10*time.Second)

	cfg := &Config{AttestationServiceURL: attesterServing(t, other[:])}
	start := time.Now()
	awaitInitData(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "" {
		t.Fatalf("CDSMeasurements = %q, want empty so refresh fails closed onto the baked seed", cfg.CDSMeasurements)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("tamper verdict took %s; it must not consume the wait budget", elapsed)
	}
}

// A refused report is terminal and reaches the operator at Error: the wait
// stops at the first refusal rather than spending the budget on retries that
// reproduce it.
func TestAwaitInitDataStopsOnRefusedReport(t *testing.T) {
	writeInitData(t, testDocument(t, "aabb"))
	// A budget that would dominate the test if the refusal were retried.
	shortInitDataWait(t, time.Minute, 10*time.Second)

	v := newScriptedVerifier(t, http.StatusUnprocessableEntity, -1)
	cfg := &Config{AttestationServiceURL: v.url}
	rec := &levelRecorder{}
	start := time.Now()
	awaitInitData(context.Background(), slog.New(rec), cfg)

	if cfg.CDSMeasurements != "" {
		t.Fatalf("CDSMeasurements = %q, want empty so refresh fails closed onto the baked seed", cfg.CDSMeasurements)
	}
	if n := v.verifyCalls(); n != 1 {
		t.Fatalf("verify attempts = %d, want 1: a refusal must not be retried", n)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("refusal took %s; it must not consume the wait budget", elapsed)
	}
	if got := rec.levelOf(t, "refused"); got != slog.LevelError {
		t.Fatalf("refusal logged at %v, want Error", got)
	}
}

// A missing anchor is terminal like a refusal, but not at a refusal's level.
func TestAwaitInitDataStopsOnMissingAnchor(t *testing.T) {
	writeInitData(t, testDocument(t, "aabb"))
	shortInitDataWait(t, time.Minute, 10*time.Second)

	// MRCONFIGID's width.
	cfg := &Config{AttestationServiceURL: attesterServing(t, make([]byte, 48))}
	rec := &levelRecorder{}
	start := time.Now()
	awaitInitData(context.Background(), slog.New(rec), cfg)

	if cfg.CDSMeasurements != "" {
		t.Fatalf("CDSMeasurements = %q, want empty so refresh fails closed onto the baked seed", cfg.CDSMeasurements)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("missing anchor took %s; it must not consume the wait budget", elapsed)
	}
	if got := rec.levelOf(t, "anchor"); got != slog.LevelWarn {
		t.Fatalf("missing anchor logged at %v, want Warn", got)
	}
}

// The other half of the split: a verifier still coming up is retried, so a slow
// attestation-service does not cost the guest its pin.
func TestAwaitInitDataRetriesAnUnavailableVerifier(t *testing.T) {
	raw := testDocumentWithFloor(t, "aabb,ccdd", "3,0,8,0")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)
	shortInitDataWait(t, 5*time.Second, 10*time.Millisecond)

	v := newScriptedVerifier(t, http.StatusServiceUnavailable, 2)
	v.attester.SetVerdict(hostDataVerdict(digest[:]))

	cfg := &Config{AttestationServiceURL: v.url}
	awaitInitData(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "aabb,ccdd" {
		t.Fatalf("CDSMeasurements = %q, want the wait to outlast a verifier still coming up", cfg.CDSMeasurements)
	}
	if n := v.verifyCalls(); n != 3 {
		t.Fatalf("verify calls = %d, want 3: two outages then the answer", n)
	}
}

// A host that delivers no document at all leaves the guest exactly where it
// was before: seed-only enforcement, no measurements.
func TestAwaitInitDataBudgetExhausted(t *testing.T) {
	pointInitDataAt(t)
	shortInitDataWait(t, 100*time.Millisecond, 10*time.Millisecond)

	cfg := &Config{AttestationServiceURL: attesterServing(t, make([]byte, initdata.DigestSize))}
	awaitInitData(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "" {
		t.Fatalf("CDSMeasurements = %q, want empty so refresh fails closed onto the baked seed", cfg.CDSMeasurements)
	}
}
