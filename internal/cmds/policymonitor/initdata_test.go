package policymonitor

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/initdata"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// snpHostDataOffset is HOST_DATA's byte offset in an SEV-SNP ATTESTATION_REPORT
// (AMD SEV-SNP ABI table: VERSION..PLATFORM_INFO, REPORT_DATA at 0x50,
// MEASUREMENT at 0x90, HOST_DATA at 0xC0).
const snpHostDataOffset = 0xC0

const snpReportLen = 1184

// snpPolicyOffset is POLICY's offset. go-sev-guest rejects a report whose
// bit 17 is clear, so the field cannot be left zero. 0x30000 is what a kata
// SNP guest actually reports (bit 16 SMT, bit 17 reserved-must-be-1).
const (
	snpPolicyOffset = 0x08
	snpTestPolicy   = 0x30000
)

// attesterServing returns the URL of a fake in-guest attester whose report
// carries hostData in HOST_DATA.
func attesterServing(t *testing.T, hostData []byte) string {
	t.Helper()
	report := make([]byte, snpReportLen)
	report[0] = 0x02 // VERSION 2
	binary.LittleEndian.PutUint64(report[snpPolicyOffset:], snpTestPolicy)
	copy(report[snpHostDataOffset:], hostData)

	evidence, err := json.Marshal(map[string]string{
		"attestation_report": base64.StdEncoding.EncodeToString(report),
	})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.AttestResponse{Platform: "snp", Evidence: evidence})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
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

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestResolveInitDataMeasurementsHonoursCommittedDocument(t *testing.T) {
	raw := testDocument(t, "aabb,ccdd")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)

	cfg := &Config{AttestationServiceURL: attesterServing(t, digest[:])}
	got, err := resolveInitDataMeasurements(context.Background(), cfg)
	if err != nil {
		t.Fatalf("resolveInitDataMeasurements: %v", err)
	}
	if got != "aabb,ccdd" {
		t.Fatalf("measurements = %q, want %q", got, "aabb,ccdd")
	}
}

// The whole trust anchor: a host that writes one document and commits another
// must not have its measurements believed.
func TestResolveInitDataMeasurementsRejectsUncommittedDocument(t *testing.T) {
	writeInitData(t, testDocument(t, "aabb"))

	// HOST_DATA commits some other document.
	other := initdata.Digest(testDocument(t, "deadbeef"))
	cfg := &Config{AttestationServiceURL: attesterServing(t, other[:])}

	_, err := resolveInitDataMeasurements(context.Background(), cfg)
	if err == nil {
		t.Fatal("accepted a document HOST_DATA does not commit")
	}
	if !strings.Contains(err.Error(), "HOST_DATA") {
		t.Fatalf("error = %v, want it to name HOST_DATA", err)
	}
}

// A guest whose HOST_DATA was never set (all-zero) must not pass either.
func TestResolveInitDataMeasurementsRejectsZeroHostData(t *testing.T) {
	writeInitData(t, testDocument(t, "aabb"))
	cfg := &Config{AttestationServiceURL: attesterServing(t, make([]byte, initdata.DigestSize))}

	if _, err := resolveInitDataMeasurements(context.Background(), cfg); err == nil {
		t.Fatal("accepted a document against zero HOST_DATA")
	}
}

func TestResolveInitDataMeasurementsNoDocument(t *testing.T) {
	old := initDataDocumentPath
	initDataDocumentPath = filepath.Join(t.TempDir(), "absent.toml")
	t.Cleanup(func() { initDataDocumentPath = old })

	_, err := resolveInitDataMeasurements(context.Background(), &Config{})
	if !errors.Is(err, errNoInitData) {
		t.Fatalf("err = %v, want errNoInitData", err)
	}
}

// Verification precedes parsing, so malformed bytes that HOST_DATA does commit
// still fail — as a parse error, not silently.
func TestResolveInitDataMeasurementsMalformedDocument(t *testing.T) {
	raw := []byte("this is not an init-data document\n")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)

	cfg := &Config{AttestationServiceURL: attesterServing(t, digest[:])}
	_, err := resolveInitDataMeasurements(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "parse init-data") {
		t.Fatalf("err = %v, want a parse failure", err)
	}
}

func TestResolveInitDataMeasurementsAttesterUnreachable(t *testing.T) {
	writeInitData(t, testDocument(t, "aabb"))
	cfg := &Config{AttestationServiceURL: "http://127.0.0.1:1"}

	if _, err := resolveInitDataMeasurements(context.Background(), cfg); err == nil {
		t.Fatal("succeeded with no reachable attester")
	}
}

func TestApplyInitDataMeasurementsSetsFromDocument(t *testing.T) {
	raw := testDocument(t, "aabb,ccdd")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)

	cfg := &Config{AttestationServiceURL: attesterServing(t, digest[:])}
	applyInitDataMeasurements(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "aabb,ccdd" {
		t.Fatalf("CDSMeasurements = %q, want it taken from the document", cfg.CDSMeasurements)
	}
}

// An operator pinning measurements out-of-band must not be re-pointed by the
// host, so the attester is never even consulted.
func TestApplyInitDataMeasurementsExplicitValueWins(t *testing.T) {
	raw := testDocument(t, "fromdocument")
	writeInitData(t, raw)
	digest := initdata.Digest(raw)

	cfg := &Config{
		CDSMeasurements:       "explicit",
		AttestationServiceURL: attesterServing(t, digest[:]),
	}
	applyInitDataMeasurements(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "explicit" {
		t.Fatalf("CDSMeasurements = %q, want the explicit value kept", cfg.CDSMeasurements)
	}
}

// Every failure path must leave cfg untouched: empty measurements is what makes
// runAllowlistRefresh fail closed onto the baked seed.
func TestApplyInitDataMeasurementsFailuresLeaveConfigEmpty(t *testing.T) {
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
			applyInitDataMeasurements(context.Background(), quietLogger(), cfg)
			if cfg.CDSMeasurements != "" {
				t.Fatalf("CDSMeasurements = %q, want empty so refresh fails closed", cfg.CDSMeasurements)
			}
		})
	}
}

func TestSelfHostDataReadsHostDataField(t *testing.T) {
	want := make([]byte, initdata.DigestSize)
	for i := range want {
		want[i] = byte(i + 1)
	}
	cfg := &Config{AttestationServiceURL: attesterServing(t, want)}

	got, err := selfHostData(context.Background(), cfg)
	if err != nil {
		t.Fatalf("selfHostData: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("HOST_DATA = %x, want %x", got, want)
	}
}

func TestSelfHostDataRejectsUnparseableReport(t *testing.T) {
	evidence, err := json.Marshal(map[string]string{
		"attestation_report": base64.StdEncoding.EncodeToString([]byte("too short")),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.AttestResponse{Platform: "snp", Evidence: evidence})
	}))
	defer srv.Close()

	if _, err := selfHostData(context.Background(), &Config{AttestationServiceURL: srv.URL}); err == nil {
		t.Fatal("accepted a report that does not parse")
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
func TestAwaitInitDataMeasurementsWaitsForKataAgent(t *testing.T) {
	raw := testDocument(t, "aabb,ccdd")
	digest := initdata.Digest(raw)
	path := pointInitDataAt(t)
	shortInitDataWait(t, 5*time.Second, 10*time.Millisecond)

	// Written a beat late, the way kata-agent does.
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = os.WriteFile(path, raw, 0o644)
	}()

	cfg := &Config{AttestationServiceURL: attesterServing(t, digest[:])}
	awaitInitDataMeasurements(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "aabb,ccdd" {
		t.Fatalf("CDSMeasurements = %q, want it picked up once kata-agent wrote the document", cfg.CDSMeasurements)
	}
}

// A document HOST_DATA does not commit is a verdict, not a timing problem, so
// the wait must abandon it immediately rather than retry until the budget runs
// out — otherwise a tampering host delays every guest's refresh.
func TestAwaitInitDataMeasurementsStopsOnUncommittedDocument(t *testing.T) {
	writeInitData(t, testDocument(t, "aabb"))
	other := initdata.Digest(testDocument(t, "deadbeef"))
	// A budget that would dominate the test if the tamper path retried.
	shortInitDataWait(t, time.Minute, 10*time.Second)

	cfg := &Config{AttestationServiceURL: attesterServing(t, other[:])}
	start := time.Now()
	awaitInitDataMeasurements(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "" {
		t.Fatalf("CDSMeasurements = %q, want empty so refresh fails closed onto the baked seed", cfg.CDSMeasurements)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("tamper verdict took %s; it must not consume the wait budget", elapsed)
	}
}

// A host that delivers no document at all leaves the guest exactly where it
// was before: seed-only enforcement, no measurements.
func TestAwaitInitDataMeasurementsBudgetExhausted(t *testing.T) {
	pointInitDataAt(t)
	shortInitDataWait(t, 100*time.Millisecond, 10*time.Millisecond)

	cfg := &Config{AttestationServiceURL: attesterServing(t, make([]byte, 48))}
	awaitInitDataMeasurements(context.Background(), quietLogger(), cfg)

	if cfg.CDSMeasurements != "" {
		t.Fatalf("CDSMeasurements = %q, want empty so refresh fails closed onto the baked seed", cfg.CDSMeasurements)
	}
}
