package policymonitor

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/go-sev-guest/abi"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/initdata"
)

// Distinct from a document that fails verification: this is an older control
// plane, that is a host that tampered.
var errNoInitData = errors.New("policy-monitor: no init-data document")

// Bounds the self-attestation; on expiry the caller falls back to the seed.
const initDataTimeout = 15 * time.Second

// Where kata-agent writes the document. A var only so tests can point at a
// tempdir; production always uses the baked path.
var initDataDocumentPath = initdata.GuestDocumentPath

// resolveInitDataMeasurements returns the CDS measurements the host delivered.
//
// The document is host-supplied; what makes it usable is that the shim commits
// sha256(document) into HOST_DATA at launch. A mismatch means the host wrote
// one document and committed another, and is treated as tampering.
func resolveInitDataMeasurements(ctx context.Context, cfg *Config) (string, error) {
	raw, err := os.ReadFile(initDataDocumentPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", errNoInitData
		}
		return "", fmt.Errorf("read init-data: %w", err)
	}

	hostData, err := selfHostData(ctx, cfg)
	if err != nil {
		return "", err
	}
	want := initdata.Digest(raw)
	if subtle.ConstantTimeCompare(hostData, want[:]) != 1 {
		return "", fmt.Errorf("policy-monitor: init-data digest %x is not the launch-committed HOST_DATA %x", want, hostData)
	}

	doc, err := initdata.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse init-data: %w", err)
	}
	return doc.Data[initdata.KeyCDSMeasurements], nil
}

// applyInitDataMeasurements fills cfg.CDSMeasurements from the launch-committed
// document. It is the only delivery path: the value cannot be baked (it would
// be a digest of the image it lives in) and unattested env must not be trusted.
//
// An explicit value wins, and every failure leaves cfg untouched, so the
// fallback is always the baked seed.
func applyInitDataMeasurements(ctx context.Context, logger *slog.Logger, cfg *Config) {
	if cfg.CDSMeasurements != "" {
		return
	}
	measurements, err := resolveInitDataMeasurements(ctx, cfg)
	switch {
	case errors.Is(err, errNoInitData):
		logger.Warn("no init-data document; CDS measurements unset, so allowlist refresh will stay disabled",
			"path", initdata.GuestDocumentPath)
		return
	case err != nil:
		// Host tampering or a broken attester; both leave the guest on the seed.
		logger.Error("init-data rejected; enforcing the baked seed alone", "error", err)
		return
	case measurements == "":
		logger.Warn("init-data carries no CDS measurements; allowlist refresh will stay disabled",
			"key", initdata.KeyCDSMeasurements)
		return
	}
	cfg.CDSMeasurements = measurements
	logger.Info("CDS measurements taken from the launch-committed init-data document",
		"key", initdata.KeyCDSMeasurements)
}

// selfHostData reads HOST_DATA from a fresh report for this guest. Report data
// is unused here, hence the zero value.
//
// SEV-SNP only: TDX commits the digest to MRCONFIGID, so a TDX guest fails to
// parse here and falls back to the baked seed — safe, but not yet wired.
func selfHostData(ctx context.Context, cfg *Config) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, initDataTimeout)
	defer cancel()

	resp, err := attestclient.NewClient("").GenerateEvidenceContext(ctx, cfg.AttestationServiceURL, make([]byte, 48))
	if err != nil {
		return nil, fmt.Errorf("attest self: %w", err)
	}
	report, err := attestclient.ExtractSNPReport(resp)
	if err != nil {
		return nil, fmt.Errorf("extract snp report: %w", err)
	}
	parsed, err := abi.ReportToProto([]byte(report))
	if err != nil {
		return nil, fmt.Errorf("parse snp report: %w", err)
	}
	hostData := parsed.GetHostData()
	if len(hostData) != initdata.DigestSize {
		return nil, fmt.Errorf("policy-monitor: HOST_DATA is %d bytes, want %d", len(hostData), initdata.DigestSize)
	}
	return hostData, nil
}
