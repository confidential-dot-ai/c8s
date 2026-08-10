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

// The in-guest attestation service has not answered yet. Like errNoInitData
// this is a "too early" condition rather than a verdict, so the caller waits
// on it; a digest mismatch or an unparseable document is neither and stops the
// wait immediately.
var errAttestUnavailable = errors.New("policy-monitor: attestation service unavailable")

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
		return "", fmt.Errorf("%w: %w", errAttestUnavailable, err)
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

// initDataWaitBudget bounds how long the guest waits for kata-agent to write
// the document and for the in-guest attestation service to answer. It runs
// after READY=1, so it delays only the first allowlist refresh, never the
// unit's start. Overridable in tests.
var (
	initDataWaitBudget   = 90 * time.Second
	initDataWaitInterval = 2 * time.Second
)

// awaitInitDataMeasurements is applyInitDataMeasurements for a caller running
// after READY=1: it waits for the document rather than reading once.
//
// kata-agent writes /run/confidential-containers/initdata/initdata.toml during
// its own startup, and systemd orders kata-agent.service behind this unit
// (kata-agent.service.d/10-c8s-policy-monitor.conf Requires= + After=). A read
// on the startup path is therefore always a read of a file the writer has not
// been allowed to create yet.
//
// Waiting is bounded and every outcome still falls back to the baked seed, so
// a guest whose host delivers no document behaves exactly as before.
func awaitInitDataMeasurements(ctx context.Context, logger *slog.Logger, cfg *Config) {
	if cfg.CDSMeasurements != "" {
		return
	}
	deadline := time.Now().Add(initDataWaitBudget)
	var lastErr error
	for {
		measurements, err := resolveInitDataMeasurements(ctx, cfg)
		switch {
		case err == nil && measurements != "":
			cfg.CDSMeasurements = measurements
			logger.Info("CDS measurements taken from the launch-committed init-data document",
				"key", initdata.KeyCDSMeasurements)
			return
		case err == nil:
			logger.Warn("init-data carries no CDS measurements; allowlist refresh will stay disabled",
				"key", initdata.KeyCDSMeasurements)
			return
		case !errors.Is(err, errNoInitData) && !errors.Is(err, errAttestUnavailable):
			// A verdict, not a timing problem: host tampering or a document we
			// cannot parse. Waiting cannot change either.
			logger.Error("init-data rejected; enforcing the baked seed alone", "error", err)
			return
		}
		lastErr = err
		if !time.Now().Add(initDataWaitInterval).Before(deadline) {
			break
		}
		time.Sleep(initDataWaitInterval)
	}
	logger.Warn("no init-data document within the wait budget; CDS measurements unset, so allowlist refresh will stay disabled",
		"path", initdata.GuestDocumentPath, "waited", initDataWaitBudget, "error", lastErr)
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
