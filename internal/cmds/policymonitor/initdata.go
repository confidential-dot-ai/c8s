package policymonitor

import (
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/initdata"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Distinct from a document that fails verification: this is an older control
// plane, that is a host that tampered.
var errNoInitData = errors.New("policy-monitor: no init-data document")

// The attester or the verifier did not answer; a later read may.
var errAttestUnavailable = errors.New("policy-monitor: attestation service unavailable")

// The verifier refused this guest's report.
var errAttestVerdict = errors.New("policy-monitor: self-report refused")

// The verified report carries no usable init-data anchor to compare the
// document against: neither SNP's 32-byte HOST_DATA nor TDX's 48-byte
// MRCONFIGID carrying a zero-padded 32-byte digest.
var errNoHostDataAnchor = errors.New("policy-monitor: init-data claim is not a 32-byte anchor")

// mrConfigIDSize is the width of TDX's MRCONFIGID, into which the shim commits
// sha256(document) zero-padded — the same shape attestation-rs's TDX verifier
// binds expected_init_data_hash against (pad_report_data(expected, 48)).
const mrConfigIDSize = 48

// Bounds the self-attestation; on expiry the caller falls back to the seed.
const initDataTimeout = 15 * time.Second

// Where kata-agent writes the document. A var only so tests can point at a
// tempdir; production always uses the baked path.
var initDataDocumentPath = initdata.GuestDocumentPath

// initDataCDSPins are the CDS pin values a launch-committed init-data
// document carries, still in their comma-separated wire form.
type initDataCDSPins struct {
	measurements string
	rtmrs        string
}

// resolveInitDataMeasurements returns the CDS pins the host delivered.
//
// The document is host-supplied; what makes it usable is that the shim commits
// sha256(document) into HOST_DATA at launch. A mismatch means the host wrote
// one document and committed another, and is treated as tampering.
func resolveInitDataMeasurements(ctx context.Context, cfg *Config) (initDataCDSPins, error) {
	raw, err := os.ReadFile(initDataDocumentPath)
	if err != nil {
		if os.IsNotExist(err) {
			return initDataCDSPins{}, errNoInitData
		}
		return initDataCDSPins{}, fmt.Errorf("read init-data: %w", err)
	}

	hostData, err := verifiedSelfHostData(ctx, cfg)
	if err != nil {
		return initDataCDSPins{}, err
	}
	want := initdata.Digest(raw)
	if subtle.ConstantTimeCompare(hostData, want[:]) != 1 {
		return initDataCDSPins{}, fmt.Errorf("policy-monitor: init-data digest %x is not the launch-committed HOST_DATA %x", want, hostData)
	}

	doc, err := initdata.Parse(raw)
	if err != nil {
		return initDataCDSPins{}, fmt.Errorf("parse init-data: %w", err)
	}
	return initDataCDSPins{
		measurements: doc.Data[initdata.KeyCDSMeasurements],
		rtmrs:        doc.Data[initdata.KeyCDSRTMRs],
	}, nil
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
	pins, err := resolveInitDataMeasurements(ctx, cfg)
	switch {
	case errors.Is(err, errNoInitData):
		logger.Warn("no init-data document; CDS measurements unset, so allowlist refresh will stay disabled",
			"path", initdata.GuestDocumentPath)
		return
	case err != nil:
		// One read, so every failure is final here — including one a retry would clear.
		logger.Error("init-data rejected; enforcing the baked seed alone", "error", err)
		return
	case pins.measurements == "":
		logger.Warn("init-data carries no CDS measurements; allowlist refresh will stay disabled",
			"key", initdata.KeyCDSMeasurements)
		return
	}
	adoptInitDataCDSPins(logger, cfg, pins)
}

// adoptInitDataCDSPins writes the launch-committed pin values into cfg. The
// RTMR pins ride the measurements' explicit-wins rule: this runs only when no
// explicit measurement value was configured, and a document that pins
// measurements without registers leaves any explicit CDSRTMRs standing.
func adoptInitDataCDSPins(logger *slog.Logger, cfg *Config, pins initDataCDSPins) {
	cfg.CDSMeasurements = pins.measurements
	if pins.rtmrs != "" {
		cfg.CDSRTMRs = pins.rtmrs
	}
	logger.Info("CDS pins taken from the launch-committed init-data document",
		"key", initdata.KeyCDSMeasurements, "rtmrs_pinned", pins.rtmrs != "")
}

// initDataWaitBudget bounds how long the guest waits for kata-agent to write
// the document and for the in-guest attestation service to answer. It runs
// after READY=1, so it delays only the first allowlist refresh, never the
// unit's start. Overridable in tests.
var (
	initDataWaitBudget   = 90 * time.Second
	initDataWaitInterval = 2 * time.Second
)

// A refusal is re-tried this many times before it counts as a verdict.
// INVARIANT: initDataVerdictRetries * initDataWaitInterval stays under
// refreshSettleBudget, so a real refusal still lands inside the wait a
// would-be deny makes. TestVerdictRetriesFitTheDenyWait pins the two.
const initDataVerdictRetries = 5

// A digest mismatch is re-read this many times, this far apart, before it counts
// as a verdict. Covers a document caught mid-write without letting a genuinely
// uncommitted one hold the guest off its seed for the whole budget.
const (
	initDataSettleReads = 3
	initDataSettleDelay = 100 * time.Millisecond
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
//
// The verifier fetches AMD KDS collateral to judge an SNP report, and the pod
// network arrives from a unit ordered behind this one (see
// resolveSandboxDigestsHostLate), so the first self-reports run without a
// resolver: a refusal counts as a verdict only after initDataVerdictRetries.
func awaitInitDataMeasurements(ctx context.Context, logger *slog.Logger, cfg *Config) {
	if cfg.CDSMeasurements != "" {
		return
	}
	deadline := time.Now().Add(initDataWaitBudget)
	var lastErr error
	settling := 0
	verdicts := 0
	for {
		pins, err := resolveInitDataMeasurements(ctx, cfg)
		switch {
		case err == nil && pins.measurements != "":
			adoptInitDataCDSPins(logger, cfg, pins)
			return
		case err == nil:
			// The digest matched, so this is the launch-committed document
			// itself: it carries no measurements and a later read cannot
			// change that.
			logger.Warn("init-data carries no CDS measurements; allowlist refresh will stay disabled",
				"key", initdata.KeyCDSMeasurements)
			return
		case errors.Is(err, errAttestVerdict) && verdicts >= initDataVerdictRetries:
			logger.Error("self-report refused by the verifier", "error", err, "attempts", verdicts+1)
			return
		case errors.Is(err, errNoHostDataAnchor):
			logger.Warn("verified report carries no 32-byte init-data anchor", "error", err)
			return
		}
		lastErr = err

		wait := initDataWaitInterval
		if errors.Is(err, errAttestVerdict) {
			verdicts++
			settling = 0
		} else if errors.Is(err, errNoInitData) || errors.Is(err, errAttestUnavailable) {
			settling = 0
		} else {
			// kata-agent writes the document in place, so a read that lands
			// mid-write sees a short file whose digest cannot match the
			// launch-committed one — the same shape as a document the host
			// tampered with. Re-read after a beat: a write in flight resolves,
			// tampering reproduces. The grace is its own short delay so a real
			// verdict still lands promptly instead of costing the whole budget.
			settling++
			if settling > initDataSettleReads {
				logger.Error("init-data rejected; enforcing the baked seed alone", "error", err)
				return
			}
			wait = initDataSettleDelay
		}

		if !time.Now().Add(wait).Before(deadline) {
			break
		}
		time.Sleep(wait)
	}
	logger.Warn("no init-data document within the wait budget; CDS measurements unset, so allowlist refresh will stay disabled",
		"path", initdata.GuestDocumentPath, "waited", initDataWaitBudget, "error", lastErr)
}

// verifiedSelfHostData returns this guest's HOST_DATA as the attestation-api
// reports it, from the claims of a report that api verified.
func verifiedSelfHostData(ctx context.Context, cfg *Config) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, initDataTimeout)
	defer cancel()

	// One anchor, both legs: the attester is asked for the 48-byte prefix and
	// zero-extends it into the 64-byte REPORTDATA the verifier must find.
	var reportData [64]byte
	resp, err := attestclient.NewClient("").GenerateEvidenceContext(ctx, cfg.AttestationServiceURL, reportData[:sha512.Size384])
	if err != nil {
		return nil, fmt.Errorf("%w: attest self: %w", errAttestUnavailable, err)
	}
	// Measurements stay unpinned.
	verified, err := attestationclient.NewClient(cfg.AttestationServiceURL).VerifyEvidence(ctx,
		types.AttestationEvidence(resp), attestationclient.EvidencePolicy{ExpectedReportData: reportData})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", classifyVerifyError(err), err)
	}

	hostData, err := hex.DecodeString(verified.Result.Claims.InitData)
	if err != nil {
		return nil, fmt.Errorf("%w: not hex: %w", errNoHostDataAnchor, err)
	}
	return initDataAnchor(hostData)
}

// initDataAnchor extracts the 32-byte sha256(document) anchor from the
// platform's init-data claim: SNP HOST_DATA carries it verbatim; TDX
// MRCONFIGID carries it zero-padded to 48 bytes, so the tail must be zero for
// the prefix to be that anchor rather than an arbitrary 48-byte value.
func initDataAnchor(claim []byte) ([]byte, error) {
	switch len(claim) {
	case initdata.DigestSize:
		return claim, nil
	case mrConfigIDSize:
		for _, b := range claim[initdata.DigestSize:] {
			if b != 0 {
				return nil, fmt.Errorf("%w: %d-byte MRCONFIGID is not a zero-padded %d-byte digest", errNoHostDataAnchor, mrConfigIDSize, initdata.DigestSize)
			}
		}
		return claim[:initdata.DigestSize], nil
	default:
		return nil, fmt.Errorf("%w: %d bytes, want %d (SNP HOST_DATA) or %d (TDX MRCONFIGID)", errNoHostDataAnchor, len(claim), initdata.DigestSize, mrConfigIDSize)
	}
}

// classifyVerifyError splits a refusal of the report from a failure to reach
// the verifier, which is what decides whether the caller retries. The
// attestation-api refuses with a 4xx status rather than with a false verdict,
// so the status arm is the one a conforming verifier takes.
func classifyVerifyError(err error) error {
	switch {
	case errors.Is(err, attestationclient.ErrSignatureInvalid),
		errors.Is(err, attestationclient.ErrReportDataMismatch),
		errors.Is(err, attestationclient.ErrMeasurementNotAllowed),
		errors.Is(err, attestationclient.ErrInvalidLaunchDigest),
		errors.Is(err, attestationclient.ErrRTMRNotAllowed),
		errors.Is(err, attestationclient.ErrUnsupportedPlatform):
		return errAttestVerdict
	}
	var apiErr *attestationclient.APIError
	if errors.As(err, &apiErr) && refusesEvidence(apiErr.Status) {
		return errAttestVerdict
	}
	// A refusal whose body is not the api's JSON error shape arrives as
	// UnexpectedError, carrying the same status.
	var unexpected *attestationclient.UnexpectedError
	if errors.As(err, &unexpected) && refusesEvidence(unexpected.Status) {
		return errAttestVerdict
	}
	return errAttestUnavailable
}

// refusesEvidence reports whether a status names the evidence rather than the
// service; 408 and 429 are availability.
func refusesEvidence(status int) bool {
	return status >= 400 && status < 500 &&
		status != http.StatusRequestTimeout && status != http.StatusTooManyRequests
}
