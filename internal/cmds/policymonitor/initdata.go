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

// The verifier refused this guest's report, which every retry reproduces.
var errAttestVerdict = errors.New("policy-monitor: self-report refused")

// The verified report carries no 32-byte anchor to compare the document
// against. TDX reports the digest padded into a 48-byte MRCONFIGID, so this is
// what an ordinary TDX boot reaches, not a hostile one.
var errNoHostDataAnchor = errors.New("policy-monitor: HOST_DATA claim is not a 32-byte anchor")

// Bounds the self-attestation; on expiry the caller falls back to the seed.
const initDataTimeout = 15 * time.Second

// Where kata-agent writes the document. A var only so tests can point at a
// tempdir; production always uses the baked path.
var initDataDocumentPath = initdata.GuestDocumentPath

// resolveInitData returns the launch-committed init-data document's data.
//
// The document is host-supplied; what makes it usable is that the shim commits
// sha256(document) into HOST_DATA at launch. A mismatch means the host wrote
// one document and committed another, and is treated as tampering.
func resolveInitData(ctx context.Context, cfg *Config) (map[string]string, error) {
	raw, err := os.ReadFile(initDataDocumentPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNoInitData
		}
		return nil, fmt.Errorf("read init-data: %w", err)
	}

	hostData, err := verifiedSelfHostData(ctx, cfg)
	if err != nil {
		return nil, err
	}
	want := initdata.Digest(raw)
	if subtle.ConstantTimeCompare(hostData, want[:]) != 1 {
		return nil, fmt.Errorf("policy-monitor: init-data digest %x is not the launch-committed HOST_DATA %x", want, hostData)
	}

	doc, err := initdata.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse init-data: %w", err)
	}
	return doc.Data, nil
}

// applyInitData fills cfg.CDSMeasurements and cfg.MinTCB from the
// launch-committed document. It is the only delivery path: the measurements
// cannot be baked (they are a digest of the image they would live in) and an
// unattested channel must not be trusted — a host that could strip the floor
// from env would run known-vulnerable firmware unobserved.
//
// An explicit value wins, and every failure leaves cfg untouched, so the
// fallback is always the baked seed.
func applyInitData(ctx context.Context, logger *slog.Logger, cfg *Config) {
	if cfg.CDSMeasurements != "" && cfg.MinTCB != "" {
		return
	}
	data, err := resolveInitData(ctx, cfg)
	switch {
	case errors.Is(err, errNoInitData):
		warnNoDocument(logger, cfg, "no init-data document", "path", initdata.GuestDocumentPath)
		return
	case err != nil:
		// One read, so every failure is final here — including one a retry would clear.
		logger.Error("init-data rejected; enforcing the baked seed alone", "error", err)
		return
	}
	applyInitDataValues(logger, cfg, data)
}

// warnNoDocument logs an undelivered document's consequence: the values it
// would have delivered stay unset — unset measurements disable refresh, an
// unset floor leaves CDS evidence unfloored. At least one is unset whenever
// applyInitData/awaitInitData ran.
func warnNoDocument(logger *slog.Logger, cfg *Config, msg string, args ...any) {
	if cfg.CDSMeasurements == "" {
		logger.Warn(msg+"; CDS measurements unset, so allowlist refresh will stay disabled", args...)
		return
	}
	logger.Warn(msg+"; TCB floor unset, so CDS evidence from any platform TCB level is accepted (UNSAFE outside development)", args...)
}

// applyInitDataValues fills the still-unset policy values from a verified
// document, logging what each key resolves to.
//
// A document that would enable refresh (measurements present) but carries no
// floor key is refused outright: with no explicit floor to win, that is the
// shape a host writes when it strips the floor from the annotation, and
// refreshing CDS evidence from any TCB level is worse than no refresh.
func applyInitDataValues(logger *slog.Logger, cfg *Config, data map[string]string) {
	measurements, floor := data[initdata.KeyCDSMeasurements], data[initdata.KeyCDSMinTCB]
	// The all-zero floor parses clean and packs to "no floor", so a document
	// naming it is as floorless as one missing the key.
	parsed, parseErr := types.ParseMinTcb(floor)
	floorless := parseErr == nil && parsed == (types.MinTcb{})
	if cfg.CDSMeasurements == "" && cfg.MinTCB == "" && measurements != "" && floorless {
		logger.Error("init-data carries CDS measurements but no non-zero TCB floor; refusing the document, so allowlist refresh will stay disabled",
			"measurements_key", initdata.KeyCDSMeasurements, "floor_key", initdata.KeyCDSMinTCB, "floor", floor)
		return
	}
	if cfg.CDSMeasurements == "" {
		if measurements != "" {
			cfg.CDSMeasurements = measurements
			logger.Info("CDS measurements taken from the launch-committed init-data document",
				"key", initdata.KeyCDSMeasurements)
		} else {
			logger.Warn("init-data carries no CDS measurements; allowlist refresh will stay disabled",
				"key", initdata.KeyCDSMeasurements)
		}
	}
	if cfg.MinTCB == "" {
		if floor != "" {
			cfg.MinTCB = floor
			logger.Info("minimum TCB floor taken from the launch-committed init-data document",
				"key", initdata.KeyCDSMinTCB)
		} else {
			logger.Warn("init-data carries no TCB floor; CDS evidence from any platform TCB level is accepted (UNSAFE outside development)",
				"key", initdata.KeyCDSMinTCB)
		}
	}
}

// initDataWaitBudget bounds how long the guest waits for kata-agent to write
// the document and for the in-guest attestation service to answer. It runs
// after READY=1, so it delays only the first allowlist refresh, never the
// unit's start. Overridable in tests.
var (
	initDataWaitBudget   = 90 * time.Second
	initDataWaitInterval = 2 * time.Second
)

// A digest mismatch is re-read this many times, this far apart, before it counts
// as a verdict. Covers a document caught mid-write without letting a genuinely
// uncommitted one hold the guest off its seed for the whole budget.
const (
	initDataSettleReads = 3
	initDataSettleDelay = 100 * time.Millisecond
)

// awaitInitData is applyInitData for a caller running after READY=1: it waits
// for the document rather than reading once.
//
// kata-agent writes /run/confidential-containers/initdata/initdata.toml during
// its own startup, and systemd orders kata-agent.service behind this unit
// (kata-agent.service.d/10-c8s-policy-monitor.conf Requires= + After=). A read
// on the startup path is therefore always a read of a file the writer has not
// been allowed to create yet.
//
// Waiting is bounded and every outcome still falls back to the baked seed, so
// a guest whose host delivers no document behaves exactly as before.
func awaitInitData(ctx context.Context, logger *slog.Logger, cfg *Config) {
	if cfg.CDSMeasurements != "" && cfg.MinTCB != "" {
		return
	}
	deadline := time.Now().Add(initDataWaitBudget)
	var lastErr error
	settling := 0
	for {
		data, err := resolveInitData(ctx, cfg)
		switch {
		case err == nil:
			// The digest matched, so this is the launch-committed document
			// itself: a key it does not carry now is one a later read cannot
			// deliver either.
			applyInitDataValues(logger, cfg, data)
			return
		case errors.Is(err, errAttestVerdict):
			logger.Error("self-report refused by the verifier", "error", err)
			return
		case errors.Is(err, errNoHostDataAnchor):
			logger.Warn("verified report carries no 32-byte init-data anchor", "error", err)
			return
		}
		lastErr = err

		wait := initDataWaitInterval
		if errors.Is(err, errNoInitData) || errors.Is(err, errAttestUnavailable) {
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
	warnNoDocument(logger, cfg, "no init-data document within the wait budget",
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
	if len(hostData) != initdata.DigestSize {
		return nil, fmt.Errorf("%w: %d bytes, want %d", errNoHostDataAnchor, len(hostData), initdata.DigestSize)
	}
	return hostData, nil
}

// classifyVerifyError splits a refusal of the report from a failure to reach
// the verifier, which is what decides whether the caller retries. The
// attestation-api refuses with a 4xx status rather than with a false verdict,
// so the status arm is the one a conforming verifier takes. That arm is shared
// with cds.classifyVerifyError; the sentinel arms are not.
func classifyVerifyError(err error) error {
	switch {
	case errors.Is(err, attestationclient.ErrSignatureInvalid),
		errors.Is(err, attestationclient.ErrReportDataMismatch),
		errors.Is(err, attestationclient.ErrMeasurementNotAllowed),
		errors.Is(err, attestationclient.ErrInvalidLaunchDigest),
		errors.Is(err, attestationclient.ErrRTMRNotAllowed),
		errors.Is(err, attestationclient.ErrUnsupportedPlatform),
		// Echo rejections reproduce on every retry — same evidence, same
		// policy — so they are verdicts, not availability.
		errors.Is(err, attestationclient.ErrMinTCBNotEchoed),
		errors.Is(err, attestationclient.ErrDebugPolicyNotEchoed):
		return errAttestVerdict
	}
	// A refusal whose body is not the api's JSON error shape arrives as
	// UnexpectedError, carrying the same status.
	var apiErr *attestationclient.APIError
	if errors.As(err, &apiErr) && refusesEvidence(apiErr.Status) {
		return errAttestVerdict
	}
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
