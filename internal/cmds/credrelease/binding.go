// Package credrelease implements the in-guest credential-release service (B4
// of the operator-key design). It issues an operator a short-lived kube client
// certificate, but only to a caller who proves possession of the operator
// private key whose public half was bound into the CVM's launch identity
// directly or through the launchdata commitment — giving an external operator
// console-free, non-TOFU admin access with no pre-shared cluster secret and
// no trust in the untrusted host.
package credrelease

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/confidential-dot-ai/c8s/internal/launchdata"
	"os"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// operatorPubkeyPath is where the measured initrd stages the operator public
// key it read off the opkeydata disk (and hashed into the launch binding). The
// service reads this file rather than mounting the ISO itself — mounting fails
// under the unit's systemd hardening, and the initrd is the single, measured
// reader of the disk anyway.
// Var (not const) so tests can point it at a temp file.
var operatorPubkeyPath = "/etc/confai/operator-pubkey"

// readOperatorPubkey reads the operator public key the initrd staged off the
// opkeydata disk. The bytes are exactly what the initrd hashed into the launch
// binding, so runtimemeasure can re-derive the same digest. Absence means the
// VM was launched without an operator key (no opkeydata disk).
func readOperatorPubkey() ([]byte, error) {
	pub, err := os.ReadFile(operatorPubkeyPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w — was the VM launched with an operator key?", operatorPubkeyPath, err)
	}
	if len(pub) == 0 {
		return nil, fmt.Errorf("%s is empty", operatorPubkeyPath)
	}
	return pub, nil
}

// selfReportTimeout bounds the self-attestation round trip against the local
// attestation-api; on expiry the service fails start and systemd retries.
const selfReportTimeout = 15 * time.Second

// verifiedSelfReport returns this guest's own attestation as the local
// attestation-api verified it.
//
// Reading the launch binding off an UNVERIFIED report would take the anchor
// from an unauthenticated field, so the report goes through /verify even though
// the guest produced it. The anchor is a fresh nonce, which makes the report
// non-replayable for free.
func verifiedSelfReport(ctx context.Context, attestationAPIURL string) (*teetypes.VerificationResult, error) {
	ctx, cancel := context.WithTimeout(ctx, selfReportTimeout)
	defer cancel()

	// The attester is asked for the 48-byte prefix and zero-extends it into the
	// 64-byte report data the verifier must find.
	var reportData [64]byte
	if _, err := rand.Read(reportData[:sha512.Size384]); err != nil {
		return nil, fmt.Errorf("self-report nonce: %w", err)
	}
	resp, err := attestclient.NewClient("").GenerateEvidenceContext(ctx, attestationAPIURL, reportData[:sha512.Size384])
	if err != nil {
		return nil, fmt.Errorf("attest self: %w", err)
	}
	verified, err := attestationclient.NewClient(attestationAPIURL).VerifyEvidence(ctx,
		types.AttestationEvidence(resp), attestationclient.EvidencePolicy{ExpectedReportData: reportData})
	if err != nil {
		return nil, fmt.Errorf("verify self-report: %w", err)
	}
	return &verified.Result, nil
}

// LoadMeasuredOperatorKey returns the launch-bound operator public key.
// launchDataDir, when it exists, is the launchdata arm: the key and the
// binding come from the staged bundle's commitment. Otherwise the opkeydata
// arm applies: the initrd-staged single key file, verified against the TDX
// RTMR[3] the initrd extended or the SNP HOSTDATA the launcher committed.
// Called once at service start; both bindings are fixed for the guest's life.
// The platform comes from the verified self-report.
func LoadMeasuredOperatorKey(ctx context.Context, attestationAPIURL, launchDataDir string) ([]byte, error) {
	if launchDataDir != "" {
		if _, err := os.Stat(launchDataDir); err == nil {
			return loadLaunchDataOperatorKey(ctx, attestationAPIURL, launchDataDir)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("stat %s: %w", launchDataDir, err)
		}
	}
	pub, err := readOperatorPubkey()
	if err != nil {
		return nil, err
	}
	// The platform comes from the verified report, not from configuration: a
	// config string says which platform an operator EXPECTED, and the anchor
	// check must key off what the hardware actually proved.
	report, err := verifiedSelfReport(ctx, attestationAPIURL)
	if err != nil {
		return nil, err
	}
	if err := runtimemeasure.VerifyBinding(report, pub, nil); err != nil {
		return nil, err
	}
	return pub, nil
}

// loadLaunchDataOperatorKey is the launchdata arm: dir holds exactly the
// launchdata ISO's staged files, and the platform binding covers their
// combined commitment (LaunchDataManifest) rather than one key file. The
// operator key is the bundle's operator-pubkey, so the binding fixes the
// exact key bytes together with every other staged file.
func loadLaunchDataOperatorKey(ctx context.Context, attestationAPIURL, dir string) ([]byte, error) {
	manifest, pub, err := launchdata.LoadLaunchData(dir)
	if err != nil {
		return nil, err
	}
	report, err := verifiedSelfReport(ctx, attestationAPIURL)
	if err != nil {
		return nil, err
	}
	switch report.Platform {
	case teetypes.PlatformTDX:
		own := []byte(report.Claims.InitData)
		want := launchdata.LaunchDataMRConfigID(manifest)
		if !bytes.Equal(own, want[:]) {
			return nil, fmt.Errorf(
				"launchdata does not match the launch-committed MRCONFIGID: got %s, staged bundle implies %s (were the staged files modified after boot, or the TD launched with a different bundle?)",
				hex.EncodeToString(own), hex.EncodeToString(want[:]))
		}
	case teetypes.PlatformSNP:
		hostData := []byte(report.Claims.InitData)
		want := launchdata.LaunchDataHostData(manifest)
		if !bytes.Equal(hostData, want[:]) {
			return nil, fmt.Errorf(
				"launchdata does not match the launch-committed HOSTDATA: got %s, staged bundle implies %s (were the staged files modified after boot, or the VM launched with a different bundle?)",
				hex.EncodeToString(hostData), hex.EncodeToString(want[:]))
		}
	default:
		return nil, fmt.Errorf("no launchdata binding check for platform %q", report.Platform)
	}
	return pub, nil
}
