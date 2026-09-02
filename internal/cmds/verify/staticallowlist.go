package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// staticCAReport is the sealed-policy section of the verdict: the
// static-allowlist stamp found on the mesh CA, and whether the CA's own
// embedded evidence verified. Gathered only when --static-allowlist asks for
// the check (the CA evidence verification can fetch AMD KDS collateral).
type staticCAReport struct {
	// digest is the .1.6 stamp of the one sealed CA in the --mesh-ca bundle
	// (nil when no bundle certificate carries a stamp).
	digest []byte
	// launchDigest is the sealed CA evidence's verified launch measurement.
	launchDigest string
	// verifyErr records why the sealed CA's embedded evidence was refused
	// (nil once the evidence verified and its launch digest passed the same
	// measurement policy the target is pinned against).
	verifyErr error
	// err is bundle-level damage: an unreadable bundle, a malformed or
	// duplicated stamp, or more than one stamped CA. Fails the verdict.
	err error
}

// gatherStaticCA reads the --mesh-ca bundle, finds the sealed CA, and
// verifies its embedded RA-TLS evidence in-process against the run's
// measurement policy. The stamp alone is CA-self-asserted; the embedded
// evidence — REPORTDATA bound to the CA public key, launch digest inside the
// pinned set — is what turns "this CA claims digest D" into "a measured CDS
// launched to enforce digest D minted this CA" (docs/static-allowlist.md).
func gatherStaticCA(ctx context.Context, cfg config, plan *verifyPlan) staticCAReport {
	if !cfg.staticAllowlist {
		return staticCAReport{}
	}
	// buildPolicy requires --mesh-ca alongside --static-allowlist.
	certs, err := certutil.LoadPEMCertificatesFile(cfg.meshCA)
	if err != nil {
		return staticCAReport{err: err}
	}
	var sealed *x509.Certificate
	var digest []byte
	for _, cert := range certs {
		stamp, err := ratls.StaticAllowlistFromCert(cert)
		if err != nil {
			return staticCAReport{err: err}
		}
		if stamp == nil {
			continue
		}
		if sealed != nil {
			return staticCAReport{err: fmt.Errorf("--mesh-ca carries more than one certificate with a static-allowlist stamp; a sealed deployment has exactly one")}
		}
		sealed, digest = cert, stamp.AllowlistDigest
	}
	if sealed == nil {
		return staticCAReport{}
	}

	report := staticCAReport{digest: digest}
	if cfg.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	}
	// The sealed CA is a self-signed RA-TLS certificate: the standard cert
	// pipeline authenticates its body under its own attested key and binds
	// REPORTDATA to that key, so the existing verifier covers it unchanged.
	caEv, err := evidenceFromCert(sealed, "sealed mesh CA in --mesh-ca", leafTrust{})
	if err != nil {
		report.verifyErr = err
		return report
	}
	result, err := verifyInProcess(ctx, caEv, plan.policy, nil, nil)
	if err != nil {
		report.verifyErr = err
		return report
	}
	report.launchDigest = result.Claims.LaunchDigest
	report.verifyErr = staticCALaunchAllowed(result, plan)
	return report
}

// staticCALaunchAllowed enforces the run's measurement policy on the sealed
// CA's verified claims: the CA must come from a launch the operator pinned,
// with the same alternatives the target itself gets (--measurements
// membership, a --measurements-config entry matched whole, or the
// --image-manifest tuple). An unpinned run accepts any genuine TEE — the
// verdict already carries the global UNSAFE warning for that.
func staticCALaunchAllowed(result *teetypes.VerificationResult, plan *verifyPlan) error {
	pinned := len(plan.policy.Measurements) > 0 || len(plan.policy.Entries) > 0 || plan.pins.image != nil
	if !pinned {
		return nil
	}
	launch := strings.ToLower(strings.TrimSpace(result.Claims.LaunchDigest))
	lb, err := hex.DecodeString(launch)
	if err != nil || len(lb) == 0 {
		return fmt.Errorf("sealed CA evidence carries no usable launch digest (%q)", result.Claims.LaunchDigest)
	}
	if plan.pins.image != nil {
		if !bytes.Equal(lb, plan.pins.image.MRTD[:]) {
			return fmt.Errorf("sealed CA launch measurement %s does not match the --image-manifest MRTD", launch)
		}
		return staticCARTMRs(result, map[int][]byte{1: plan.pins.image.RTMR1[:], 2: plan.pins.image.RTMR2[:]})
	}
	if attestationclient.MeasurementAllowed(lb, plan.policy.Measurements) {
		return nil
	}
	if err := staticCAEntryMatch(result, lb, plan.policy.Entries); err == nil {
		return nil
	}
	return fmt.Errorf("sealed CA launch measurement %s is not in the pinned measurement policy", launch)
}

// staticCAEntryMatch accepts the sealed CA's claims when one reference entry
// matches whole: launch digest, and every RTMR that entry pins.
func staticCAEntryMatch(result *teetypes.VerificationResult, launch []byte, entries []measurements.Entry) error {
	for _, e := range entries {
		if !bytes.Equal(launch, e.Digest) {
			continue
		}
		if len(e.RTMRs) == 0 {
			return nil
		}
		if err := staticCARTMRs(result, e.RTMRs); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no pinned image matches the sealed CA evidence whole")
}

// staticCARTMRs compares pinned TDX registers against the verified claims.
// Absent or malformed claims fail closed, mirroring applyRTMRPins.
func staticCARTMRs(result *teetypes.VerificationResult, pinned map[int][]byte) error {
	if len(pinned) == 0 {
		return nil
	}
	for idx, want := range pinned {
		got, _ := result.Claims.PlatformData[fmt.Sprintf("rtmr_%d", idx)].(string)
		gb, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(got)))
		if err != nil || len(gb) != runtimemeasure.Size {
			return fmt.Errorf("sealed CA claims carry no usable rtmr_%d", idx)
		}
		if !bytes.Equal(gb, want) {
			return fmt.Errorf("sealed CA RTMR[%d] is %s, expected %s", idx, got, hex.EncodeToString(want))
		}
	}
	return nil
}

// applyStaticAllowlistPolicy enforces --static-allowlist on the final verdict:
// the mesh CA must carry a stamp whose embedded evidence verified, the stamped
// digest must match the held --allowlist bytes when given, and a leaf
// matched-workload stamp must have been decided under the same sealed policy.
// It runs after applySandboxPolicy (the chain check that authenticates the
// leaf's stamps) and, like the other pins, only ever demotes Verified.
func applyStaticAllowlistPolicy(oc *Outcome, cfg config, ev *evidence, held *heldAllowlist, report staticCAReport) {
	if !cfg.staticAllowlist {
		return
	}
	fail := func(format string, args ...any) {
		oc.Verified = false
		if oc.Error == "" {
			oc.Error = fmt.Sprintf(format, args...)
		}
	}
	if report.err != nil {
		fail("static_allowlist_malformed: %v", report.err)
		return
	}
	if report.digest == nil {
		fail("static_allowlist_absent: --static-allowlist is pinned but no certificate in the --mesh-ca bundle carries a static-allowlist stamp (is this CDS running with --static-allowlist?)")
		return
	}
	oc.StaticAllowlistDigest = hex.EncodeToString(report.digest)
	if report.verifyErr != nil {
		fail("static_allowlist_ca_unverified: the sealed mesh CA's embedded evidence was refused: %v", report.verifyErr)
		return
	}
	if held != nil {
		digest := sha256.Sum256(held.raw)
		if !bytes.Equal(digest[:], report.digest) {
			fail("static_allowlist_digest_mismatch: sealed policy digest %x does not match SHA-256 %x of the held --allowlist bytes", report.digest, digest[:])
			return
		}
	}
	if ev.workload != nil && !bytes.Equal(ev.workload.AllowlistDigest, report.digest) {
		fail("static_allowlist_skew: the leaf's matched-workload stamp was decided under allowlist digest %x, not the sealed digest %x", ev.workload.AllowlistDigest, report.digest)
		return
	}
	if oc.Verified {
		oc.StaticAllowlistNote = fmt.Sprintf("static_allowlist_verified: the mesh CA embeds TEE evidence binding its own key (launch %s, inside the pinned measurement policy) and seals this policy digest; the policy cannot change without minting a new CA", report.launchDigest)
	}
}
