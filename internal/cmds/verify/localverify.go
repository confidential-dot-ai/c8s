package verify

import (
	"context"
	"errors"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// verifyInProcess verifies already-gathered evidence with the shared engine
// (internal/localverify) and maps its error classes onto this command's exit
// codes: collateral unavailable = exit 3, any other rejection = a security
// verdict (exit 2). The --measurements pin is not passed down — newOutcome
// enforces it, so a pin failure still renders the rejected measurement.
func verifyInProcess(ctx context.Context, ev *evidence, policy *ratls.VerifyPolicy, minTCB *teetypes.SnpTcb) (*teetypes.VerificationResult, error) {
	res, err := localverify.Verify(ctx, ev.platform, ev.rawEvidence, localverify.Params{
		ExpectedReportData: ev.erd,
		AllowDebug:         policy.AllowDebug,
		MinTCB:             minTCB,
	})
	if err != nil {
		var ce *localverify.CollateralError
		if errors.As(err, &ce) {
			return nil, &connectError{err: err}
		}
		return nil, &securityError{err: err}
	}
	return res, nil
}
