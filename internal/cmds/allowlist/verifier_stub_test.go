package allowlist

import (
	"context"
	"encoding/json"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
)

type verifierStub localverify.VerifyFunc

func (v verifierStub) Verify(ctx context.Context, platform string, evidence json.RawMessage, params localverify.Params) (*teetypes.VerificationResult, error) {
	return v(ctx, platform, evidence, params)
}
