package ear

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Version is set at build time via ldflags.
var Version = "dev"

const earProfile = "tag:ietf.org,2026:rats/ear#03"

// statusAffirming is the EAR trustworthiness tier value meaning
// "recognised and not compromised" (draft-ietf-rats-ear).
const statusAffirming = 2

// Issuer produces signed EAR (Entity Attestation Result) JWT tokens
// conforming to draft-ietf-rats-ear.
type Issuer struct {
	signingKey *ecdsa.PrivateKey
	issuer     string
	lifetime   time.Duration
}

// NewIssuer creates an EAR issuer from a PEM-encoded EC private key (P-256/ES256).
func NewIssuer(keyPEM []byte, issuer string, lifetime time.Duration) (Issuer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return Issuer{}, fmt.Errorf("invalid EAR signing key: no PEM block found")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Issuer{}, fmt.Errorf("invalid EAR signing key: %w", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return Issuer{}, fmt.Errorf("invalid EAR signing key: not an EC key")
	}

	return Issuer{
		signingKey: ecKey,
		issuer:     issuer,
		lifetime:   lifetime,
	}, nil
}

// Issue produces a signed EAR JWT for a successful attestation verification.
// submodsEvidence is the raw attestation evidence to embed for audit purposes.
func (iss Issuer) Issue(submodsEvidence json.RawMessage) (string, error) {
	now := time.Now().Unix()

	claims := jwt.MapClaims{
		"eat_profile": earProfile,
		"iss":         iss.issuer,
		"iat":         now,
		"exp":         now + int64(iss.lifetime.Seconds()),
		"ear_verifier_id": map[string]string{
			"developer": iss.issuer,
			"build":     Version,
		},
		"submods": map[string]any{
			"attester": map[string]any{
				"ear_status": statusAffirming,
				"ear_trustworthiness_vector": map[string]any{
					"instance-identity": statusAffirming,
				},
				"ear_raw_evidence": json.RawMessage(submodsEvidence),
			},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := token.SignedString(iss.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign EAR token: %w", err)
	}

	return signed, nil
}
