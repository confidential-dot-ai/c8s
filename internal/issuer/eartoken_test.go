package issuer_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

type testKeyProvider struct{ pub *ecdsa.PublicKey }

func (p testKeyProvider) PublicKey(string) (*ecdsa.PublicKey, error) {
	return p.pub, nil
}

func signEARJWT(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

func validEARClaims(now int64) map[string]any {
	return map[string]any{
		earclaims.EATProfile: earclaims.EARProfileTag,
		earclaims.Issuer:     "cds",
		earclaims.IssuedAt:   now,
		earclaims.ExpiresAt:  now + 600,
		earclaims.EARVerifierID: map[string]any{
			earclaims.Developer: "test",
			earclaims.Build:     "test",
		},
		earclaims.Submods: map[string]any{
			earclaims.SubmodAttester: map[string]any{
				earclaims.EARStatus: 2,
			},
		},
	}
}

func TestValidateEARTokenRejectsFutureIssuedAt(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().Unix()
	claims := validEARClaims(now)
	claims[earclaims.IssuedAt] = now + 120
	token := signEARJWT(t, key, claims)

	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
	if err == nil {
		t.Fatal("expected future iat to be rejected")
	}
	var validationErr *issuer.TokenValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %[1]v, want TokenValidationError", err)
	}
	if validationErr.Reason != issuer.ReasonNotYetValid {
		t.Fatalf("reason = %q, want not_yet_valid", validationErr.Reason)
	}
}

func TestValidateEARTokenRejectsFutureNotBefore(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().Unix()
	claims := validEARClaims(now)
	claims[earclaims.NotBefore] = now + 120
	token := signEARJWT(t, key, claims)

	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
	if err == nil {
		t.Fatal("expected future nbf to be rejected")
	}
	var validationErr *issuer.TokenValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %[1]v, want TokenValidationError", err)
	}
	if validationErr.Reason != issuer.ReasonNotYetValid {
		t.Fatalf("reason = %q, want not_yet_valid", validationErr.Reason)
	}
}

func TestValidateEARTokenRejectsAudienceClaim(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().Unix()
	claims := validEARClaims(now)
	claims["aud"] = "other-service"
	token := signEARJWT(t, key, claims)

	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
	if err == nil {
		t.Fatal("expected aud claim to be rejected")
	}
	var validationErr *issuer.TokenValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %[1]v, want TokenValidationError", err)
	}
	if validationErr.Reason != issuer.ReasonInvalidAudience {
		t.Fatalf("reason = %q, want invalid_audience", validationErr.Reason)
	}
}

func TestValidateEARTokenRejectsSignedNonEARJWT(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().Unix()
	token := signEARJWT(t, key, map[string]any{
		earclaims.Issuer:    "cds",
		earclaims.IssuedAt:  now,
		earclaims.ExpiresAt: now + 600,
	})

	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
	if err == nil {
		t.Fatal("expected signed non-EAR JWT to be rejected")
	}
	var validationErr *issuer.TokenValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %[1]v, want TokenValidationError", err)
	}
	if validationErr.Reason != issuer.ReasonMalformed {
		t.Fatalf("reason = %q, want malformed", validationErr.Reason)
	}
}

// TestEARClaimsRawEvidencePreservation pins the audit-evidence capture: with
// submods present RawEvidence carries them, and without submods it must keep
// the full raw claim set rather than being cleared.
func TestEARClaimsRawEvidencePreservation(t *testing.T) {
	withoutSubmods := []byte(`{"iss":"cds","iat":1}`)
	var c issuer.EARClaims
	if err := json.Unmarshal(withoutSubmods, &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bytes.Equal(c.RawEvidence, withoutSubmods) {
		t.Fatalf("RawEvidence = %q, want the full raw claims %q", c.RawEvidence, withoutSubmods)
	}
	if len(c.Submods) != 0 {
		t.Fatalf("Submods = %q, want empty without a submods claim", c.Submods)
	}

	withSubmods := []byte(`{"iss":"cds","submods":{"cvm":{"ear.status":2}}}`)
	c = issuer.EARClaims{}
	if err := json.Unmarshal(withSubmods, &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(c.Submods) == 0 || !bytes.Equal(c.Submods, c.RawEvidence) {
		t.Fatalf("Submods = %q, RawEvidence = %q; want both set to the submods object", c.Submods, c.RawEvidence)
	}
}

func TestValidateEARTokenRejectsMissingMandatoryEARClaims(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now().Unix()

	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{name: "missing profile", edit: func(claims map[string]any) { delete(claims, earclaims.EATProfile) }},
		{name: "wrong profile", edit: func(claims map[string]any) { claims[earclaims.EATProfile] = "tag:example.com:not-ear" }},
		{name: "missing iat", edit: func(claims map[string]any) { delete(claims, earclaims.IssuedAt) }},
		{name: "missing verifier id", edit: func(claims map[string]any) { delete(claims, earclaims.EARVerifierID) }},
		{name: "empty verifier id", edit: func(claims map[string]any) { claims[earclaims.EARVerifierID] = map[string]any{} }},
		{name: "missing submods", edit: func(claims map[string]any) { delete(claims, earclaims.Submods) }},
		{name: "empty submods", edit: func(claims map[string]any) { claims[earclaims.Submods] = map[string]any{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := validEARClaims(now)
			tc.edit(claims)
			token := signEARJWT(t, key, claims)

			_, err := issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
			if err == nil {
				t.Fatal("expected malformed EAR to be rejected")
			}
			var validationErr *issuer.TokenValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error = %T %[1]v, want TokenValidationError", err)
			}
			if validationErr.Reason != issuer.ReasonMalformed {
				t.Fatalf("reason = %q, want malformed", validationErr.Reason)
			}
		})
	}
}

func TestEARClaimsGetters(t *testing.T) {
	c := issuer.EARClaims{Issuer: "cds"}
	if sub, err := c.GetSubject(); err != nil || sub != "" {
		t.Errorf("GetSubject() = %q, %v; want \"\", nil", sub, err)
	}
	aud, err := c.GetAudience()
	if err != nil {
		t.Fatalf("GetAudience: %v", err)
	}
	if len(aud) != 0 {
		t.Errorf("GetAudience() = %v, want empty", aud)
	}
	iss, err := c.GetIssuer()
	if err != nil || iss != "cds" {
		t.Errorf("GetIssuer() = %q, %v; want cds, nil", iss, err)
	}
}

func TestEARClaimsUnmarshalInvalidJSON(t *testing.T) {
	var c issuer.EARClaims
	if err := json.Unmarshal([]byte("not json"), &c); err == nil {
		t.Fatal("expected error unmarshaling invalid JSON into EARClaims")
	}
}

func TestValidateEARTokenRequiresProvider(t *testing.T) {
	_, err := issuer.ValidateEARToken("x.y.z", nil, "cds")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonInvalidSignature {
		t.Errorf("reason = %q, want invalid_signature", ve.Reason)
	}
}

func TestValidateEARTokenMalformedToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, err = issuer.ValidateEARToken("garbage", testKeyProvider{pub: &key.PublicKey}, "cds")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonMalformed {
		t.Errorf("reason = %q, want malformed", ve.Reason)
	}
}

func TestValidateEARTokenExpired(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	past := time.Now().Add(-time.Hour).Unix()
	claims := validEARClaims(past)
	claims[earclaims.ExpiresAt] = past + 1 // already expired (beyond skew)
	token := signEARJWT(t, key, claims)

	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonExpired {
		t.Errorf("reason = %q, want expired", ve.Reason)
	}
}

func TestValidateEARTokenWrongIssuer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now().Unix()
	claims := validEARClaims(now)
	claims[earclaims.Issuer] = "someone-else"
	token := signEARJWT(t, key, claims)

	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonInvalidIssuer {
		t.Errorf("reason = %q, want invalid_issuer", ve.Reason)
	}
}

func TestValidateEARTokenWrongSigningKey(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	now := time.Now().Unix()
	token := signEARJWT(t, signingKey, validEARClaims(now))

	// Provider returns a different key, so the signature does not verify.
	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &otherKey.PublicKey}, "cds")
	var ve *issuer.TokenValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T, want TokenValidationError", err)
	}
	if ve.Reason != issuer.ReasonInvalidSignature {
		t.Errorf("reason = %q, want invalid_signature", ve.Reason)
	}
}

func TestValidateEARTokenProviderError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now().Unix()
	token := signEARJWT(t, key, validEARClaims(now))

	_, err = issuer.ValidateEARToken(token, erroringKeyProvider{}, "cds")
	if err == nil {
		t.Fatal("expected error when provider cannot resolve key")
	}
}

type erroringKeyProvider struct{}

func (erroringKeyProvider) PublicKey(string) (*ecdsa.PublicKey, error) {
	return nil, errors.New("no key")
}

func TestTokenValidationErrorErrorAndUnwrap(t *testing.T) {
	inner := errors.New("inner failure")
	e := &issuer.TokenValidationError{Reason: issuer.ReasonExpired, Err: inner}
	if e.Error() != "inner failure" {
		t.Errorf("Error() = %q, want inner failure", e.Error())
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap should expose the wrapped error")
	}
}
