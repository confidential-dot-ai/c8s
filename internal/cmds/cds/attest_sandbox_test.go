package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/pkg/earsigner"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const testSandboxID = "8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f"

// testInventoryAddr is the callback address the signer stamps into tokens. The
// tests answer it with fakeDigests rather than dialing.
const testInventoryAddr = "10.0.0.7:9443"

// fakeDigests answers the inventory callback from a sandbox -> digests map. A
// missing sandbox is workloadclaims.ErrSandboxUnknown, like a 404 on the wire.
type fakeDigests map[string][]string

func (f fakeDigests) Fetch(_ context.Context, addr, sandboxID string) ([]string, error) {
	if addr != testInventoryAddr {
		return nil, fmt.Errorf("unexpected inventory address %q", addr)
	}
	d, ok := f[sandboxID]
	if !ok {
		return nil, workloadclaims.ErrSandboxUnknown
	}
	return d, nil
}

// newSandboxTestEnv wires an AttestHandler that can validate inventory EARs, and
// an inventory signer whose EARs that handler accepts: the signer's EAR source
// mints /attest-key-shaped EARs from the same issuer the handler's
// KeyProvider verifies, with launchDigest as the inventory's attested
// measurement.
func newSandboxTestEnv(t *testing.T, mockURL, launchDigest string) (AttestHandler, *workloadclaims.SandboxTokenSigner) {
	t.Helper()
	h := newTestAttestHandler(t, mockURL, nil)
	// A token now triggers the digests callback, so every sandbox test needs an
	// inventory to answer and an allowlist admitting what it reports.
	h.AllowlistStore = floorStore(wlDigestA)
	h.SandboxDigests = fakeDigests{testSandboxID: {wlDigestA}}

	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatal(err)
	}
	earIss, err := ear.NewIssuer(keyPEM, "cds", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rotator, err := earsigner.NewRotator(earsigner.RotatorConfig{}, keyPEM, earIss.SwapKey)
	if err != nil {
		t.Fatal(err)
	}
	h.EARKeyProvider = rotator
	h.EARIssuer = "cds"

	signer, err := workloadclaims.NewSandboxTokenSigner(func(_ context.Context, pubDER []byte) (string, error) {
		pubAny, err := x509.ParsePKIXPublicKey(pubDER)
		if err != nil {
			return "", err
		}
		pub, ok := pubAny.(*ecdsa.PublicKey)
		if !ok {
			return "", fmt.Errorf("inventory key is not ECDSA")
		}
		return earIss.IssueAttestedKey(json.RawMessage(`{"test":true}`), launchDigest, pub, "")
	}, testInventoryAddr)
	if err != nil {
		t.Fatal(err)
	}
	return h, signer
}

// signedSandboxToken issues an inventory token for the CSR key behind csrPEM,
// bound to the same base64 challenge the request will carry (CDS re-checks the
// token nonce against the challenge it consumes).
func signedSandboxToken(t *testing.T, signer *workloadclaims.SandboxTokenSigner, csrPEM, challenge string) json.RawMessage {
	t.Helper()
	csr, err := attestation.ParseAndVerifyCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest, err := workloadclaims.RequesterKeyDigest(csr.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.Sign(context.Background(), testSandboxID, keyDigest, nonce)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func postAttestSandbox(t *testing.T, h AttestHandler, challenge, csrPEM string, token json.RawMessage) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge:    challenge,
		Evidence:     types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{"test":true}`)},
		CSR:          csrPEM,
		SandboxToken: token,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	return w
}

// A valid inventory token gets its sandbox ID stamped into the signed leaf.
func TestAttest_SandboxToken_StampedOnLeaf(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	csrPEM, _ := generateCSR(t)

	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", w.Code, w.Body.String())
	}
	got, err := ratls.SandboxIDFromCert(leafFromAttestResponse(t, w))
	if err != nil {
		t.Fatalf("SandboxIDFromCert: %v", err)
	}
	if got != testSandboxID {
		t.Fatalf("leaf sandbox = %q, want %q", got, testSandboxID)
	}
}

// No token ⇒ no extension (the pre-sandbox flow is unchanged).
func TestAttest_SandboxToken_AbsentWhenNotRequested(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, _ := newSandboxTestEnv(t, mock.URL, "deadbeef")
	csrPEM, _ := generateCSR(t)

	w := postAttest(t, h, issueChallenge(t, h), csrPEM)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", w.Code, w.Body.String())
	}
	if got, err := ratls.SandboxIDFromCert(leafFromAttestResponse(t, w)); err != nil || got != "" {
		t.Fatalf("leaf sandbox = %q, %v; want empty", got, err)
	}
}

// A token bound to a different key than the CSR's must be rejected: only the
// get-cert holding the bound key may redeem the token.
func TestAttest_SandboxToken_RejectsWrongRequesterKey(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	victimCSR, _ := generateCSR(t)
	attackerCSR, _ := generateCSR(t)

	// Token issued for the victim's key, replayed with the attacker's CSR.
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, attackerCSR, signedSandboxToken(t, signer, victimCSR, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// A token whose EAR the CDS cannot validate (unknown signer) must be
// rejected: provenance from a CDS-attested inventory key is the whole point.
func TestAttest_SandboxToken_RejectsForeignInventoryEAR(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, _ := newSandboxTestEnv(t, mock.URL, "deadbeef")
	// A second env with its own EAR issuer the handler does not trust.
	_, foreignSigner := newSandboxTestEnv(t, mock.URL, "deadbeef")
	csrPEM, _ := generateCSR(t)

	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, foreignSigner, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// An inventory EAR on a non-allowlisted measurement must be rejected when the
// CDS pins measurements.
func TestAttest_SandboxToken_RejectsDeniedMeasurement(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "badbadbad")
	h.Measurements = map[string]bool{"deadbeef": true}
	csrPEM, _ := generateCSR(t)

	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// The freshness guarantee: a validly-signed token whose nonce is some other
// challenge — not the one this request consumes — is rejected, so a captured or
// pre-signed token cannot be replayed against a fresh challenge.
func TestAttest_SandboxToken_RejectsStaleNonce(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	csrPEM, _ := generateCSR(t)

	// Token is bound to a different challenge than the request carries.
	staleChallenge := base64.StdEncoding.EncodeToString([]byte("a-different-challenge"))
	w := postAttestSandbox(t, h, issueChallenge(t, h), csrPEM, signedSandboxToken(t, signer, csrPEM, staleChallenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// A CDS with no EAR key provider cannot verify tokens and must reject a
// request that carries one rather than stamp it unverified.
func TestAttest_SandboxToken_RejectsWhenUnverifiable(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.EARKeyProvider = nil
	csrPEM, _ := generateCSR(t)

	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}
