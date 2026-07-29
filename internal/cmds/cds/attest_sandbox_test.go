package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const testSandboxID = "8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f"

// testInventoryHost is the callback host the signer stamps into tokens. The
// tests answer it with fakeDigests rather than dialing.
const testInventoryHost = "10.0.0.7"

// fakeDigests answers the inventory callback from a sandbox -> digests map. A
// missing sandbox is workloadclaims.ErrSandboxUnknown, like a 404 on the wire.
type fakeDigests struct {
	digests map[string][]string
	key     *ecdsa.PublicKey
}

func (f fakeDigests) InventoryKey(_ context.Context, host string) (*ecdsa.PublicKey, error) {
	if host != testInventoryHost {
		return nil, fmt.Errorf("unexpected inventory host %q", host)
	}
	if f.key == nil {
		return nil, fmt.Errorf("no inventory at %s", host)
	}
	return f.key, nil
}

func (f fakeDigests) Fetch(_ context.Context, host, sandboxID string) ([]string, error) {
	if host != testInventoryHost {
		return nil, fmt.Errorf("unexpected inventory host %q", host)
	}
	d, ok := f.digests[sandboxID]
	if !ok {
		return nil, workloadclaims.ErrSandboxUnknown
	}
	return d, nil
}

// newSandboxTestEnv wires an AttestHandler that can validate inventory EARs, and
// an inventory signer whose EARs that handler accepts: the signer's EAR source
// newSandboxTestEnv wires an AttestHandler that resolves an inventory key the
// way production does — from the inventory's own endpoint — and the signer
// holding that key. launchDigest is unused now that the key's provenance is the
// privileged-port callback rather than an EAR, but is kept in the signature so
// the call sites read the same.
func newSandboxTestEnv(t *testing.T, mockURL, launchDigest string) (AttestHandler, *workloadclaims.SandboxTokenSigner) {
	t.Helper()
	_ = launchDigest
	h := newTestAttestHandler(t, mockURL, nil)

	signer, err := workloadclaims.NewSandboxTokenSigner(testInventoryHost)
	if err != nil {
		t.Fatal(err)
	}
	// A token triggers the digests callback, so every sandbox test needs an
	// inventory to answer, an allowlist admitting what it reports, and node
	// CIDRs the callback host falls inside.
	h.AllowlistStore = floorStore(wlDigestA)
	h.SandboxDigests = fakeDigests{
		digests: map[string][]string{testSandboxID: {wlDigestA}},
		key:     signer.PublicKey(),
	}
	hosts, err := workloadclaims.ParseInventoryHosts([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	h.InventoryHosts = hosts
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
	token, err := signer.Sign(testSandboxID, keyDigest, nonce)
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

// The core of the design: a token signed by a key the inventory does not hold
// is rejected. This is what stops a compromised workload — which shares the
// node's launch measurement and can reach CDS — from minting a token naming
// another pod's sandbox. CDS resolves the key from the inventory's own
// privileged-port endpoint, so the impostor's own key never matches.
func TestAttest_SandboxToken_RejectsKeyTheInventoryDoesNotHold(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, _ := newSandboxTestEnv(t, mock.URL, "deadbeef")

	// An attacker signs its own token for someone else's sandbox.
	impostor, err := workloadclaims.NewSandboxTokenSigner(testInventoryHost)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, impostor, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// A token naming a host outside the operator's node CIDRs is refused before
// anything is dialed — that boundary is what stops a workload pointing the
// callback at its own pod IP and answering as its node's inventory.
func TestAttest_SandboxToken_RejectsHostOutsideNodeCIDRs(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	hosts, err := workloadclaims.ParseInventoryHosts([]string{"192.168.99.0/24"}) // not testInventoryHost
	if err != nil {
		t.Fatal(err)
	}
	h.InventoryHosts = hosts

	csrPEM, _ := generateCSR(t)
	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// With no CIDRs configured CDS has no boundary to apply, so it refuses tokens
// outright rather than dialing wherever it is pointed.
func TestAttest_SandboxToken_RejectsWithoutConfiguredCIDRs(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h, signer := newSandboxTestEnv(t, mock.URL, "deadbeef")
	h.InventoryHosts = nil

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
	h.SandboxDigests = nil
	csrPEM, _ := generateCSR(t)

	challenge := issueChallenge(t, h)
	w := postAttestSandbox(t, h, challenge, csrPEM, signedSandboxToken(t, signer, csrPEM, challenge))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// A malformed token envelope, and one whose signed bytes are not a token, are
// both refused before any callback is attempted.
func TestAttest_SandboxToken_RejectsMalformedEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token json.RawMessage
	}{
		{"wrong JSON shape", json.RawMessage(`[]`)},
		{"unknown field", json.RawMessage(`{"token":"AA==","signature":"AA==","ear":"x"}`)},
		{"token bytes are not DER", json.RawMessage(`{"token":"bm90LWRlcg==","signature":"AA=="}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := newMockAttestationApi(t, "deadbeef")
			h, _ := newSandboxTestEnv(t, mock.URL, "deadbeef")
			csrPEM, _ := generateCSR(t)
			w := postAttestSandbox(t, h, issueChallenge(t, h), csrPEM, tc.token)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body = %s", w.Code, w.Body.String())
			}
		})
	}
}
