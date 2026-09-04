package attestation_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/internal/testattest"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func testAppWithRTMRs(t *testing.T, attestationURL string, rtmrs map[int][]byte) http.Handler {
	t.Helper()
	challengeStore := attestation.NewChallengeStore(60 * time.Second)
	earIssuer, err := ear.NewIssuer(testKeyPEM(), "test-issuer", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h := attestation.Handler{
		Challenges:        &challengeStore,
		AttestationClient: attestationclient.NewClient(attestationURL),
		EarIssuer:         earIssuer,
		RTMRs:             rtmrs,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /authenticate", attestation.HandleAuthenticate(h.Challenges))
	mux.HandleFunc("POST /attest-key", h.HandleAttestKey)
	return mux
}

func attestKeyBodyTDX(t *testing.T, appURL string) string {
	t.Helper()
	challenge := authenticate(t, appURL)
	pubKey := generateAttestKeyPubKey(t)
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	return mustJSON(types.AttestKeyRequestBody{
		Challenge: challenge,
		Evidence: types.AttestationEvidence{
			Platform: "tdx",
			Evidence: json.RawMessage(`{"quote":"abc"}`),
		},
		PublicKey: base64.StdEncoding.EncodeToString(pubDER),
	})
}

// A TDX caller whose pinned register does not match the verified report must
// be minted no EAR: the EAR's launch digest (MRTD) covers TDVF firmware only,
// and this gate is what keeps a substituted guest image out of the EAR chain.
func TestAttestKeyTDXWrongRTMRMintsNoEAR(t *testing.T) {
	pinned, err := hex.DecodeString(strings.Repeat("11", 48))
	if err != nil {
		t.Fatal(err)
	}
	stub := testattest.New(t)
	verdict := testattest.PassingVerdict(strings.Repeat("aa", 48))
	verdict.Claims.PlatformData = map[string]any{"rtmr_1": strings.Repeat("ab", 48)}
	stub.SetVerdict(verdict)

	app := httptest.NewServer(testAppWithRTMRs(t, stub.URL, map[int][]byte{1: pinned}))
	defer app.Close()

	resp := postAttestKey(t, app.URL, attestKeyBodyTDX(t, app.URL))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// The same pins with a matching report mint normally.
func TestAttestKeyTDXMatchingRTMRMints(t *testing.T) {
	rtmr1 := strings.Repeat("11", 48)
	pinned, err := hex.DecodeString(rtmr1)
	if err != nil {
		t.Fatal(err)
	}
	stub := testattest.New(t)
	verdict := testattest.PassingVerdict(strings.Repeat("aa", 48))
	verdict.Claims.PlatformData = map[string]any{"rtmr_1": rtmr1}
	stub.SetVerdict(verdict)

	app := httptest.NewServer(testAppWithRTMRs(t, stub.URL, map[int][]byte{1: pinned}))
	defer app.Close()

	resp := postAttestKey(t, app.URL, attestKeyBodyTDX(t, app.URL))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// SNP evidence carries no registers; configured pins must not refuse it.
func TestAttestKeySNPUnaffectedByRTMRPins(t *testing.T) {
	pinned, err := hex.DecodeString(strings.Repeat("11", 48))
	if err != nil {
		t.Fatal(err)
	}
	stub := testattest.New(t)

	app := httptest.NewServer(testAppWithRTMRs(t, stub.URL, map[int][]byte{1: pinned}))
	defer app.Close()

	resp := postAttestKey(t, app.URL, attestKeyBody(t, app.URL))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
