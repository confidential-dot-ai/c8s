package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/policystate"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// buildStateEndpointJSON is what a router answers attest-pq with: the
// statement travels in the response, and its hash, the session's envelope and
// the route are framed into the transcript the identity proof signs.
func buildStateEndpointJSON(t *testing.T, id *endpointIdentity, nonce, report []byte, s testSession, signed policystate.SignedState, route string) []byte {
	t.Helper()
	b64u := base64.RawURLEncoding.EncodeToString
	hash, err := policystate.StateHash(signed.Statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope := policystate.Bound(signed.Statement)
	transcript, err := overenc.IdentityTranscriptHash("cds", s.ek, s.ct, s.sid, nonce, id.leaf.Raw, id.ca.Raw, hash, envelope, route)
	if err != nil {
		t.Fatal(err)
	}
	stateJSON, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	resp := map[string]any{
		"version":  types.BindingAttestPQ,
		"platform": "snp",
		"nonce":    b64u(nonce),
		"evidence": map[string]any{
			"attestation_report": base64.StdEncoding.EncodeToString(report),
			"cert_chain":         map[string]any{"vcek": base64.StdEncoding.EncodeToString([]byte("vcek"))},
		},
		"front_door_mode": "cds",
		"xwing_ek":        b64u(s.ek),
		"xwing_ct":        b64u(s.ct),
		"session_id":      b64u(s.sid),
		"cds_cert_pem":    id.chainPEM,
		"identity_proof":  id.proofJSON(t, transcript),
		"state":           json.RawMessage(stateJSON),
		"state_hash":      hash,
		"envelope":        envelope,
		"route":           route,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// signTestState signs a settled statement under a throwaway authority, which
// is all the gather path needs: whether that authority may speak for the
// deployment is the state policy's question.
func signTestState(t *testing.T, update *policystate.Update) policystate.SignedState {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := policystate.AuthorityFingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := policystate.SignState(priv, policystate.State{
		Protocol:      policystate.Protocol,
		DeploymentID:  "c8s-test",
		Authority:     fingerprint,
		LogHead:       "sha256:" + strings.Repeat("a", 64),
		LogPosition:   4,
		ActiveVersion: 2,
		ActiveDigest:  testDigestP,
		Update:        update,
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// The response is parsed into the bound statement, and report_data is
// recomputed with the statement's own hash and bound — not the state_hash and
// envelope fields the responder chose.
func TestGatherReadsTheStateBinding(t *testing.T) {
	report := bytes.Repeat([]byte{0x01}, 64)
	id := mintEndpointIdentity(t)
	signed := signTestState(t, &policystate.Update{
		Version: 3, SourceDigest: testDigestP, TargetDigest: testDigestQ, RequiresDrain: true,
	})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.AttestPQRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
		if err != nil {
			http.Error(w, "bad nonce", http.StatusBadRequest)
			return
		}
		sess := fakeSession(0x02)
		if sess.ek, err = base64.RawURLEncoding.DecodeString(req.XWingEK); err != nil {
			http.Error(w, "bad xwing_ek", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildStateEndpointJSON(t, id, nonce, report, sess, signed, "api"))
	}))
	defer srv.Close()

	ev, err := gatherFromEndpoint(context.Background(), srv.URL, "", 5*time.Second)
	if err != nil {
		t.Fatalf("gatherFromEndpoint: %v", err)
	}
	if ev.state == nil {
		t.Fatalf("no state bound; note = %q", ev.stateNote)
	}
	if ev.bindingVersion != types.BindingAttestPQ {
		t.Errorf("binding version = %q, want %q", ev.bindingVersion, types.BindingAttestPQ)
	}
	if ev.route != "api" {
		t.Errorf("route = %q, want api", ev.route)
	}
	if ev.state.signed.Statement.ActiveDigest != testDigestP {
		t.Errorf("bound active digest = %q, want %q", ev.state.signed.Statement.ActiveDigest, testDigestP)
	}
	want := []string{testDigestP, testDigestQ}
	if len(ev.state.envelope) != 2 || ev.state.envelope[0] != want[0] || ev.state.envelope[1] != want[1] {
		t.Errorf("envelope = %v, want the source-or-target bound %v", ev.state.envelope, want)
	}
	if ev.stateFetchCert == "" {
		t.Error("no certificate recorded for the follow-up state fetches")
	}
}

// A responder that names one policy and ships another is caught where the
// hash and the bound are recomputed, not at the report-data compare.
func TestGatherRejectsAMisreportedBinding(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	report := bytes.Repeat([]byte{0x01}, 64)
	id := mintEndpointIdentity(t)
	base := buildStateEndpointJSON(t, id, nonce, report, fakeSession(0x02), signTestState(t, nil), "api")

	for _, tc := range []struct {
		name  string
		field string
		value any
	}{
		{name: "state hash", field: "state_hash", value: "sha256:" + strings.Repeat("0", 64)},
		{name: "envelope", field: "envelope", value: []string{testDigestQ}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var obj map[string]any
			if err := json.Unmarshal(base, &obj); err != nil {
				t.Fatal(err)
			}
			obj[tc.field] = tc.value
			mutated, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := evidenceFromEndpointJSON(mutated, nonce, fakeSession(0x02).ek, "test"); err == nil || !isSecurityError(err) {
				t.Fatalf("error = %v, want a security error about the %s", err, tc.name)
			}
		})
	}
}

// A statement whose signature does not verify under the key it carries is
// rejected where it is parsed: nothing downstream should ever see it.
func TestGatherRejectsAnUnsignedStatement(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	report := bytes.Repeat([]byte{0x01}, 64)
	id := mintEndpointIdentity(t)
	signed := signTestState(t, nil)
	signed.Signature = signTestState(t, nil).Signature

	data := buildStateEndpointJSON(t, id, nonce, report, fakeSession(0x02), signed, "api")
	if _, err := evidenceFromEndpointJSON(data, nonce, fakeSession(0x02).ek, "test"); err == nil || !isSecurityError(err) {
		t.Fatalf("error = %v, want a security error about the state signature", err)
	}
}
