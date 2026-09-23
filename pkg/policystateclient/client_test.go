package policystateclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/policystate"
)

const policyDoc = `{"schema":"c8s.allowlist/v1","workloads":{}}`

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
}

func serve(t *testing.T, routes map[string]http.HandlerFunc) Client {
	t.Helper()
	mux := http.NewServeMux()
	for pattern, h := range routes {
		mux.HandleFunc(pattern, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return New(srv.URL)
}

// serveObject answers every object request with the same bytes, which is what
// lets a test hand the client bytes that do not match the digest it asked for.
func serveObject(t *testing.T, body []byte) Client {
	t.Helper()
	return serve(t, map[string]http.HandlerFunc{
		policystate.PathObjectPrefix: func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write(body); err != nil {
				t.Errorf("write object: %v", err)
			}
		},
	})
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func testSignedState(t *testing.T, priv ed25519.PrivateKey) policystate.SignedState {
	t.Helper()
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("priv.Public() is %T, want ed25519.PublicKey", priv.Public())
	}
	authority, err := policystate.AuthorityFingerprint(pub)
	if err != nil {
		t.Fatalf("AuthorityFingerprint(pub) = _, %v, want no error", err)
	}
	signed, err := policystate.SignState(priv, policystate.State{
		Protocol:      policystate.Protocol,
		DeploymentID:  "deploy",
		Authority:     authority,
		LogHead:       policystate.ContentDigest([]byte("head")),
		LogPosition:   3,
		ActiveVersion: 1,
		ActiveDigest:  policystate.ContentDigest([]byte(policyDoc)),
		IssuedAt:      "2026-09-14T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("SignState(priv, s) = _, %v, want no error", err)
	}
	return signed
}

func testEntry(t *testing.T) (policystate.Entry, string) {
	t.Helper()
	entry, err := policystate.NewEntryAt(nil, "", policystate.ContentDigest([]byte("authority")), policystate.EventPublished,
		policystate.PublishedPayload{
			Version:      1,
			TargetDigest: policystate.ContentDigest([]byte(policyDoc)),
			AuthorizedBy: policystate.AuthorizedBySeed,
		}, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("NewEntryAt(...) = _, %v, want no error", err)
	}
	digest, err := policystate.EntryDigest(entry)
	if err != nil {
		t.Fatalf("EntryDigest(entry) = _, %v, want no error", err)
	}
	return entry, digest
}

func TestObject(t *testing.T) {
	want := []byte(policyDoc)
	digest := policystate.ContentDigest(want)
	cases := []struct {
		name    string
		digest  string
		body    []byte
		wantErr bool
	}{
		{name: "matching bytes", digest: digest, body: want},
		{name: "tampered bytes", digest: digest, body: append(want, ' '), wantErr: true},
		{name: "malformed digest", digest: "sha256:zz", body: want, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := serveObject(t, tc.body).Object(context.Background(), tc.digest)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Object(%s) = %q, %v, wantErr %v", tc.digest, got, err, tc.wantErr)
			}
			if !tc.wantErr && !bytes.Equal(got, want) {
				t.Errorf("Object(%s) = %q, want %q", tc.digest, got, want)
			}
		})
	}
}

// TestPolicyChecksTheDocument keeps an object that is not an allowlist from
// being installed as one, and returns the exact bytes a verifier pins.
func TestPolicyChecksTheDocument(t *testing.T) {
	cases := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{name: "an allowlist", body: []byte(policyDoc)},
		{name: "another document", body: []byte(`{"protocol":"c8s.policystate/v1"}`), wantErr: true},
		{name: "not json", body: []byte("nope"), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			digest := policystate.ContentDigest(tc.body)
			got, err := serveObject(t, tc.body).Policy(context.Background(), digest)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Policy(%s) = %q, %v, wantErr %v", digest, got, err, tc.wantErr)
			}
			if !tc.wantErr && !bytes.Equal(got, tc.body) {
				t.Errorf("Policy(%s) = %q, want %q", digest, got, tc.body)
			}
		})
	}
}

func TestEntry(t *testing.T) {
	entry, digest := testEntry(t)
	canonical, err := policystate.Canonical(entry)
	if err != nil {
		t.Fatalf("Canonical(entry) = _, %v, want no error", err)
	}
	invalid := entry
	invalid.Type = "nonsense"
	invalidBytes, err := policystate.Canonical(invalid)
	if err != nil {
		t.Fatalf("Canonical(invalidEntry) = _, %v, want no error", err)
	}
	cases := []struct {
		name    string
		digest  string
		body    []byte
		wantErr bool
	}{
		{name: "the named entry", digest: digest, body: canonical},
		{name: "another entry under that name", digest: digest, body: invalidBytes, wantErr: true},
		{name: "an entry with an unknown type", digest: policystate.ContentDigest(invalidBytes), body: invalidBytes, wantErr: true},
		{name: "an unknown field", digest: policystate.ContentDigest([]byte(`{"nope":1}`)), body: []byte(`{"nope":1}`), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := serveObject(t, tc.body).Entry(context.Background(), tc.digest)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Entry(%s) = %+v, %v, wantErr %v", tc.digest, got, err, tc.wantErr)
			}
			if !tc.wantErr && got.Position != entry.Position {
				t.Errorf("Entry(%s).Position = %d, want %d", tc.digest, got.Position, entry.Position)
			}
		})
	}
}

func TestStateVerifies(t *testing.T) {
	signed := testSignedState(t, testKey(t))
	c := serve(t, map[string]http.HandlerFunc{
		policystate.PathState: func(w http.ResponseWriter, _ *http.Request) { writeJSON(t, w, signed) },
	})
	got, err := c.State(context.Background())
	if err != nil {
		t.Fatalf("State() = _, %v, want no error", err)
	}
	if err := policystate.VerifySignedState(got); err != nil {
		t.Errorf("VerifySignedState(served state) = %v, want no error", err)
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	priv := testKey(t)
	signed := testSignedState(t, priv)
	c := serve(t, map[string]http.HandlerFunc{
		policystate.PathChallenge: func(w http.ResponseWriter, r *http.Request) {
			var req policystate.ChallengeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
			nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
			cs, err := policystate.SignChallenge(priv, signed, nonce)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(t, w, cs)
		},
	})
	nonce := bytes.Repeat([]byte{1}, 32)
	cs, err := c.Challenge(context.Background(), nonce)
	if err != nil {
		t.Fatalf("Challenge(nonce) = _, %v, want no error", err)
	}
	if err := policystate.VerifyChallengedState(cs, nonce); err != nil {
		t.Errorf("VerifyChallengedState(cs, nonce) = %v, want no error", err)
	}
	if _, err := c.Challenge(context.Background(), nonce[:4]); err == nil {
		t.Errorf("Challenge(short nonce) = nil error, want an error")
	}
}

func TestEnrollSignsEnvelope(t *testing.T) {
	priv := testKey(t)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("priv.Public() is %T, want ed25519.PublicKey", priv.Public())
	}
	var got policystate.Envelope[policystate.Enrollment]
	c := serve(t, map[string]http.HandlerFunc{
		policystate.PathEnroll: func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		},
	})
	e := policystate.Enrollment{
		Protocol:      policystate.Protocol,
		BootID:        policystate.BootID(pub),
		Name:          "n1",
		BootKey:       policystate.EncodeBootKey(pub),
		AppliedDigest: policystate.ContentDigest([]byte(policyDoc)),
	}
	if err := c.Enroll(context.Background(), priv, e); err != nil {
		t.Fatalf("Enroll(priv, e) = %v, want no error", err)
	}
	if err := policystate.VerifyMessage(pub, policystate.DomainAck, got); err != nil {
		t.Errorf("VerifyMessage(pub, DomainAck, posted envelope) = %v, want no error", err)
	}
	if got.Message != e {
		t.Errorf("posted message = %+v, want %+v", got.Message, e)
	}
}

func TestStatusError(t *testing.T) {
	c := serve(t, map[string]http.HandlerFunc{
		policystate.PathLatest: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope", http.StatusConflict) },
	})
	_, err := c.Latest(context.Background())
	if !IsStatus(err, http.StatusConflict) {
		t.Fatalf("Latest() error = %v, want a 409 StatusError", err)
	}
	if IsStatus(err, http.StatusNotFound) {
		t.Errorf("IsStatus(err, 404) = true, want false")
	}
}
