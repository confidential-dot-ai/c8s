package policystate

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"strings"
	"testing"
)

func TestBound(t *testing.T) {
	source, target := digestOf('b'), digestOf('d')
	withUpdate := func(u Update) State {
		s := testState()
		s.Update = &u
		return s
	}
	tests := []struct {
		name  string
		state State
		want  []string
	}{
		{"no update", quietState(), []string{quietState().ActiveDigest}},
		{"an update that removes permissions", testState(), []string{source, target}},
		{"an additions-only update", withUpdate(Update{Version: 4, SourceDigest: source, TargetDigest: target}), []string{target}},
		{"the first policy", withUpdate(Update{Version: 1, TargetDigest: target}), []string{target}},
		{"a republished identical policy", withUpdate(Update{Version: 4, SourceDigest: target, TargetDigest: target, RequiresDrain: true}), []string{target}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Bound(tc.state)
			if !slices.Equal(got, tc.want) {
				t.Errorf("Bound(%s) = %v, want %v", tc.name, got, tc.want)
			}
			if !slices.IsSorted(got) {
				t.Errorf("Bound(%s) = %v, want it sorted", tc.name, got)
			}
		})
	}
}

func TestStateHash(t *testing.T) {
	base, err := StateHash(testState())
	if err != nil {
		t.Fatalf("StateHash(testState()) = _, %v, want no error", err)
	}
	if _, err := ParseHash(base); err != nil {
		t.Errorf("ParseHash(StateHash(...) = %q) = _, %v, want no error", base, err)
	}
	other, err := StateHash(quietState())
	if err != nil {
		t.Fatalf("StateHash(quietState()) = _, %v, want no error", err)
	}
	if other == base {
		t.Errorf("StateHash(quietState()) = %s, want it to differ from %s", other, base)
	}
}

func TestSignAndVerifyState(t *testing.T) {
	signed, err := SignState(testKey(), testState())
	if err != nil {
		t.Fatalf("SignState(priv, testState()) = _, %v, want no error", err)
	}
	if err := VerifySignedState(signed); err != nil {
		t.Errorf("VerifySignedState(signed) = %v, want no error", err)
	}

	otherPub, otherPriv, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("z", 64)))
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() = _, _, %v, want no error", err)
	}
	otherEncoded, err := EncodeAuthorityKey(otherPub)
	if err != nil {
		t.Fatalf("EncodeAuthorityKey(otherPub) = _, %v, want no error", err)
	}
	otherKey := signed
	otherKey.PublicKey = otherEncoded
	malformedKey := signed
	malformedKey.PublicKey = "not base64!"
	tampered := signed
	tampered.Signature = flipLastBit(t, signed.Signature)
	editedStatement := signed
	editedStatement.Statement.ActiveVersion = 99
	invalidStatement := signed
	invalidStatement.Statement.Protocol = "c8s.policystate/v2"

	// A statement signed by another key, naming that key as its authority: it
	// verifies, and refusing it is the caller's trust decision, not ours.
	otherAuthority := testState()
	otherAuthority.Authority, err = AuthorityFingerprint(otherPub)
	if err != nil {
		t.Fatalf("AuthorityFingerprint(otherPub) = _, %v, want no error", err)
	}
	otherSigned, err := SignState(otherPriv, otherAuthority)
	if err != nil {
		t.Fatalf("SignState(otherPriv, otherAuthority) = _, %v, want no error", err)
	}

	tests := []struct {
		name    string
		in      SignedState
		wantErr bool
	}{
		{"the signed statement", signed, false},
		{"another authority's statement", otherSigned, false},
		{"a key that is not the named authority", otherKey, true},
		{"a malformed key", malformedKey, true},
		{"a tampered signature", tampered, true},
		{"an edited statement", editedStatement, true},
		{"an invalid statement", invalidStatement, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifySignedState(tc.in); (err != nil) != tc.wantErr {
				t.Errorf("VerifySignedState(%s) = %v, want error: %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

// TestSignStateRefusesAForeignAuthority keeps CDS from signing a statement
// that names a key it does not hold, or one a verifier must reject.
func TestSignStateRefusesAForeignAuthority(t *testing.T) {
	foreign := testState()
	foreign.Authority = digestOf('9')
	if got, err := SignState(testKey(), foreign); err == nil {
		t.Errorf("SignState(priv, stateNamingAnotherAuthority) = %+v, nil, want an error", got)
	}
	invalid := testState()
	invalid.IssuedAt = "now"
	if got, err := SignState(testKey(), invalid); err == nil {
		t.Errorf("SignState(priv, invalidStatement) = %+v, nil, want an error", got)
	}
}

func TestSignAndVerifyChallenge(t *testing.T) {
	nonce := bytes.Repeat([]byte{3}, MinNonceLen)
	signed, err := SignState(testKey(), testState())
	if err != nil {
		t.Fatalf("SignState(priv, testState()) = _, %v, want no error", err)
	}
	cs, err := SignChallenge(testKey(), signed, nonce)
	if err != nil {
		t.Fatalf("SignChallenge(priv, signed, nonce) = _, %v, want no error", err)
	}
	if err := VerifyChallengedState(cs, nonce); err != nil {
		t.Errorf("VerifyChallengedState(cs, nonce) = %v, want no error", err)
	}
	if cs.Challenge.LogHead != signed.Statement.LogHead {
		t.Errorf("SignChallenge(...).Challenge.LogHead = %s, want %s", cs.Challenge.LogHead, signed.Statement.LogHead)
	}

	movedHead := cs
	movedHead.Challenge.LogHead = digestOf('9')
	movedPosition := cs
	movedPosition.Challenge.LogPosition = 99
	movedAuthority := cs
	movedAuthority.Challenge.Authority = digestOf('9')
	badNonceEncoding := cs
	badNonceEncoding.Challenge.Nonce = "not base64!"
	tampered := cs
	tampered.ChallengeSignature = flipLastBit(t, cs.ChallengeSignature)

	tests := []struct {
		name  string
		in    ChallengedState
		nonce []byte
	}{
		{"a different nonce", cs, bytes.Repeat([]byte{4}, MinNonceLen)},
		{"a shorter nonce", cs, nonce[:MinNonceLen-1]},
		{"a binding naming another head", movedHead, nonce},
		{"a binding naming another position", movedPosition, nonce},
		{"a binding naming another authority", movedAuthority, nonce},
		{"a nonce that is not base64url", badNonceEncoding, nonce},
		{"a tampered challenge signature", tampered, nonce},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyChallengedState(tc.in, tc.nonce); err == nil {
				t.Errorf("VerifyChallengedState(%s) = nil, want an error", tc.name)
			}
		})
	}
}

func TestSignChallengeRejectsNonceLengths(t *testing.T) {
	signed, err := SignState(testKey(), testState())
	if err != nil {
		t.Fatalf("SignState(priv, testState()) = _, %v, want no error", err)
	}
	for _, n := range []int{0, MinNonceLen - 1, MaxNonceLen + 1} {
		got, err := SignChallenge(testKey(), signed, bytes.Repeat([]byte{1}, n))
		if err == nil {
			t.Errorf("SignChallenge(priv, signed, %d-byte nonce) = %+v, nil, want an error", n, got)
		}
	}
}

func TestValidateState(t *testing.T) {
	mutate := func(f func(*State)) State {
		s := testState()
		f(&s)
		return s
	}
	tests := []struct {
		name    string
		state   State
		wantErr bool
	}{
		{"a statement mid-update", testState(), false},
		{"a settled statement", quietState(), false},
		{"an unknown protocol", mutate(func(s *State) { s.Protocol = "c8s.policystate/v2" }), true},
		{"no deployment id", mutate(func(s *State) { s.DeploymentID = "" }), true},
		{"an authority that is not a fingerprint", mutate(func(s *State) { s.Authority = "cds" }), true},
		{"a log position of 0", mutate(func(s *State) { s.LogPosition = 0 }), true},
		{"a log position at 2^53", mutate(func(s *State) { s.LogPosition = MaxCounter }), true},
		{"an active version of 0", mutate(func(s *State) { s.ActiveVersion = 0 }), true},
		{"an active version at 2^53", mutate(func(s *State) { s.ActiveVersion = MaxCounter }), true},
		{"a malformed log head", mutate(func(s *State) { s.LogHead = "head" }), true},
		{"a malformed active digest", mutate(func(s *State) { s.ActiveDigest = "" }), true},
		{"an update with version 0", mutate(func(s *State) { s.Update.Version = 0 }), true},
		{"an update with no target digest", mutate(func(s *State) { s.Update.TargetDigest = "" }), true},
		{"an update with a malformed source digest", mutate(func(s *State) { s.Update.SourceDigest = "source" }), true},
		{"a drain with no source policy", mutate(func(s *State) { s.Update.SourceDigest = "" }), true},
		{"an issued_at that is not RFC3339", mutate(func(s *State) { s.IssuedAt = "now" }), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateState(tc.state)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateState(%s) = %v, want error: %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

// TestChallengedStateWireShape pins that the signed state fields stay inline
// beside the challenge, which is what the endpoint's consumers parse.
func TestChallengedStateWireShape(t *testing.T) {
	signed, err := SignState(testKey(), quietState())
	if err != nil {
		t.Fatalf("SignState(priv, quietState()) = _, %v, want no error", err)
	}
	cs, err := SignChallenge(testKey(), signed, bytes.Repeat([]byte{5}, MinNonceLen))
	if err != nil {
		t.Fatalf("SignChallenge(priv, signed, nonce) = _, %v, want no error", err)
	}
	wire, err := Canonical(cs)
	if err != nil {
		t.Fatalf("Canonical(cs) = _, %v, want no error", err)
	}
	for _, want := range []string{`"statement":`, `"public_key":`, `"signature":`, `"challenge":`, `"challenge_signature":`} {
		if !strings.Contains(string(wire), want) {
			t.Errorf("Canonical(cs) = %s, want it to contain %s", wire, want)
		}
	}
	var back ChallengedState
	if err := Decode(wire, &back); err != nil {
		t.Fatalf("Decode(%s) = %v, want no error", wire, err)
	}
	if err := VerifyChallengedState(back, bytes.Repeat([]byte{5}, MinNonceLen)); err != nil {
		t.Errorf("VerifyChallengedState(decoded, nonce) = %v, want no error", err)
	}
}
