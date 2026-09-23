package policystate

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSignVerify(t *testing.T) {
	priv, pub := testKey(), testPub()
	canonical := []byte(`{"a":1}`)
	sig, err := Sign(priv, DomainAck, canonical)
	if err != nil {
		t.Fatalf("Sign(priv, DomainAck, %s) = _, %v, want no error", canonical, err)
	}
	other, _, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("x", 64)))
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() = _, _, %v, want no error", err)
	}
	tampered := flipLastBit(t, sig)

	tests := []struct {
		name      string
		pub       ed25519.PublicKey
		domain    string
		canonical []byte
		signature string
		wantErr   bool
	}{
		{"the signed message", pub, DomainAck, canonical, sig, false},
		{"a different domain", pub, DomainState, canonical, sig, true},
		{"different bytes", pub, DomainAck, []byte(`{"a":2}`), sig, true},
		{"a different key", other, DomainAck, canonical, sig, true},
		{"a tampered signature", pub, DomainAck, canonical, tampered, true},
		{"a signature that is not base64url", pub, DomainAck, canonical, "not base64!", true},
		{"a truncated signature", pub, DomainAck, canonical, sig[:10], true},
		{"a short public key", ed25519.PublicKey("short"), DomainAck, canonical, sig, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Verify(tc.pub, tc.domain, tc.canonical, tc.signature)
			if (err != nil) != tc.wantErr {
				t.Errorf("Verify(pub, %q, %s, sig) = %v, want error: %v", tc.domain, tc.canonical, err, tc.wantErr)
			}
		})
	}
}

func TestSignRejectsAShortKey(t *testing.T) {
	got, err := Sign(ed25519.PrivateKey("short"), DomainAck, nil)
	if err == nil {
		t.Errorf("Sign(shortKey, DomainAck, nil) = %q, nil, want an error", got)
	}
}

func TestSignVerifyMessage(t *testing.T) {
	msg := Ack{
		Protocol:     Protocol,
		BootID:       BootID(testPub()),
		Version:      4,
		TargetDigest: digestOf('d'),
		Retired:      2,
	}
	env, err := SignMessage(testKey(), DomainAck, msg)
	if err != nil {
		t.Fatalf("SignMessage(priv, DomainAck, ack) = _, %v, want no error", err)
	}
	if err := VerifyMessage(testPub(), DomainAck, env); err != nil {
		t.Errorf("VerifyMessage(pub, DomainAck, env) = %v, want no error", err)
	}

	edited := env
	edited.Message.Retired = 3
	if err := VerifyMessage(testPub(), DomainAck, edited); err == nil {
		t.Errorf("VerifyMessage(pub, DomainAck, editedEnvelope) = nil, want an error")
	}
	if err := VerifyMessage(testPub(), DomainState, env); err == nil {
		t.Errorf("VerifyMessage(pub, DomainState, env) = nil, want an error")
	}
}

// TestEnvelopeRoundTripsStrictly checks the envelope survives the wire in the
// shape the contract pins: {"message":..., "signature":...}.
func TestEnvelopeRoundTripsStrictly(t *testing.T) {
	env, err := SignMessage(testKey(), DomainAck, Completion{
		Protocol:     Protocol,
		BootID:       BootID(testPub()),
		Version:      4,
		TargetDigest: digestOf('d'),
	})
	if err != nil {
		t.Fatalf("SignMessage(priv, DomainAck, completion) = _, %v, want no error", err)
	}
	wire, err := Canonical(env)
	if err != nil {
		t.Fatalf("Canonical(env) = _, %v, want no error", err)
	}
	var back Envelope[Completion]
	if err := Decode(wire, &back); err != nil {
		t.Fatalf("Decode(%s) = %v, want no error", wire, err)
	}
	if err := VerifyMessage(testPub(), DomainAck, back); err != nil {
		t.Errorf("VerifyMessage(pub, DomainAck, decoded) = %v, want no error", err)
	}
}

func flipLastBit(t *testing.T, signature string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("base64 decode of %q = %v, want no error", signature, err)
	}
	raw[len(raw)-1] ^= 1
	return base64.RawURLEncoding.EncodeToString(raw)
}
