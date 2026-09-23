package policystate

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestParticipantMessagesRoundTrip checks each participant-to-CDS message
// survives the envelope, a strict decode and verification unchanged.
func TestParticipantMessagesRoundTrip(t *testing.T) {
	bootID := BootID(testPub())
	t.Run("enrollment", func(t *testing.T) {
		assertEnvelopeRoundTrip(t, Enrollment{
			Protocol:      Protocol,
			BootID:        bootID,
			Name:          "node-a",
			BootKey:       EncodeBootKey(testPub()),
			AppliedDigest: digestOf('b'),
		})
	})
	t.Run("ack", func(t *testing.T) {
		assertEnvelopeRoundTrip(t, Ack{
			Protocol:     Protocol,
			BootID:       bootID,
			Version:      4,
			TargetDigest: digestOf('d'),
			Retired:      4,
		})
	})
	t.Run("completion", func(t *testing.T) {
		assertEnvelopeRoundTrip(t, Completion{
			Protocol:     Protocol,
			BootID:       bootID,
			Version:      4,
			TargetDigest: digestOf('d'),
		})
	})
}

func assertEnvelopeRoundTrip[T comparable](t *testing.T, msg T) {
	t.Helper()
	env, err := SignMessage(testKey(), DomainAck, msg)
	if err != nil {
		t.Fatalf("SignMessage(priv, DomainAck, %+v) = _, %v, want no error", msg, err)
	}
	wire, err := Canonical(env)
	if err != nil {
		t.Fatalf("Canonical(env) = _, %v, want no error", err)
	}
	var back Envelope[T]
	if err := Decode(wire, &back); err != nil {
		t.Fatalf("Decode(%s) = %v, want no error", wire, err)
	}
	if back.Message != msg {
		t.Errorf("Decode(%s).Message = %+v, want %+v", wire, back.Message, msg)
	}
	if err := VerifyMessage(testPub(), DomainAck, back); err != nil {
		t.Errorf("VerifyMessage(pub, DomainAck, decoded) = %v, want no error", err)
	}
}

// TestBootIDNamesTheRawKey pins the identity rule: one CVM lifetime is named
// by the content digest of the key it generated at boot.
func TestBootIDNamesTheRawKey(t *testing.T) {
	got := BootID(testPub())
	if want := ContentDigest(testPub()); got != want {
		t.Errorf("BootID(pub) = %s, want %s", got, want)
	}
	if _, err := ParseHash(got); err != nil {
		t.Errorf("ParseHash(BootID(pub) = %q) = _, %v, want no error", got, err)
	}
}

func TestEncodeDecodeBootKey(t *testing.T) {
	encoded := EncodeBootKey(testPub())
	if strings.ContainsAny(encoded, "=+/") {
		t.Errorf("EncodeBootKey(pub) = %s, want unpadded base64url", encoded)
	}
	back, err := DecodeBootKey(encoded)
	if err != nil {
		t.Fatalf("DecodeBootKey(%s) = _, %v, want no error", encoded, err)
	}
	if !back.Equal(testPub()) {
		t.Errorf("DecodeBootKey(EncodeBootKey(pub)) = %x, want %x", back, testPub())
	}
}

func TestDecodeBootKeyRejects(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"padded base64", base64.URLEncoding.EncodeToString(testPub())},
		{"standard base64 with slashes", "a/b"},
		{"a short key", base64.RawURLEncoding.EncodeToString([]byte("short"))},
		{"empty", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeBootKey(tc.input)
			if err == nil {
				t.Errorf("DecodeBootKey(%q) = %x, nil, want an error", tc.input, got)
			}
		})
	}
}
