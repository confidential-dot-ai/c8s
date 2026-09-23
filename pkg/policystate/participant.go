package policystate

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// Participant messages are the private coordinator API: CDS needs them to know
// when an update may switch and complete, but a verifier never sees them. Each
// is posted inside an Envelope signed by the sender's boot key under DomainAck.

// Enrollment announces a CVM boot to CDS. The key it carries is the one CDS
// requires on every later message from that boot id.
type Enrollment struct {
	Protocol      string `json:"protocol"`
	BootID        string `json:"boot_id"`
	Name          string `json:"name"`
	BootKey       string `json:"boot_key"`
	AppliedDigest string `json:"applied_digest"`
}

// Ack says a participant's barrier for an update is in place: new work already
// satisfies the target, and Retired counts what still holds permissions only
// the source granted — running instances for an enforcer, open sessions for a
// router. An update switches when every frozen participant has acked.
type Ack struct {
	Protocol     string `json:"protocol"`
	BootID       string `json:"boot_id"`
	Version      uint64 `json:"version"`
	TargetDigest string `json:"target_digest"`
	Retired      uint64 `json:"retired"`
}

// Completion says the target is applied and nothing on this participant still
// needs the source. It is a claim by the participant, not proof: what it is
// worth depends on that participant's measured enforcement profile.
type Completion struct {
	Protocol     string `json:"protocol"`
	BootID       string `json:"boot_id"`
	Version      uint64 `json:"version"`
	TargetDigest string `json:"target_digest"`
}

// BootID names one CVM lifetime by its boot key. A reboot generates a new key
// and so a new boot id, which is what keeps a lifetime's policy exposure
// attributable after the machine comes back.
func BootID(pub ed25519.PublicKey) string {
	return ContentDigest(pub)
}

// EncodeBootKey renders a boot key as unpadded base64url of its raw 32 bytes,
// the form Enrollment carries.
func EncodeBootKey(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// DecodeBootKey parses the wire form and checks the length, so a truncated key
// cannot reach ed25519.Verify, which would panic on it.
func DecodeBootKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("boot key is not unpadded base64url: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("boot key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
