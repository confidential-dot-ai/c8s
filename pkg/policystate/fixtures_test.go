package policystate

import (
	"bytes"
	"crypto/ed25519"
	"strings"
)

// testSeed is the fixed Ed25519 seed the cross-language vectors are generated
// from. Every signature in the tests and in testdata/vectors.json comes from
// it, so a change to the signing input shows up as a vector mismatch.
var testSeed = bytes.Repeat([]byte{7}, 32)

// testAuthority is the fingerprint of testPub, the authority every fixture
// statement names.
var testAuthority = mustFingerprint()

func testKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(testSeed) }

func testPub() ed25519.PublicKey { return testKey().Public().(ed25519.PublicKey) }

func mustFingerprint() string {
	fingerprint, err := AuthorityFingerprint(testKey().Public().(ed25519.PublicKey))
	if err != nil {
		panic(err)
	}
	return fingerprint
}

func digestOf(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// testState is a statement mid-update: an outstanding move that removed
// permissions, already switched and waiting to drain.
func testState() State {
	return State{
		Protocol:      Protocol,
		DeploymentID:  "deploy-1",
		Authority:     testAuthority,
		LogHead:       digestOf('a'),
		LogPosition:   7,
		ActiveVersion: 4,
		ActiveDigest:  digestOf('d'),
		Update: &Update{
			Version:       4,
			SourceDigest:  digestOf('b'),
			TargetDigest:  digestOf('d'),
			RequiresDrain: true,
			Switched:      true,
		},
		IssuedAt: "2026-09-14T10:00:00Z",
	}
}

// quietState is the settled case: one active policy, nothing outstanding.
func quietState() State {
	return State{
		Protocol:      Protocol,
		DeploymentID:  "deploy-1",
		Authority:     testAuthority,
		LogHead:       digestOf('a'),
		LogPosition:   1,
		ActiveVersion: 1,
		ActiveDigest:  digestOf('b'),
		IssuedAt:      "2026-09-14T10:00:00Z",
	}
}
