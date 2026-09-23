package policystate

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestHashSeparatesDomains is the property the domain prefix exists for: the
// same bytes under two domains must not collide.
func TestHashSeparatesDomains(t *testing.T) {
	canonical := []byte(`{"a":1}`)
	seen := map[string]string{}
	for _, domain := range []string{DomainState, DomainChallenge, DomainAck} {
		got := FormatHash(Hash(domain, canonical))
		if other, dup := seen[got]; dup {
			t.Errorf("Hash(%q, %s) = %s, want it to differ from Hash(%q, ...)", domain, canonical, got, other)
		}
		seen[got] = domain
	}
}

// TestHashSeparatorIsUnambiguous checks that moving bytes across the domain
// boundary changes the hash, so a domain cannot be extended into the payload.
func TestHashSeparatorIsUnambiguous(t *testing.T) {
	a := FormatHash(Hash("ab", []byte("c")))
	b := FormatHash(Hash("a", []byte("bc")))
	if a == b {
		t.Errorf(`Hash("ab", "c") = %s, want it to differ from Hash("a", "bc")`, a)
	}
}

func TestFormatHash(t *testing.T) {
	var h [hashLen]byte
	h[0], h[hashLen-1] = 0x0a, 0xff
	want := "sha256:0a" + strings.Repeat("00", hashLen-2) + "ff"
	if got := FormatHash(h); got != want {
		t.Errorf("FormatHash(h) = %s, want %s", got, want)
	}
}

func TestParseHash(t *testing.T) {
	valid := "sha256:" + strings.Repeat("ab", hashLen)
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"a valid hash", valid, false},
		{"uppercase hex", "sha256:" + strings.Repeat("AB", hashLen), true},
		{"no algorithm prefix", strings.Repeat("ab", hashLen), true},
		{"the wrong algorithm", "sha512:" + strings.Repeat("ab", hashLen), true},
		{"too short", "sha256:abcd", true},
		{"too long", valid + "ab", true},
		{"non-hex characters", "sha256:" + strings.Repeat("zz", hashLen), true},
		{"empty", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseHash(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseHash(%q) = %x, %v, want error: %v", tc.input, got, err, tc.wantErr)
			}
			if err == nil && FormatHash(got) != tc.input {
				t.Errorf("FormatHash(ParseHash(%q)) = %s, want %s", tc.input, FormatHash(got), tc.input)
			}
		})
	}
}

// TestContentDigestIsPlainSHA256 pins that a content address is reproducible
// by anyone holding the bytes, with no protocol knowledge.
func TestContentDigestIsPlainSHA256(t *testing.T) {
	// echo -n "" | sha256sum
	want := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := ContentDigest(nil); got != want {
		t.Errorf("ContentDigest(nil) = %s, want %s", got, want)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(want, "sha256:")); err != nil {
		t.Fatalf("hex.DecodeString(want) = %v, want no error", err)
	}
}
