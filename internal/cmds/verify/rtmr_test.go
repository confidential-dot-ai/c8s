package verify

import (
	"encoding/hex"
	"strings"
	"testing"
)

func sha384Hex(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), 48) }

func TestParseRTMRPins(t *testing.T) {
	t.Run("indices 1 and 2 parse", func(t *testing.T) {
		got, err := parseRTMRPins([]string{"1=" + sha384Hex(0x11), "2=" + sha384Hex(0x22)})
		if err != nil {
			t.Fatalf("parseRTMRPins: %v", err)
		}
		if len(got) != 2 || hex.EncodeToString(got[1]) != sha384Hex(0x11) || hex.EncodeToString(got[2]) != sha384Hex(0x22) {
			t.Fatalf("parsed %v, want RTMR[1] and RTMR[2]", got)
		}
	})

	t.Run("no pins is nil", func(t *testing.T) {
		got, err := parseRTMRPins(nil)
		if err != nil || got != nil {
			t.Fatalf("parseRTMRPins(nil) = %v, %v; want nil, nil", got, err)
		}
	})

	// Rejected rather than ignored: accepting them would look like a guest
	// identity pin while providing none.
	for _, tc := range []struct{ name, pin, want string }{
		{"RTMR[0] tracks pod shape", "0=" + sha384Hex(0), "TD HOB"},
		{"RTMR[3] is guest-extended", "3=" + sha384Hex(3), "in-guest software"},
		{"index out of range", "9=" + sha384Hex(9), "must be 1 or 2"},
		{"missing =", sha384Hex(1), "<index>=<sha384-hex>"},
		{"index not a number", "x=" + sha384Hex(1), "not a number"},
		{"value not hex", "1=zzzz", "not hex"},
		{"wrong length", "1=" + hex.EncodeToString([]byte{1, 2, 3}), "bytes, want 48"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRTMRPins([]string{tc.pin})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}

	t.Run("repeated index rejected", func(t *testing.T) {
		_, err := parseRTMRPins([]string{"1=" + sha384Hex(1), "1=" + sha384Hex(2)})
		if err == nil || !strings.Contains(err.Error(), "more than once") {
			t.Fatalf("error = %v, want a duplicate-index error", err)
		}
	})
}

func TestBuildPolicyCarriesRTMRPins(t *testing.T) {
	p, err := buildPolicy(config{rtmrs: []string{"2=" + sha384Hex(0x22)}})
	if err != nil {
		t.Fatalf("buildPolicy: %v", err)
	}
	if len(p.RTMRs) != 1 || hex.EncodeToString(p.RTMRs[2]) != sha384Hex(0x22) {
		t.Fatalf("policy RTMRs = %v, want RTMR[2] pinned", p.RTMRs)
	}
}
