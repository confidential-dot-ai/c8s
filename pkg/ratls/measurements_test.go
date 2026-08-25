package ratls

import (
	"bytes"

	"encoding/hex"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"reflect"
	"strings"
	"testing"
)

func TestParseHexMeasurementsList(t *testing.T) {
	m1 := bytes.Repeat([]byte{0xAB}, SNPMeasurementSize)
	m2 := bytes.Repeat([]byte{0xCD}, SNPMeasurementSize)

	tests := []struct {
		name    string
		in      []string
		want    [][]byte
		wantErr string
	}{
		{"single valid", []string{hex.EncodeToString(m1)}, [][]byte{m1}, ""},
		{"multiple valid", []string{hex.EncodeToString(m1), hex.EncodeToString(m2)}, [][]byte{m1, m2}, ""},
		{"blank entries skipped", []string{"", "  ", hex.EncodeToString(m1)}, [][]byte{m1}, ""},
		{"all blank returns nil", []string{"", "  "}, nil, ""},
		{"empty slice returns nil", nil, nil, ""},
		{"invalid hex", []string{"zz"}, nil, "invalid hex measurement"},
		{"wrong length", []string{hex.EncodeToString([]byte{1, 2, 3})}, nil, "want 48"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHexMeasurementsList(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseHexMeasurementsList: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %x, want %x", got, tt.want)
			}
		})
	}
}

func TestParseHexMeasurements(t *testing.T) {
	m1 := bytes.Repeat([]byte{0xAB}, SNPMeasurementSize)
	m2 := bytes.Repeat([]byte{0xCD}, SNPMeasurementSize)

	got, err := ParseHexMeasurements(hex.EncodeToString(m1) + "," + hex.EncodeToString(m2))
	if err != nil {
		t.Fatalf("ParseHexMeasurements: %v", err)
	}
	if !reflect.DeepEqual(got, [][]byte{m1, m2}) {
		t.Fatalf("got %x, want %x", got, [][]byte{m1, m2})
	}

	got, err = ParseHexMeasurements("")
	if err != nil || got != nil {
		t.Fatalf("empty input: got %x, %v; want nil, nil", got, err)
	}
}

func TestParseRTMRPins(t *testing.T) {
	hex48 := strings.Repeat("ab", 48)
	want, err := hex.DecodeString(hex48)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid pins", func(t *testing.T) {
		got, err := ParseRTMRPins([]string{"1=" + hex48, " 2 = " + hex48})
		if err != nil {
			t.Fatalf("ParseRTMRPins: %v", err)
		}
		if len(got) != 2 || !bytes.Equal(got[1], want) || !bytes.Equal(got[2], want) {
			t.Fatalf("pins = %v, want RTMR[1] and RTMR[2] = %s", got, hex48)
		}
	})

	t.Run("empty and blank entries pin nothing", func(t *testing.T) {
		for _, in := range [][]string{nil, {}, {" ", ""}} {
			got, err := ParseRTMRPins(in)
			if err != nil || got != nil {
				t.Fatalf("ParseRTMRPins(%q) = %v, %v; want nil, nil", in, got, err)
			}
		}
	})

	rejects := map[string][]string{
		"missing separator":  {hex48},
		"non-numeric index":  {"x=" + hex48},
		"index zero":         {"0=" + hex48},
		"index out of range": {"4=" + hex48},
		"duplicate index":    {"1=" + hex48, "1=" + hex48},
		"non-hex value":      {"1=zz"},
		"short value":        {"1=abcd"},
	}
	for name, in := range rejects {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRTMRPins(in); err == nil {
				t.Fatalf("ParseRTMRPins(%q) accepted, want error", in)
			}
		})
	}
}

func TestParseRTMRPinsString(t *testing.T) {
	hex48 := strings.Repeat("cd", 48)
	got, err := ParseRTMRPinsString("1=" + hex48 + ",2=" + hex48)
	if err != nil || len(got) != 2 {
		t.Fatalf("ParseRTMRPinsString = %v, %v; want two pins", got, err)
	}
	if got, err := ParseRTMRPinsString(" "); err != nil || got != nil {
		t.Fatalf("blank input = %v, %v; want nil, nil", got, err)
	}
}

// Every verifying path builds its policy from Pins, so a field dropped in the
// conversion would silently unpin without failing to compile.
func TestPinsVerifyPolicyCarriesEveryField(t *testing.T) {
	digest := bytes.Repeat([]byte{0xaa}, SNPMeasurementSize)
	reg := bytes.Repeat([]byte{0xbb}, SNPMeasurementSize)
	pins := Pins{
		Measurements: [][]byte{digest},
		RTMRs:        map[int][]byte{1: reg},
		Entries:      []measurements.Entry{{Name: "image", Digest: digest, RTMRs: map[int][]byte{1: reg}}},
	}

	policy := pins.VerifyPolicy("http://attestation-api")
	if len(policy.Entries) != 1 || policy.Entries[0].Name != "image" {
		t.Errorf("Entries dropped in conversion: %+v", policy.Entries)
	}
	if len(policy.Measurements) != 1 || !bytes.Equal(policy.Measurements[0], digest) {
		t.Errorf("Measurements dropped in conversion: %+v", policy.Measurements)
	}
	if !bytes.Equal(policy.RTMRs[1], reg) {
		t.Errorf("RTMRs dropped in conversion: %+v", policy.RTMRs)
	}
	if policy.AttestationApiURL != "http://attestation-api" {
		t.Errorf("AttestationApiURL = %q", policy.AttestationApiURL)
	}
}
