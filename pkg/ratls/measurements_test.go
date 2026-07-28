package ratls

import (
	"bytes"
	"encoding/hex"
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
