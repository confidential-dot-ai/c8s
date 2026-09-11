package ratls

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseHexInitData(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  string
		want []byte
	}{
		"snp host data": {strings.Repeat("aa", SNPHostDataSize), bytes.Repeat([]byte{0xaa}, SNPHostDataSize)},
		"tdx mrconfigid": {" " + strings.Repeat("bb", TDXMRConfigIDSize) + " ",
			bytes.Repeat([]byte{0xbb}, TDXMRConfigIDSize)},
		"unset": {"", nil},
		"blank": {"  ", nil},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseHexInitData(tc.raw)
			if err != nil {
				t.Fatalf("ParseHexInitData(%q): %v", tc.raw, err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("ParseHexInitData(%q) = %x, want %x", tc.raw, got, tc.want)
			}
		})
	}

	// A value of the wrong width would be compared against a field it can
	// never equal, which reads as a pin but accepts nothing.
	for _, bad := range []string{"zz", strings.Repeat("aa", 31), strings.Repeat("aa", 47), strings.Repeat("aa", 64)} {
		if _, err := ParseHexInitData(bad); err == nil {
			t.Errorf("ParseHexInitData(%q) accepted", bad)
		}
	}
}
