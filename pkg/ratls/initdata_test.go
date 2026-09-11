package ratls

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseHexInitData(t *testing.T) {
	hostData := strings.Repeat("aa", 32)
	mrconfigID := strings.Repeat("bb", 48)

	got, err := ParseHexInitData(hostData + ", " + mrconfigID + ",")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !bytes.Equal(got[0], bytes.Repeat([]byte{0xaa}, 32)) || !bytes.Equal(got[1], bytes.Repeat([]byte{0xbb}, 48)) {
		t.Fatalf("got %x", got)
	}
	for _, empty := range []string{"", " , ", ","} {
		if got, err := ParseHexInitData(empty); err != nil || got != nil {
			t.Fatalf("ParseHexInitData(%q) = %v, %v; want nil, nil", empty, got, err)
		}
	}
	for _, bad := range []string{"zz", strings.Repeat("aa", 31), strings.Repeat("aa", 47), strings.Repeat("aa", 64)} {
		if _, err := ParseHexInitData(bad); err == nil {
			t.Errorf("ParseHexInitData(%q) accepted", bad)
		}
	}
}

// Pins.VerifyPolicy must carry the init-data pin: a conversion that dropped
// it would silently accept every launch of the pinned image.
func TestPinsVerifyPolicyCarriesInitData(t *testing.T) {
	pin := [][]byte{bytes.Repeat([]byte{0xaa}, 32)}
	pol := Pins{InitData: pin}.VerifyPolicy("http://127.0.0.1:8400")
	if len(pol.InitData) != 1 || !bytes.Equal(pol.InitData[0], pin[0]) {
		t.Fatalf("VerifyPolicy.InitData = %x, want %x", pol.InitData, pin)
	}
}
