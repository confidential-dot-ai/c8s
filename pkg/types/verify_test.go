package types

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestHeaderFieldWireShape pins the header encoding the JS client depends on:
// one field is a two-element CBOR array [name, value], not a map.
func TestHeaderFieldWireShape(t *testing.T) {
	got, err := cbor.Marshal(HeaderField{Name: "Set-Cookie", Value: "a=1"})
	if err != nil {
		t.Fatal(err)
	}
	want, err := cbor.Marshal([]string{"Set-Cookie", "a=1"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("HeaderField wire shape = %x, want the array form %x", got, want)
	}

	var back HeaderField
	if err := cbor.Unmarshal(want, &back); err != nil {
		t.Fatal(err)
	}
	if back.Name != "Set-Cookie" || back.Value != "a=1" {
		t.Fatalf("round-trip = %+v", back)
	}
}
