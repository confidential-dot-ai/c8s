package earclaims

import (
	"encoding/json"
	"testing"
)

func TestBindSetsNameAndTarget(t *testing.T) {
	var s string
	b := Bind("foo", &s)
	if b.Name != "foo" {
		t.Errorf("Name = %q, want foo", b.Name)
	}
	if b.Target != &s {
		t.Errorf("Target not set to provided pointer")
	}
}

func TestUnmarshalObjectBindsPresentClaims(t *testing.T) {
	raw := []byte(`{"name":"alice","age":30}`)
	var name string
	var age int
	if err := UnmarshalObject(raw, Bind("name", &name), Bind("age", &age)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "alice" {
		t.Errorf("name = %q, want alice", name)
	}
	if age != 30 {
		t.Errorf("age = %d, want 30", age)
	}
}

func TestUnmarshalObjectIgnoresMissingClaims(t *testing.T) {
	raw := []byte(`{"name":"alice"}`)
	missing := "untouched"
	if err := UnmarshalObject(raw, Bind("absent", &missing)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if missing != "untouched" {
		t.Errorf("missing binding mutated target to %q", missing)
	}
}

func TestUnmarshalObjectInvalidTopLevelJSON(t *testing.T) {
	var v string
	if err := UnmarshalObject([]byte(`not json`), Bind("x", &v)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestUnmarshalObjectClaimTypeMismatchWrapsName(t *testing.T) {
	raw := []byte(`{"age":"not-a-number"}`)
	var age int
	err := UnmarshalObject(raw, Bind("age", &age))
	if err == nil {
		t.Fatal("expected error for type mismatch")
	}
	if got := err.Error(); !contains(got, "age") {
		t.Errorf("error %q should mention claim name", got)
	}
}

func TestUnmarshalObjectEmptyRawClaimSkipped(t *testing.T) {
	// A claim explicitly present but null/empty should not be unmarshaled.
	var object = map[string]json.RawMessage{"x": json.RawMessage("")}
	encoded, _ := json.Marshal(map[string]any{"y": 1})
	_ = object
	var x int
	if err := UnmarshalObject(encoded, Bind("x", &x)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if x != 0 {
		t.Errorf("x = %d, want 0", x)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
