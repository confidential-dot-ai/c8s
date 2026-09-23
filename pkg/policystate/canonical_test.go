package policystate

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestCanonical(t *testing.T) {
	type inner struct {
		Zebra string `json:"zebra"`
		Apple string `json:"apple"`
	}
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{"sorts object keys bytewise", map[string]any{"b": 1, "A": 2, "a": 3}, `{"A":2,"a":3,"b":1}`},
		{"sorts nested object keys", map[string]any{"outer": inner{Zebra: "z", Apple: "a"}}, `{"outer":{"apple":"a","zebra":"z"}}`},
		{"leaves HTML characters verbatim", map[string]string{"k": "<tag> & \"q\""}, `{"k":"<tag> & \"q\""}`},
		{"leaves non-ASCII verbatim", map[string]string{"k": "héllo … 日本 \U0001f512"}, "{\"k\":\"héllo … 日本 \U0001f512\"}"},
		{"escapes only what JSON requires", map[string]string{"k": "a\tb\nc\\d\x01"}, `{"k":"a\tb\nc\\d` + `\u0001` + `"}`},
		{"keeps the line separator unescaped", map[string]string{"k": "a\u2028b"}, "{\"k\":\"a\u2028b\"}"},
		{"keeps an empty required slice as []", map[string][]string{"p": {}}, `{"p":[]}`},
		{"writes a nil slice as null", map[string][]string{"p": nil}, `{"p":null}`},
		{"keeps integers exact", map[string]uint64{"n": MaxCounter - 1}, `{"n":9007199254740991}`},
		{"keeps negative integers", map[string]int{"n": -5}, `{"n":-5}`},
		{"preserves array order", []any{3, 1, 2}, `[3,1,2]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonical(tc.input)
			if err != nil {
				t.Fatalf("Canonical(%v) = _, %v, want no error", tc.input, err)
			}
			if string(got) != tc.want {
				t.Errorf("Canonical(%v) = %s, want %s", tc.input, got, tc.want)
			}
		})
	}
}

// TestCanonicalWritesAbsentUpdateAsNull pins the one field the contract
// requires to be explicitly null rather than omitted.
func TestCanonicalWritesAbsentUpdateAsNull(t *testing.T) {
	got, err := Canonical(quietState())
	if err != nil {
		t.Fatalf("Canonical(quietState()) = _, %v, want no error", err)
	}
	if !strings.Contains(string(got), `"update":null`) {
		t.Errorf(`Canonical(quietState()) = %s, want it to contain "update":null`, got)
	}
}

func TestCanonicalRejects(t *testing.T) {
	tests := []struct {
		name  string
		input any
	}{
		{"a float", map[string]float64{"n": 1.5}},
		{"a whole float in exponent form", map[string]float64{"n": 1e300}},
		{"a counter at 2^53", map[string]uint64{"n": MaxCounter}},
		{"a counter above 2^53", map[string]uint64{"n": math.MaxUint64}},
		{"a negative counter at -2^53", map[string]int64{"n": -int64(MaxCounter)}},
		{"a value json cannot encode", map[string]any{"c": make(chan int)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonical(tc.input)
			if err == nil {
				t.Errorf("Canonical(%v) = %s, nil, want an error", tc.input, got)
			}
		})
	}
}

// TestCanonicalIsStable pins that a value and a re-parse of its canonical form
// produce identical bytes, which is the property a verifier relies on.
func TestCanonicalIsStable(t *testing.T) {
	first, err := Canonical(testState())
	if err != nil {
		t.Fatalf("Canonical(testState()) = _, %v, want no error", err)
	}
	var tree any
	if err := json.Unmarshal(first, &tree); err != nil {
		t.Fatalf("json.Unmarshal(canonical) = %v, want no error", err)
	}
	second, err := Canonical(tree)
	if err != nil {
		t.Fatalf("Canonical(reparsed) = _, %v, want no error", err)
	}
	if string(first) != string(second) {
		t.Errorf("Canonical(reparsed) = %s, want %s", second, first)
	}
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{"a well-formed object", `{"authority":"sha256:aa","version":1}`, false},
		{"an unknown field", `{"authority":"sha256:aa","extra":1}`, true},
		{"trailing data", `{"authority":"sha256:aa"} {}`, true},
		{"trailing garbage", `{"authority":"sha256:aa"} nope`, true},
		{"a truncated object", `{"authority":`, true},
		{"a type mismatch", `{"authority":7}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var head Head
			err := Decode([]byte(tc.data), &head)
			if (err != nil) != tc.wantErr {
				t.Errorf("Decode(%s) = %v, want error: %v", tc.data, err, tc.wantErr)
			}
		})
	}
}

// TestDecodeAllowsTrailingWhitespace keeps a stored object with a trailing
// newline readable; only another JSON value counts as trailing data.
func TestDecodeAllowsTrailingWhitespace(t *testing.T) {
	var head Head
	data := "{\"authority\":\"sha256:aa\"}\n"
	if err := Decode([]byte(data), &head); err != nil {
		t.Errorf("Decode(%q) = %v, want no error", data, err)
	}
}
