package allowlist

import "testing"

// A document from a newer release must not freeze an older consumer's policy.
func TestServedParseIgnoresUnknownFields(t *testing.T) {
	doc := `{"schema":"` + Schema + `","workloads":{},"somethingNewer":{"x":1}}`
	if _, err := ParseServedJSON([]byte(doc)); err != nil {
		t.Fatalf("ParseServedJSON rejected an unknown field: %v", err)
	}
	if _, err := ParseJSON([]byte(doc)); err == nil {
		t.Error("ParseJSON accepted an unknown field in an operator-authored document")
	}
}
