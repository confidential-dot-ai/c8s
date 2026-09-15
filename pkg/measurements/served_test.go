package measurements

import (
	"crypto/elliptic"
	"encoding/hex"
	"strings"
	"testing"
)

// A verifier must be able to read the policy a component reports as enforced,
// including the empty set an unpinned component publishes.
func TestServeAndParseServedRoundTrip(t *testing.T) {
	empty, err := Format(ReferenceValues{TEE: TEESNP})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseServed(empty)
	if err != nil {
		t.Fatalf("ParseServed(empty): %v", err)
	}
	if got.TEE != TEESNP || !got.Empty() {
		t.Fatalf("got %+v, want empty %s set", got, TEESNP)
	}
	if _, err := Parse(empty); err == nil {
		t.Fatal("the strict parser accepted an empty enforced set")
	}

	key := operatorPEM(t, elliptic.P256())
	pinned, err := Format(ReferenceValues{TEE: TEETDX, Entries: []Entry{{
		Name: "server", Digest: mustHex(t, d1), RTMRs: map[int][]byte{1: mustHex(t, r1)}, OperatorKey: key,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	got, err = ParseServed(pinned)
	if err != nil {
		t.Fatalf("ParseServed(pinned): %v", err)
	}
	if len(got.Entries) != 1 || string(got.Entries[0].OperatorKey) != string(key) {
		t.Fatalf("pinned entry lost its operator: %+v", got.Entries)
	}
}

func TestParseServedRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":      `{`,
		"wrong schema":  `{"schema_version":"2","tee":"tdx","measurements":[]}`,
		"unknown tee":   `{"schema_version":"1","tee":"sgx","measurements":[]}`,
		"bad entry":     snpFile(`{"name":"a","measurement":"short"}`),
		"duplicate key": snpFile(`{"name":"a","measurement":"` + d1 + `","measurement":"` + d2 + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseServed([]byte(doc)); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

func TestDiffOrdersByTuple(t *testing.T) {
	entry := func(digest string, key []byte) Entry {
		return Entry{Name: digest[:4], Digest: mustHex(t, digest), OperatorKey: key}
	}
	key := operatorPEM(t, elliptic.P256())
	want := ReferenceValues{TEE: TEESNP, Entries: []Entry{entry(d1, nil), entry(d2, nil), entry(d1, key)}}
	got := ReferenceValues{TEE: TEESNP, Entries: []Entry{entry(d2, nil), entry(d2, key), entry(r1, nil)}}
	missing, extra := Diff(want, got)
	if len(missing) != 2 || len(extra) != 2 {
		t.Fatalf("missing %d extra %d", len(missing), len(extra))
	}
	// d1 without an operator sorts before d1 with one; r1 (3e90…) before d2 (9f2c…).
	if hex.EncodeToString(missing[0].Digest) != d1 || len(missing[0].OperatorKey) != 0 || len(missing[1].OperatorKey) == 0 {
		t.Errorf("missing order: %v", missing)
	}
	if hex.EncodeToString(extra[0].Digest) != r1 || hex.EncodeToString(extra[1].Digest) != d2 {
		t.Errorf("extra order: %v", extra)
	}
	if m, e := Diff(want, want); len(m) != 0 || len(e) != 0 {
		t.Error("identical sets differ")
	}
}

func TestFormatEmptySetRendersAnEmptyList(t *testing.T) {
	data, err := Format(ReferenceValues{TEE: TEETDX})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"measurements": []`) {
		t.Errorf("empty set rendered as %s", data)
	}
	// Format is a serializer; the strict parser is the schema check, so a
	// malformed entry survives formatting only to be refused on the way back.
	data, err = Format(ReferenceValues{TEE: TEESNP, Entries: []Entry{{Name: "a", Digest: []byte("short")}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err == nil {
		t.Error("strict parser accepted a formatted short digest")
	}
}

func TestDuplicateKeyScannerReportsInvalidJSON(t *testing.T) {
	for name, doc := range map[string]string{
		"truncated object": `{"a":1,`,
		"truncated value":  `{"a":`,
		"truncated entry":  `{"schema_version":"1","tee":"tdx","measurements":[{"name":`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
	if key, err := duplicateKey([]byte(`[1,2]`)); err != nil || key != "" {
		t.Errorf("array: %q, %v", key, err)
	}
	if key, err := duplicateKey(nil); err != nil || key != "" {
		t.Errorf("empty: %q, %v", key, err)
	}
	if _, err := Parse([]byte(snpFile(`{"name":"a","measurement":"` + d1 + `","operator_key":42}`))); err == nil || !strings.Contains(err.Error(), "operator_key") {
		t.Errorf("non-string operator key: %v", err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
