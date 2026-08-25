package measurements

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	d1 = "c1e0a7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009"
	d2 = "9f2c1a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003"
	r1 = "77df02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
	r2 = "3e90ac000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005"
)

func snpFile(entries string) string {
	return `{"schema_version":"1","tee":"sev-snp","measurements":[` + entries + `]}`
}

func tdxFile(entries string) string {
	return `{"schema_version":"1","tee":"tdx","measurements":[` + entries + `]}`
}

func TestParseValidSNP(t *testing.T) {
	set, err := Parse([]byte(snpFile(
		`{"name":"worker-smp2","measurement":"` + d1 + `"},` +
			`{"name":"worker-smp4","measurement":"` + d2 + `"}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.TEE != TEESNP {
		t.Errorf("TEE = %q, want %q", set.TEE, TEESNP)
	}
	if len(set.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(set.Entries))
	}
	if got := hex.EncodeToString(set.Entries[0].Digest); got != d1 {
		t.Errorf("digest = %s, want %s", got, d1)
	}
	if set.Entries[0].RTMRs != nil {
		t.Errorf("SNP entry carries RTMRs: %v", set.Entries[0].RTMRs)
	}
	if set.Empty() {
		t.Error("Empty() = true for a populated set")
	}
}

// An empty rtmr slot pins the register to all zeros; a null slot leaves it
// unchecked. The two must not collapse into each other.
func TestParseTDXRTMRSlots(t *testing.T) {
	set, err := Parse([]byte(tdxFile(
		`{"name":"worker","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `",null,""]}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := set.Entries[0].RTMRs
	if _, pinned := got[0]; pinned {
		t.Error("rtmr[0] pinned from a null slot")
	}
	if _, pinned := got[2]; pinned {
		t.Error("rtmr[2] pinned from a null slot")
	}
	if want, _ := hex.DecodeString(r1); !bytes.Equal(got[1], want) {
		t.Errorf("rtmr[1] = %x, want %s", got[1], r1)
	}
	if !bytes.Equal(got[3], make([]byte, DigestSize)) {
		t.Errorf("rtmr[3] = %x, want %d zero bytes", got[3], DigestSize)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"wrong schema version", `{"schema_version":"2","tee":"tdx","measurements":[{"name":"a","mrtd":"` + d1 + `"}]}`, "schema_version"},
		{"missing schema version", `{"tee":"tdx","measurements":[{"name":"a","mrtd":"` + d1 + `"}]}`, "schema_version"},
		{"unknown tee", `{"schema_version":"1","tee":"sev","measurements":[{"name":"a","mrtd":"` + d1 + `"}]}`, "tee"},
		{"empty measurements", `{"schema_version":"1","tee":"tdx","measurements":[]}`, "empty"},
		{"missing measurements", `{"schema_version":"1","tee":"tdx"}`, "empty"},
		{"unknown field", snpFile(`{"name":"a","measurement":"` + d1 + `","host_data":"ab"}`), "host_data"},
		{"unknown top-level field", `{"schema_version":"1","tee":"tdx","extra":1,"measurements":[{"name":"a","mrtd":"` + d1 + `"}]}`, "extra"},
		{"duplicate top-level key", `{"schema_version":"1","tee":"tdx","tee":"sev-snp","measurements":[{"name":"a","mrtd":"` + d1 + `"}]}`, "duplicate key"},
		{"duplicate key inside an entry", tdxFile(`{"name":"a","mrtd":"` + d1 + `","mrtd":"` + d2 + `"}`), "duplicate key"},
		{"uppercase hex", snpFile(`{"name":"a","measurement":"` + strings.ToUpper(d1) + `"}`), "lowercase"},
		{"short digest", snpFile(`{"name":"a","measurement":"c1e0a7"}`), "hex chars"},
		{"non-hex digest", snpFile(`{"name":"a","measurement":"` + strings.Repeat("z", 96) + `"}`), "not hex"},
		{"missing name", snpFile(`{"measurement":"` + d1 + `"}`), "name is required"},
		{"blank name", snpFile(`{"name":"  ","measurement":"` + d1 + `"}`), "name is required"},
		{"missing measurement", snpFile(`{"name":"a"}`), "measurement is required"},
		{"missing mrtd", tdxFile(`{"name":"a"}`), "mrtd is required"},
		{"snp entry with mrtd", snpFile(`{"name":"a","measurement":"` + d1 + `","mrtd":"` + d2 + `"}`), "tdx fields"},
		{"snp entry with rtmr", snpFile(`{"name":"a","measurement":"` + d1 + `","rtmr":[null,"` + r1 + `"]}`), "tdx fields"},
		{"tdx entry with measurement", tdxFile(`{"name":"a","mrtd":"` + d1 + `","measurement":"` + d2 + `"}`), "sev-snp field"},
		{"pinned rtmr0", tdxFile(`{"name":"a","mrtd":"` + d1 + `","rtmr":["` + r1 + `"]}`), "rtmr[0]"},
		{"zero-pinned rtmr0", tdxFile(`{"name":"a","mrtd":"` + d1 + `","rtmr":[""]}`), "rtmr[0]"},
		{"too many rtmrs", tdxFile(`{"name":"a","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `","` + r2 + `","` + r1 + `","` + r2 + `"]}`), "at most"},
		{"duplicate name", snpFile(`{"name":"a","measurement":"` + d1 + `"},{"name":"a","measurement":"` + d2 + `"}`), "duplicate name"},
		{"duplicate tuple", snpFile(`{"name":"a","measurement":"` + d1 + `"},{"name":"b","measurement":"` + d1 + `"}`), "same tuple"},
		{"not an object", `[]`, "decode"},
		{"trailing data", snpFile(`{"name":"a","measurement":"`+d1+`"}`) + `{}`, "trailing data"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil {
				t.Fatalf("Parse accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// Two entries differing only in RTMRs are distinct images, not a duplicate.
func TestParseAllowsSameMRTDDifferentRTMRs(t *testing.T) {
	if _, err := Parse([]byte(tdxFile(
		`{"name":"a","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `"]},` +
			`{"name":"b","mrtd":"` + d1 + `","rtmr":[null,"` + r2 + `"]}`))); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

// The flat flags enforced "digest in the list AND the one RTMR set". The
// converted entries must say exactly that.
func TestFromFlagsMatchesFlatSemantics(t *testing.T) {
	b1, _ := hex.DecodeString(d1)
	b2, _ := hex.DecodeString(d2)
	pins, _ := hex.DecodeString(r1)
	rtmrs := map[int][]byte{1: pins}

	set := FromFlags([][]byte{b1, b2}, rtmrs)
	if len(set.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(set.Entries))
	}
	for i, e := range set.Entries {
		if !bytes.Equal(e.RTMRs[1], pins) {
			t.Errorf("entry %d does not carry the shared RTMR pin", i)
		}
	}
	common, ok := set.CommonRTMRs()
	if !ok || !bytes.Equal(common[1], pins) {
		t.Errorf("CommonRTMRs = %v, %v; want the shared pin", common, ok)
	}
}

// --rtmrs without --measurements has no entry form; it stays on the flat
// path, so the converted set must report itself as pinning nothing rather
// than claiming a digest gate the operator never configured.
func TestFromFlagsRTMRsWithoutDigests(t *testing.T) {
	pins, _ := hex.DecodeString(r1)
	set := FromFlags(nil, map[int][]byte{1: pins})
	if len(set.Entries) != 0 {
		t.Errorf("got %d entries, want 0", len(set.Entries))
	}
	if !set.Empty() {
		t.Error("Empty() = false for a set with no entries")
	}
	if len(set.DigestSet()) != 0 {
		t.Error("DigestSet() is non-empty for a set with no entries")
	}
}

// Entries must not share one RTMR map: consumers assign to policy pins.
func TestFromFlagsEntriesOwnTheirRTMRs(t *testing.T) {
	b1, _ := hex.DecodeString(d1)
	b2, _ := hex.DecodeString(d2)
	pins, _ := hex.DecodeString(r1)
	set := FromFlags([][]byte{b1, b2}, map[int][]byte{1: pins})

	set.Entries[0].RTMRs[2] = make([]byte, DigestSize)
	if _, leaked := set.Entries[1].RTMRs[2]; leaked {
		t.Error("mutating one entry's RTMRs changed another's")
	}
}

func TestEmptySet(t *testing.T) {
	if !(ReferenceValues{}).Empty() {
		t.Error("zero ReferenceValues is not Empty()")
	}
	if !FromFlags(nil, nil).Empty() {
		t.Error("FromFlags(nil, nil) is not Empty()")
	}
}

// A gate that cannot express per-entry tuples must be able to tell that the
// entries disagree, rather than silently taking the first.
func TestCommonRTMRsDisagree(t *testing.T) {
	set, err := Parse([]byte(tdxFile(
		`{"name":"a","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `"]},` +
			`{"name":"b","mrtd":"` + d2 + `","rtmr":[null,"` + r2 + `"]}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := set.CommonRTMRs(); ok {
		t.Error("CommonRTMRs reported agreement across differing entries")
	}
}

func TestDigestAccessors(t *testing.T) {
	set, err := Parse([]byte(snpFile(
		`{"name":"a","measurement":"` + d1 + `"},{"name":"b","measurement":"` + d2 + `"}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := len(set.Digests()); got != 2 {
		t.Errorf("Digests() len = %d, want 2", got)
	}
	ds := set.DigestSet()
	if !ds[d1] || !ds[d2] {
		t.Errorf("DigestSet() = %v, want both digests", ds)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(snpFile(`{"name":"a","measurement":"` + d1 + `"}`))
	f.Add(tdxFile(`{"name":"a","mrtd":"` + d1 + `","rtmr":[null,"` + r1 + `","` + r2 + `",""]}`))
	f.Fuzz(func(t *testing.T, doc string) {
		set, err := Parse([]byte(doc))
		if err != nil {
			return
		}
		// Anything that parses must be usable as a policy without panicking
		// and must actually pin something.
		if set.Empty() {
			t.Fatalf("accepted a document that pins nothing: %q", doc)
		}
		for _, e := range set.Entries {
			if len(e.Digest) != DigestSize {
				t.Fatalf("accepted a %d-byte digest", len(e.Digest))
			}
			for idx, v := range e.RTMRs {
				if idx == 0 {
					t.Fatalf("accepted a pin on RTMR[0]")
				}
				if len(v) != DigestSize {
					t.Fatalf("accepted a %d-byte RTMR pin", len(v))
				}
			}
		}
		set.CommonRTMRs()
		set.DigestSet()
	})
}

// Format must refuse a set whose platform it cannot render, rather than
// emitting a document that would not load.
func TestFormatRejectsUnknownTEE(t *testing.T) {
	_, err := Format(ReferenceValues{TEE: "sev", Entries: []Entry{{Name: "a", Digest: make([]byte, DigestSize)}}})
	if err == nil {
		t.Fatal("formatted a set with an unknown tee")
	}
	if !strings.Contains(err.Error(), "tee") {
		t.Errorf("error %q does not name the field", err)
	}
}
