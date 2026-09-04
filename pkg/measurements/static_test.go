package measurements

import (
	"bytes"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

func staticFixture() (runtimemeasure.ImagePins, [runtimemeasure.Size]byte) {
	var pins runtimemeasure.ImagePins
	var rtmr3 [runtimemeasure.Size]byte
	for i := range runtimemeasure.Size {
		pins.MRTD[i], pins.RTMR1[i], pins.RTMR2[i], rtmr3[i] = 0xa1, 0xb2, 0xc3, 0xd4
	}
	return pins, rtmr3
}

// The static entry must survive the file format: what install writes is what
// CDS loads, register for register.
func TestStaticReferenceValuesRoundTrip(t *testing.T) {
	pins, rtmr3 := staticFixture()
	set := StaticReferenceValues(pins, rtmr3)

	doc, err := Format(set)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	parsed, err := Parse(doc)
	if err != nil {
		t.Fatalf("Parse(Format(static)) = %v, want nil\n%s", err, doc)
	}
	entry, err := parsed.StaticEntry()
	if err != nil {
		t.Fatalf("StaticEntry() = %v, want nil", err)
	}
	if entry.Name != StaticEntryName {
		t.Errorf("Name = %q, want %q", entry.Name, StaticEntryName)
	}
	if !bytes.Equal(entry.Digest, pins.MRTD[:]) {
		t.Errorf("Digest = %x, want MRTD %x", entry.Digest, pins.MRTD)
	}
	for idx, want := range map[int][]byte{1: pins.RTMR1[:], 2: pins.RTMR2[:], 3: rtmr3[:]} {
		if !bytes.Equal(entry.RTMRs[idx], want) {
			t.Errorf("RTMRs[%d] = %x, want %x", idx, entry.RTMRs[idx], want)
		}
	}
	if _, ok := entry.RTMRs[0]; ok {
		t.Error("RTMRs[0] pinned; it varies with the VM shape and must stay unpinned")
	}
}

func TestStaticEntryRejectsLooserSets(t *testing.T) {
	pins, rtmr3 := staticFixture()
	complete := StaticReferenceValues(pins, rtmr3)
	without := func(idx int) ReferenceValues {
		s := StaticReferenceValues(pins, rtmr3)
		delete(s.Entries[0].RTMRs, idx)
		return s
	}
	for _, tc := range []struct {
		name string
		set  ReferenceValues
		want string
	}{
		{"snp", ReferenceValues{TEE: TEESNP, Entries: complete.Entries}, `needs tee "tdx"`},
		{"empty", ReferenceValues{TEE: TEETDX}, "exactly one measurements entry"},
		{"two entries", ReferenceValues{TEE: TEETDX, Entries: append(complete.Entries, complete.Entries[0])}, "exactly one measurements entry"},
		{"no rtmr1", without(1), "must pin RTMR[1]"},
		{"no rtmr2", without(2), "must pin RTMR[2]"},
		{"no rtmr3", without(3), "must pin RTMR[3]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.set.StaticEntry()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("StaticEntry(%s) = %v, want error containing %q", tc.name, err, tc.want)
			}
		})
	}
}
