package measurements

import (
	"bytes"
	"fmt"

	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// StaticEntryName names the one image a static-allowlist cluster accepts.
const StaticEntryName = "static-allowlist"

// StaticReferenceValues builds the reference values a static-allowlist cluster
// pins: one TDX entry carrying the image tuple from the build manifest and the
// RTMR[3] a node sealed to the policy bundle reports. Every register is
// pinned, so a pod on an unsealed node of the same image, or on a node sealed
// to another bundle, matches nothing.
func StaticReferenceValues(pins runtimemeasure.ImagePins, rtmr3 [runtimemeasure.Size]byte) ReferenceValues {
	return ReferenceValues{TEE: TEETDX, Entries: []Entry{{
		Name:   StaticEntryName,
		Digest: bytes.Clone(pins.MRTD[:]),
		RTMRs: map[int][]byte{
			1: bytes.Clone(pins.RTMR1[:]),
			2: bytes.Clone(pins.RTMR2[:]),
			3: bytes.Clone(rtmr3[:]),
		},
	}}}
}

// StaticEntry returns the entry a static-allowlist consumer enforces: the set
// must declare TDX and hold exactly one entry pinning RTMR[1], RTMR[2] and
// RTMR[3]. Anything looser would let a second image, or an unsealed node of
// the same image, through the static gate.
func (s ReferenceValues) StaticEntry() (Entry, error) {
	if s.TEE != TEETDX {
		return Entry{}, fmt.Errorf("static allowlist needs tee %q, config declares %q", TEETDX, s.TEE)
	}
	if len(s.Entries) != 1 {
		return Entry{}, fmt.Errorf("static allowlist needs exactly one measurements entry, config has %d", len(s.Entries))
	}
	e := s.Entries[0]
	for _, idx := range []int{1, 2, 3} {
		if len(e.RTMRs[idx]) != DigestSize {
			return Entry{}, fmt.Errorf("static allowlist entry %q must pin RTMR[%d]", e.Name, idx)
		}
	}
	return e, nil
}
