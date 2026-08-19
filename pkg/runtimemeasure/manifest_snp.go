package runtimemeasure

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// SNPImagePins is the complete SEV-SNP measurement identity of one guest
// image: the set of launch digests the image can legitimately produce, keyed
// by vCPU count.
//
// Unlike TDX's single MRTD, an SNP launch measurement covers the initial vCPU
// state, so ONE image has one digest per SMP count — which is why the build
// ships a per-SMP IGVM (guest-smp2.igvm, guest-smp4.igvm, …) and publishes a
// digest for each. All entries come from one provenanced build manifest
// describing one image, so pinning the set is as tight as pinning a scalar:
// every member attests the same rootfs, differing only in how many vCPUs it
// was launched with.
type SNPImagePins struct {
	// BySMP maps vCPU count to that variant's launch digest.
	BySMP map[int][Size]byte
}

// Digests returns the pinned launch digests in ascending SMP order, for
// verifiers that accept any variant of the pinned image.
func (p SNPImagePins) Digests() [][Size]byte {
	smps := make([]int, 0, len(p.BySMP))
	for smp := range p.BySMP {
		smps = append(smps, smp)
	}
	sort.Ints(smps)
	out := make([][Size]byte, 0, len(smps))
	for _, smp := range smps {
		out = append(out, p.BySMP[smp])
	}
	return out
}

// Has reports whether digest is one of the pinned variants.
func (p SNPImagePins) Has(digest [Size]byte) bool {
	for _, want := range p.BySMP {
		if want == digest {
			return true
		}
	}
	return false
}

// snpImageManifest is the JSON subset LoadSNPImageManifest reads. Extra
// fields are allowed (build manifests carry plenty); snp_variants is not
// optional.
type snpImageManifest struct {
	SNPVariants []struct {
		SMP         int `json:"smp"`
		Measurement struct {
			SNPLaunchDigest string `json:"snp_launch_digest"`
			Algorithm       string `json:"algorithm"`
		} `json:"measurement"`
	} `json:"snp_variants"`
}

// LoadSNPImageManifest loads an SEV-SNP image pin — the per-SMP launch-digest
// set — from one provenanced build-artifact manifest. Every variant must
// carry a positive smp, a sha384 algorithm, and a digest of exactly 96
// lowercase hex chars; a malformed or duplicate variant fails the whole load,
// so a policy can never pin part of an image or a value other than the one it
// reads. A TDX manifest (mrtd/rtmr1/rtmr2) or a generic artifact-hash
// manifest.json carries no snp_variants and is rejected by the same rule.
func LoadSNPImageManifest(path string) (SNPImagePins, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SNPImagePins{}, fmt.Errorf("read image manifest: %w", err)
	}
	var m snpImageManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return SNPImagePins{}, fmt.Errorf("image manifest %s is not a JSON object: %w", path, err)
	}
	if len(m.SNPVariants) == 0 {
		return SNPImagePins{}, fmt.Errorf(
			"image manifest %s: no %q — an SNP image pin is the per-SMP launch-digest set from one provenanced build-artifact manifest; a TDX tuple or a generic artifact-hash manifest.json is not it",
			path, "snp_variants")
	}
	pins := SNPImagePins{BySMP: make(map[int][Size]byte, len(m.SNPVariants))}
	for i, v := range m.SNPVariants {
		if v.SMP <= 0 {
			return SNPImagePins{}, fmt.Errorf("image manifest %s: snp_variants[%d] has smp %d, want a positive vCPU count", path, i, v.SMP)
		}
		if _, dup := pins.BySMP[v.SMP]; dup {
			// Two digests for one SMP means the manifest describes two
			// launches; pinning either would be a guess.
			return SNPImagePins{}, fmt.Errorf("image manifest %s: duplicate snp_variants entry for smp %d", path, v.SMP)
		}
		// The launch measurement is SHA-384 (Size). The algorithm must be
		// named and must be sha384: an absent field would let a manifest
		// whose digest means something else load as if it were comparable,
		// and the TDX loader's posture is that an incomplete pin fails the
		// whole load rather than being guessed at.
		if v.Measurement.Algorithm != "sha384" {
			return SNPImagePins{}, fmt.Errorf("image manifest %s: snp_variants[smp=%d] algorithm %q, want sha384", path, v.SMP, v.Measurement.Algorithm)
		}
		var digest [Size]byte
		if v.Measurement.SNPLaunchDigest == "" {
			return SNPImagePins{}, fmt.Errorf("image manifest %s: snp_variants[smp=%d] has no snp_launch_digest", path, v.SMP)
		}
		if err := decodeRegister(v.Measurement.SNPLaunchDigest, &digest); err != nil {
			return SNPImagePins{}, fmt.Errorf("image manifest %s: snp_variants[smp=%d] snp_launch_digest %w", path, v.SMP, err)
		}
		pins.BySMP[v.SMP] = digest
	}
	return pins, nil
}
