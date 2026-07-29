package allowlist

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func matchTestDoc(t *testing.T) *Allowlist {
	t.Helper()
	floorD := "sha256:" + hexOf(0xf0)
	imgA := "sha256:" + hexOf(0xaa)
	imgB := "sha256:" + hexOf(0xbb)
	doc, err := ParseJSON(fmt.Appendf(nil, `{
		"schema": "c8s.allowlist/v1",
		"digests": {"%s": "floor/img"},
		"workloads": {
			"kimi-k3": {
				"containers": [{"digest": "%s", "command": {"policy": "exact", "argv": ["/serve"]}, "args": {"policy": "exact", "argv": ["--model", "kimi-k3"]}, "paths": {"policy": "deny"}}]
			},
			"sglang-dev": {
				"containers": [{"digest": "%s", "command": {"policy": "exact", "argv": ["/serve"]}, "args": {"policy": "exact", "argv": ["--model", "qwen3-0.6b"]}, "paths": {"policy": "deny"}}]
			},
			"other": {
				"containers": [{"digest": "%s", "command": {"policy": "any"}, "args": {"policy": "any"}, "paths": {"policy": "deny"}}]
			}
		}
	}`, floorD, imgA, imgA, imgB))
	if err != nil {
		t.Fatalf("parse test allowlist: %v", err)
	}
	return doc
}

func hexOf(b byte) string {
	return hex.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func TestMatchingWorkloadEntries_SharedDigestNamesBoth(t *testing.T) {
	doc := matchTestDoc(t)
	imgA := "sha256:" + hexOf(0xaa)

	names := doc.MatchingWorkloadEntries(nil, []string{imgA})
	if len(names) != 2 || names[0] != "kimi-k3" || names[1] != "sglang-dev" {
		t.Fatalf("same-digest entries must BOTH match, sorted; got %v", names)
	}
}

func TestMatchingWorkloadEntries_UniqueDigestNamesOne(t *testing.T) {
	doc := matchTestDoc(t)
	imgB := "sha256:" + hexOf(0xbb)

	names := doc.MatchingWorkloadEntries(nil, []string{imgB})
	if len(names) != 1 || names[0] != "other" {
		t.Fatalf("want [other], got %v", names)
	}
}

func TestMatchingWorkloadEntries_FloorExcludedBothSides(t *testing.T) {
	doc := matchTestDoc(t)
	floorD := "sha256:" + hexOf(0xf0)
	imgB := "sha256:" + hexOf(0xbb)

	// The injected floor container must not change the match.
	names := doc.MatchingWorkloadEntries([]string{floorD}, []string{imgB, floorD})
	if len(names) != 1 || names[0] != "other" {
		t.Fatalf("floor digests must be excluded; got %v", names)
	}
	// Floor-only reduces to nothing to match.
	if names := doc.MatchingWorkloadEntries([]string{floorD}, []string{floorD}); names != nil {
		t.Fatalf("floor-only pod must match no entry, got %v", names)
	}
}

func TestMatchingWorkloadEntries_NoMatch(t *testing.T) {
	doc := matchTestDoc(t)
	stranger := "sha256:" + hexOf(0xcc)
	if names := doc.MatchingWorkloadEntries(nil, []string{stranger}); names != nil {
		t.Fatalf("unknown digest must match nothing, got %v", names)
	}
	// Superset of an entry is not that entry.
	imgA := "sha256:" + hexOf(0xaa)
	imgB := "sha256:" + hexOf(0xbb)
	if names := doc.MatchingWorkloadEntries(nil, []string{imgA, imgB}); names != nil {
		t.Fatalf("digest superset must match nothing, got %v", names)
	}
}

func TestWorkloadEntriesDigest_DeterministicAndArgvSensitive(t *testing.T) {
	doc := matchTestDoc(t)

	d1, err := doc.WorkloadEntriesDigest([]string{"kimi-k3", "sglang-dev"})
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	d2, err := doc.WorkloadEntriesDigest([]string{"kimi-k3", "sglang-dev"})
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if !bytes.Equal(d1, d2) {
		t.Fatal("entries digest must be deterministic")
	}

	// The two entries differ ONLY in argv, and their single-entry digests must
	// differ — that is the property that makes the stamp identity-bearing.
	dk, err := doc.WorkloadEntriesDigest([]string{"kimi-k3"})
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	ds, err := doc.WorkloadEntriesDigest([]string{"sglang-dev"})
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if bytes.Equal(dk, ds) {
		t.Fatal("entries differing only in argv must produce different digests")
	}

	// A reparsed copy of the same document recomputes the same digest — the
	// verifier-side property.
	canonical, err := doc.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	reparsed, err := ParseJSON(canonical)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	dr, err := reparsed.WorkloadEntriesDigest([]string{"kimi-k3", "sglang-dev"})
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if !bytes.Equal(d1, dr) {
		t.Fatal("verifier recomputation from canonical bytes must reproduce the digest")
	}
}

func TestWorkloadEntriesDigest_UnknownNameFails(t *testing.T) {
	doc := matchTestDoc(t)
	if _, err := doc.WorkloadEntriesDigest([]string{"nope"}); err == nil {
		t.Fatal("unknown entry name must fail, not digest an empty entry")
	}
	if _, err := doc.WorkloadEntriesDigest(nil); err == nil {
		t.Fatal("empty name list must fail")
	}
}
