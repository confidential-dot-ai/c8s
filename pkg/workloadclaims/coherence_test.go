package workloadclaims

import (
	"errors"
	"strings"
	"testing"
)

const (
	cohDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cohDigestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// Equal sets pass regardless of ordering and duplicate entries: Containers is
// not deduplicated by contract (two containers may share an image), and the
// flat set's ordering carries no meaning.
func TestRequireContainersAcceptsEqualSets(t *testing.T) {
	r := SandboxDigestsResponse{
		Digests: []string{cohDigestB, cohDigestA},
		Containers: []SandboxContainer{
			{Digest: cohDigestA, Argv: []string{"/init"}},
			{Digest: cohDigestB, Argv: []string{"/main"}},
			{Digest: cohDigestA, Argv: []string{"/init"}}, // replica of the same image
		},
	}
	containers, err := r.RequireContainers()
	if err != nil {
		t.Fatalf("RequireContainers: %v", err)
	}
	if len(containers) != 3 {
		t.Fatalf("RequireContainers returned %d containers, want the 3 reported", len(containers))
	}
}

// Case differences in the hex are canonicalized before comparison, so an
// uppercase flat entry and a lowercase container entry are the same digest.
func TestRequireContainersCanonicalizesBeforeComparing(t *testing.T) {
	r := SandboxDigestsResponse{
		Digests:    []string{"sha256:" + strings.ToUpper(cohDigestA[len("sha256:"):])},
		Containers: []SandboxContainer{{Digest: cohDigestA}},
	}
	if _, err := r.RequireContainers(); err != nil {
		t.Fatalf("RequireContainers: %v", err)
	}
}

// A digest only in the flat set means a container the detail view hides —
// nothing could hold it to an argv policy. Refused.
func TestRequireContainersRejectsDigestOnlyInFlatSet(t *testing.T) {
	r := SandboxDigestsResponse{
		Digests:    []string{cohDigestA, cohDigestB},
		Containers: []SandboxContainer{{Digest: cohDigestA}},
	}
	if _, err := r.RequireContainers(); err == nil {
		t.Fatal("RequireContainers accepted a digest with no per-container detail")
	}
}

// A container only in the detail view means a digest the flat gate never saw.
// Refused.
func TestRequireContainersRejectsContainerOutsideFlatSet(t *testing.T) {
	r := SandboxDigestsResponse{
		Digests:    []string{cohDigestA},
		Containers: []SandboxContainer{{Digest: cohDigestA}, {Digest: cohDigestB}},
	}
	if _, err := r.RequireContainers(); err == nil {
		t.Fatal("RequireContainers accepted a container outside the digest set")
	}
}

// An empty flat set with per-container detail is the same divergence, not a
// special case.
func TestRequireContainersRejectsDetailWithEmptyFlatSet(t *testing.T) {
	r := SandboxDigestsResponse{
		Digests:    []string{},
		Containers: []SandboxContainer{{Digest: cohDigestA}},
	}
	if _, err := r.RequireContainers(); err == nil {
		t.Fatal("RequireContainers accepted containers the empty digest set never named")
	}
}

// Malformed digests on either side fail the whole answer rather than being
// excluded from the comparison — an entry that cannot be parsed cannot be
// declared consistent either.
func TestRequireContainersRejectsMalformedDigests(t *testing.T) {
	for name, r := range map[string]SandboxDigestsResponse{
		"flat": {
			Digests:    []string{"not-a-digest"},
			Containers: []SandboxContainer{{Digest: cohDigestA}},
		},
		"container": {
			Digests:    []string{cohDigestA},
			Containers: []SandboxContainer{{Digest: "sha256:short"}},
		},
		"empty container digest": {
			Digests:    []string{cohDigestA},
			Containers: []SandboxContainer{{Digest: ""}},
		},
	} {
		if _, err := r.RequireContainers(); err == nil {
			t.Errorf("%s: RequireContainers accepted a malformed digest", name)
		}
	}
}

// The legacy compatibility path is untouched: a digest-only inventory (one
// older than the Containers field) still reports ErrSandboxContainersUnsupported
// so callers degrade deliberately instead of failing on coherence.
func TestRequireContainersLegacyDigestOnlyStillUnsupported(t *testing.T) {
	r := SandboxDigestsResponse{Digests: []string{cohDigestA}}
	if _, err := r.RequireContainers(); !errors.Is(err, ErrSandboxContainersUnsupported) {
		t.Fatalf("RequireContainers = %v, want ErrSandboxContainersUnsupported", err)
	}
}
