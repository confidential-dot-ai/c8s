package allowlist

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	dApp     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dSidecar = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dInit    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	dOther   = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

func dig(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("ParseDigest(%q): %v", s, err)
	}
	return d
}

// exactly builds a container pinned to one digest and argv.
func exactly(t *testing.T, digest string, argv ...string) Container {
	t.Helper()
	c := Container{Digest: dig(t, digest), Command: ArgvPolicy{Policy: PolicyAny}, Args: ArgvPolicy{Policy: PolicyAny}}
	if len(argv) > 0 {
		c.Command = ArgvPolicy{Policy: PolicyExact, Argv: argv}
		c.Args = ArgvPolicy{Policy: PolicyDeny}
	}
	return c
}

func run(digest string, argv ...string) RunningContainer {
	return RunningContainer{Digest: digest, Argv: argv}
}

func TestMatchWorkload(t *testing.T) {
	al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{
		"api": {
			InitContainers: []Container{exactly(t, dInit, "/migrate")},
			Containers:     []Container{exactly(t, dApp, "/serve"), exactly(t, dSidecar, "/proxy")},
		},
	}}

	for _, tc := range []struct {
		name    string
		running []RunningContainer
		want    string
		wantErr error
	}{
		{
			name:    "every main present",
			running: []RunningContainer{run(dApp, "/serve"), run(dSidecar, "/proxy")},
			want:    "api",
		},
		{
			// A declared init container that has not been reaped is not foreign.
			name:    "lingering init is admitted",
			running: []RunningContainer{run(dApp, "/serve"), run(dSidecar, "/proxy"), run(dInit, "/migrate")},
			want:    "api",
		},
		{
			name:    "missing main is refused",
			running: []RunningContainer{run(dApp, "/serve")},
			wantErr: ErrNoMatch,
		},
		{
			// The whole point: an extra image, even one that has since stopped,
			// means this pod is not the entry.
			name:    "foreign container is refused",
			running: []RunningContainer{run(dApp, "/serve"), run(dSidecar, "/proxy"), run(dOther, "/sh")},
			wantErr: ErrNoMatch,
		},
		{
			name:    "wrong argv on a declared digest is refused",
			running: []RunningContainer{run(dApp, "/bin/sh", "-c", "cat /run/secrets/*"), run(dSidecar, "/proxy")},
			wantErr: ErrNoMatch,
		},
		{
			name:    "empty running set is refused",
			running: nil,
			wantErr: ErrNoMatch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, _, err := al.MatchWorkload(tc.running)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			if name != tc.want {
				t.Fatalf("matched %q, want %q", name, tc.want)
			}
		})
	}
}

// Two entries that the running set cannot tell apart are refused rather than
// resolved by iteration order.
func TestMatchWorkloadAmbiguous(t *testing.T) {
	al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{
		"a": {Containers: []Container{exactly(t, dApp, "/serve")}},
		"b": {Containers: []Container{exactly(t, dApp, "/serve")}},
	}}
	if _, _, err := al.MatchWorkload([]RunningContainer{run(dApp, "/serve")}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("err = %v, want ErrAmbiguous", err)
	}
}

// Two entries sharing a digest but pinning different argv are distinguishable
// here, even though Index admits either argv for that digest (a union across
// entries). That difference is the reason argv is matched per entry.
func TestMatchWorkloadDistinguishesByArgv(t *testing.T) {
	al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{
		"model-a": {Containers: []Container{exactly(t, dApp, "/serve", "--model", "a")}},
		"model-b": {Containers: []Container{exactly(t, dApp, "/serve", "--model", "b")}},
	}}
	name, _, err := al.MatchWorkload([]RunningContainer{run(dApp, "/serve", "--model", "b")})
	if err != nil || name != "model-b" {
		t.Fatalf("matched %q (%v), want model-b", name, err)
	}

	idx := al.BuildIndex()
	if !idx.AdmitsContainer(dApp, []string{"/serve", "--model", "a"}) {
		t.Fatal("precondition: Index should admit either argv for the shared digest")
	}
}

// A digest declared with an "any" command in one entry does not let that entry
// swallow a pod whose real workload is another entry.
func TestMatchWorkloadWideEntryDoesNotStealNarrowPod(t *testing.T) {
	al := &Allowlist{Schema: Schema, Workloads: map[string]Workload{
		"prod":  {Containers: []Container{exactly(t, dApp, "/serve"), exactly(t, dSidecar, "/proxy")}},
		"debug": {Containers: []Container{exactly(t, dApp)}}, // command: any
	}}
	// The sidecar is foreign to "debug", so only "prod" matches.
	name, _, err := al.MatchWorkload([]RunningContainer{run(dApp, "/serve"), run(dSidecar, "/proxy")})
	if err != nil || name != "prod" {
		t.Fatalf("matched %q (%v), want prod", name, err)
	}
}

func TestMatchWorkloadEmptyAllowlist(t *testing.T) {
	al := &Allowlist{Schema: Schema}
	if _, _, err := al.MatchWorkload([]RunningContainer{run(dApp, "/serve")}); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v, want ErrNoMatch", err)
	}
}

func TestDigestConstantsAreWellFormed(t *testing.T) {
	for _, d := range []string{dApp, dSidecar, dInit, dOther} {
		if !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
			t.Fatalf("malformed test digest %q", d)
		}
	}
}

// matchEntriesDoc is a parsed allowlist for MatchingWorkloadEntries tests: a
// floor entry, two workload entries sharing an image and differing only in
// argv, and a third entry on its own image.
func matchEntriesDoc(t *testing.T) *Allowlist {
	t.Helper()
	floorD := "sha256:" + hexOf(0xf0)
	imgA := "sha256:" + hexOf(0xaa)
	imgB := "sha256:" + hexOf(0xbb)
	doc, err := ParseJSON(fmt.Appendf(nil, `{
		"schema": "c8s.allowlist/v1",
		"digests": {"%s": "floor/img"},
		"workloads": {
			"kimi-k3": {
				"containers": [{"digest": "%s", "command": {"policy": "exact", "argv": ["/serve"]}, "args": {"policy": "exact", "argv": ["--model", "kimi-k3"]}}]
			},
			"sglang-dev": {
				"containers": [{"digest": "%s", "command": {"policy": "exact", "argv": ["/serve"]}, "args": {"policy": "exact", "argv": ["--model", "qwen3-0.6b"]}}]
			},
			"other": {
				"containers": [{"digest": "%s", "command": {"policy": "any"}, "args": {"policy": "any"}}]
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

// Two entries share the image; the observed argv satisfies exactly one of
// them, so argv discrimination resolves the ambiguity the digests cannot.
func TestMatchingWorkloadEntries_ArgvDisambiguates(t *testing.T) {
	doc := matchEntriesDoc(t)
	imgA := "sha256:" + hexOf(0xaa)

	names := doc.MatchingWorkloadEntries([]RunningContainer{run(imgA, "/serve", "--model", "kimi-k3")})
	if len(names) != 1 || names[0] != "kimi-k3" {
		t.Fatalf("argv must resolve the shared-digest entries to [kimi-k3], got %v", names)
	}
}

// An argv both entries admit keeps both names, sorted — the honest ambiguity.
func TestMatchingWorkloadEntries_SharedAdmissionNamesBoth(t *testing.T) {
	imgA := "sha256:" + hexOf(0xaa)
	doc, err := ParseJSON(fmt.Appendf(nil, `{
		"schema": "c8s.allowlist/v1",
		"workloads": {
			"kimi-k3":    {"containers": [{"digest": "%s", "command": {"policy": "any"}, "args": {"policy": "any"}}]},
			"sglang-dev": {"containers": [{"digest": "%s", "command": {"policy": "any"}, "args": {"policy": "any"}}]}
		}
	}`, imgA, imgA))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	names := doc.MatchingWorkloadEntries([]RunningContainer{run(imgA, "--model", "kimi-k3")})
	if len(names) != 2 || names[0] != "kimi-k3" || names[1] != "sglang-dev" {
		t.Fatalf("entries that both admit the argv must BOTH match, sorted; got %v", names)
	}
}

func TestMatchingWorkloadEntries_FloorExcluded(t *testing.T) {
	doc := matchEntriesDoc(t)
	floorD := "sha256:" + hexOf(0xf0)
	imgB := "sha256:" + hexOf(0xbb)

	// The injected floor container must not change the match — even though no
	// entry declares it.
	names := doc.MatchingWorkloadEntries([]RunningContainer{run(floorD, "c8s-cert"), run(imgB, "whatever")})
	if len(names) != 1 || names[0] != "other" {
		t.Fatalf("floor digests must be excluded; got %v", names)
	}
	// Floor-only reduces to nothing to match.
	floorOnly := []RunningContainer{run(floorD, "c8s-cert")}
	if names := doc.MatchingWorkloadEntries(floorOnly); names != nil {
		t.Fatalf("floor-only pod must match no entry, got %v", names)
	}
	if doc.HasNonFloor(floorOnly) {
		t.Fatal("HasNonFloor = true for a floor-only pod")
	}
	if !doc.HasNonFloor([]RunningContainer{run(imgB)}) {
		t.Fatal("HasNonFloor = false for a workload container")
	}
}

func TestMatchingWorkloadEntries_NoMatch(t *testing.T) {
	doc := matchEntriesDoc(t)
	stranger := "sha256:" + hexOf(0xcc)
	if names := doc.MatchingWorkloadEntries([]RunningContainer{run(stranger, "sh")}); names != nil {
		t.Fatalf("unknown digest must match nothing, got %v", names)
	}
	// An off-policy argv on an admitted digest matches nothing either.
	imgA := "sha256:" + hexOf(0xaa)
	if names := doc.MatchingWorkloadEntries([]RunningContainer{run(imgA, "/serve", "--model", "exfiltrator")}); names != nil {
		t.Fatalf("off-policy argv must match nothing, got %v", names)
	}
	// A set spanning two entries is consistent with neither.
	imgB := "sha256:" + hexOf(0xbb)
	if names := doc.MatchingWorkloadEntries([]RunningContainer{
		run(imgA, "/serve", "--model", "kimi-k3"),
		run(imgB, "anything"),
	}); names != nil {
		t.Fatalf("containers spanning two entries must match nothing, got %v", names)
	}
}

// Unlike MatchWorkload, a running subset of an entry still matches: issuance
// happens mid-lifecycle, before every declared main container is up.
func TestMatchingWorkloadEntries_SubsetOfEntryMatches(t *testing.T) {
	imgA := "sha256:" + hexOf(0xaa)
	imgB := "sha256:" + hexOf(0xbb)
	doc, err := ParseJSON(fmt.Appendf(nil, `{
		"schema": "c8s.allowlist/v1",
		"workloads": {
			"web": {"containers": [
				{"digest": "%s", "command": {"policy": "any"}, "args": {"policy": "any"}},
				{"digest": "%s", "command": {"policy": "any"}, "args": {"policy": "any"}}
			]}
		}
	}`, imgA, imgB))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if names := doc.MatchingWorkloadEntries([]RunningContainer{run(imgA, "serve")}); len(names) != 1 || names[0] != "web" {
		t.Fatalf("a running subset of the entry must still match, got %v", names)
	}
}

func TestWorkloadEntriesDigest_DeterministicAndArgvSensitive(t *testing.T) {
	doc := matchEntriesDoc(t)

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
	doc := matchEntriesDoc(t)
	if _, err := doc.WorkloadEntriesDigest([]string{"nope"}); err == nil {
		t.Fatal("unknown entry name must fail, not digest an empty entry")
	}
	if _, err := doc.WorkloadEntriesDigest(nil); err == nil {
		t.Fatal("empty name list must fail")
	}
}
