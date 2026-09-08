package admissionhistory

import (
	"reflect"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestHistoryRetainsDistinctAdmissions(t *testing.T) {
	var h History
	digests, containers, err := h.Snapshot()
	if err != nil || digests == nil || containers == nil || len(digests)+len(containers) != 0 {
		t.Fatalf("empty history = %v, %v, %v", digests, containers, err)
	}
	h.Record("one", "sha256:b", []string{"run", "z"})
	h.Record("two", "sha256:a", nil)
	h.Record("three", "sha256:a", []string{})
	h.Record("replica", "sha256:b", []string{"run", "z"})
	h.Record("one", "sha256:b", []string{"run", "a"})
	h.Record("one", "sha256:a", []string{""})
	digests, containers, err = h.Snapshot()
	want := []workloadclaims.SandboxContainer{
		{Digest: "sha256:a", Argv: []string{}},
		{Digest: "sha256:a", Argv: []string{""}},
		{Digest: "sha256:b", Argv: []string{"run", "a"}},
		{Digest: "sha256:b", Argv: []string{"run", "z"}},
	}
	if err != nil || !reflect.DeepEqual(digests, []string{"sha256:a", "sha256:b"}) || !reflect.DeepEqual(containers, want) {
		t.Fatalf("snapshot = %v, %#v, %v", digests, containers, err)
	}
}

func TestHistoryResolutionIsPerContainer(t *testing.T) {
	var h History
	h.Record("known", "sha256:a", nil)
	h.Record("first", "", nil)
	h.Record("second", "", nil)
	assertUnresolved := func() {
		t.Helper()
		digests, containers, err := h.Snapshot()
		if err == nil || digests != nil || containers != nil {
			t.Fatalf("unresolved history returned a partial answer: %v, %v, %v", digests, containers, err)
		}
	}
	assertUnresolved()
	h.Record("different", "sha256:b", nil)
	assertUnresolved()
	h.Record("first", "sha256:b", nil)
	assertUnresolved()
	h.Record("second", "sha256:b", nil)
	if digests, containers, err := h.Snapshot(); err != nil || len(digests) != 2 || len(containers) != 2 {
		t.Fatalf("resolved snapshot = %v, %v, %v", digests, containers, err)
	}
	h.Record("known", "", nil)
	assertUnresolved()
	h.Record("known", "sha256:c", nil)
	if digests, _, err := h.Snapshot(); err != nil || len(digests) != 3 {
		t.Fatalf("resolution lost an earlier admission: %v, %v", digests, err)
	}
}

func TestHistoryOwnsArgumentsAndSnapshots(t *testing.T) {
	var h History
	argv := []string{"run", "original"}
	h.Record("one", "sha256:a", argv)
	argv[1] = "changed input"
	digests, containers, err := h.Snapshot()
	if err != nil || len(containers) != 1 || containers[0].Argv[1] != "original" {
		t.Fatalf("input mutation changed history: %v, %v", containers, err)
	}
	digests[0] = "changed digest"
	containers[0].Digest = "changed container"
	containers[0].Argv[1] = "changed output"
	digests, containers, err = h.Snapshot()
	if err != nil || !reflect.DeepEqual(digests, []string{"sha256:a"}) || len(containers) != 1 || containers[0].Digest != "sha256:a" || containers[0].Argv[1] != "original" {
		t.Fatalf("snapshot mutation changed history: %v, %v, %v", digests, containers, err)
	}
}
