package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExemptSnapshot_AdmitsIsNamespaceScoped(t *testing.T) {
	s := newExemptSnapshot([]string{"kube-system"})
	s.add("kube-system", pushDigestA)

	if !s.admits("kube-system", pushDigestA) {
		t.Error("a captured digest must admit in its own namespace")
	}
	if s.admits("default", pushDigestA) {
		t.Error("a digest captured in kube-system must not admit in another namespace")
	}
	if s.admits("kube-system", pushDigestB) {
		t.Error("an uncaptured digest must not admit")
	}
}

func TestExemptSnapshot_AddIgnoresBlankAndDedupes(t *testing.T) {
	s := newExemptSnapshot([]string{"kube-system"})
	s.add("kube-system", "")
	s.add("kube-system", pushDigestA)
	s.add("kube-system", pushDigestA)

	if s.count() != 1 {
		t.Fatalf("count = %d, want 1 (blank dropped, duplicate folded)", s.count())
	}
	if got := s.Digests["kube-system"]; len(got) != 1 || got[0] != pushDigestA {
		t.Fatalf("Digests[kube-system] = %v, want [%s]", got, pushDigestA)
	}
}

func TestExemptSnapshot_NilAdmitsNothing(t *testing.T) {
	var s *exemptSnapshot
	if s.admits("kube-system", pushDigestA) {
		t.Error("a nil snapshot must admit nothing")
	}
	if !s.empty() {
		t.Error("a nil snapshot is empty")
	}
}

func TestExemptSnapshot_PersistLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exempt-snapshot.json")
	s := newExemptSnapshot([]string{"kube-system", "gmp-system"})
	s.add("kube-system", pushDigestA)
	s.add("kube-system", pushDigestB)
	s.add("gmp-system", pushDigestC)
	if err := s.persist(path); err != nil {
		t.Fatalf("persist: %v", err)
	}

	loaded, err := loadExemptSnapshot(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded == nil {
		t.Fatal("load returned nil for a written file")
	}
	for _, tc := range []struct {
		ns, digest string
	}{
		{"kube-system", pushDigestA},
		{"kube-system", pushDigestB},
		{"gmp-system", pushDigestC},
	} {
		if !loaded.admits(tc.ns, tc.digest) {
			t.Errorf("loaded snapshot does not admit %s in %s", tc.digest, tc.ns)
		}
	}
	if loaded.admits("gmp-system", pushDigestA) {
		t.Error("load must preserve namespace scoping")
	}
}

func TestExemptSnapshot_LoadAbsentReturnsNil(t *testing.T) {
	loaded, err := loadExemptSnapshot(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("an absent file is not an error: %v", err)
	}
	if loaded != nil {
		t.Fatal("an absent file must load as nil so the caller captures")
	}
}

func TestExemptSnapshot_LoadCorruptErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exempt-snapshot.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadExemptSnapshot(path); err == nil {
		t.Fatal("a corrupt snapshot must surface as an error, not be silently recaptured")
	}
}
