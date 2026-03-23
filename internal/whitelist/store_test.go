package whitelist

import (
	"testing"

	"github.com/lunal-dev/c8s/pkg/types"
)

const digestA = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
const digestB = "sha256:b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

func mustParseDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("parse digest %q: %v", s, err)
	}
	return d
}

func TestInitialVersionIsOne(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if version != "1" {
		t.Fatalf("version: got %q, want %q", version, "1")
	}
	if len(digests) != 0 {
		t.Fatalf("expected empty digests, got %d", len(digests))
	}
}

func TestAddAndListRoundtrip(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dA := mustParseDigest(t, digestA)
	if err := store.Add(dA, "nginx:latest"); err != nil {
		t.Fatalf("add: %v", err)
	}

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if version != "2" {
		t.Fatalf("version: got %q, want %q", version, "2")
	}
	if len(digests) != 1 {
		t.Fatalf("expected 1 digest, got %d", len(digests))
	}
	if digests[dA] != "nginx:latest" {
		t.Fatalf("image: got %q, want %q", digests[dA], "nginx:latest")
	}
}

func TestAddSameDigestReplacesImage(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dA := mustParseDigest(t, digestA)

	if err := store.Add(dA, "nginx:1.0"); err != nil {
		t.Fatalf("add first: %v", err)
	}
	if err := store.Add(dA, "nginx:2.0"); err != nil {
		t.Fatalf("add second: %v", err)
	}

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// Two adds = version 3
	if version != "3" {
		t.Fatalf("version: got %q, want %q", version, "3")
	}
	if len(digests) != 1 {
		t.Fatalf("expected 1 digest, got %d", len(digests))
	}
	if digests[dA] != "nginx:2.0" {
		t.Fatalf("image: got %q, want %q", digests[dA], "nginx:2.0")
	}
}

func TestDeleteExistingDigests(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dA := mustParseDigest(t, digestA)
	dB := mustParseDigest(t, digestB)

	if err := store.Add(dA, "nginx:latest"); err != nil {
		t.Fatalf("add A: %v", err)
	}
	if err := store.Add(dB, "redis:latest"); err != nil {
		t.Fatalf("add B: %v", err)
	}

	ok, err := store.Delete([]types.Digest{dA, dB})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !ok {
		t.Fatal("expected delete to return true")
	}

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// 2 adds + 1 delete = version 4
	if version != "4" {
		t.Fatalf("version: got %q, want %q", version, "4")
	}
	if len(digests) != 0 {
		t.Fatalf("expected 0 digests, got %d", len(digests))
	}
}

func TestDeleteNonexistentReturnsFalse(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dA := mustParseDigest(t, digestA)

	ok, err := store.Delete([]types.Digest{dA})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if ok {
		t.Fatal("expected delete to return false for nonexistent digest")
	}

	// Version should not change
	version, _, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if version != "1" {
		t.Fatalf("version: got %q, want %q", version, "1")
	}
}

func TestDeleteEmptyListIsOK(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	ok, err := store.Delete([]types.Digest{})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !ok {
		t.Fatal("expected delete of empty list to return true")
	}
}
