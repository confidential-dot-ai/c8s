package secrets

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestMemoryStoreGetMissing(t *testing.T) {
	s := NewMemoryStore(10, 64)
	if _, err := s.Get(context.Background(), "/nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// The first writer defines the value; a later one is told what is there and
// that it did not create it — which is how a losing replica recovers.
func TestMemoryStorePutIfAbsent(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(10, 64)

	got, created, err := s.PutIfAbsent(ctx, "/a", []byte("first"))
	if err != nil || !created || !bytes.Equal(got, []byte("first")) {
		t.Fatalf("first put: %q %v %v", got, created, err)
	}
	got, created, err = s.PutIfAbsent(ctx, "/a", []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("second put reported that it created the value")
	}
	if !bytes.Equal(got, []byte("first")) {
		t.Fatalf("second put = %q, want the original value", got)
	}
}

// A caller must not be able to reach into stored state through a returned
// slice.
func TestMemoryStoreCopiesValues(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(10, 64)
	original := []byte("secret")
	if _, _, err := s.PutIfAbsent(ctx, "/a", original); err != nil {
		t.Fatal(err)
	}
	original[0] = 'X' // mutate the caller's slice after storing

	got, err := s.Get(ctx, "/a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("stored value = %q, want it unaffected by the caller's slice", got)
	}
	got[0] = 'Y' // mutate what Get handed back
	again, _ := s.Get(ctx, "/a")
	if !bytes.Equal(again, []byte("secret")) {
		t.Fatalf("stored value = %q, want it unaffected by a mutated result", again)
	}
}

func TestMemoryStoreBounds(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(2, 4)

	if _, _, err := s.PutIfAbsent(ctx, "/big", []byte("toolong")); err == nil {
		t.Fatal("an oversized value was stored")
	}
	for _, p := range []string{"/a", "/b"} {
		if _, _, err := s.PutIfAbsent(ctx, p, []byte("ok")); err != nil {
			t.Fatalf("put %s: %v", p, err)
		}
	}
	if _, _, err := s.PutIfAbsent(ctx, "/c", []byte("ok")); err == nil {
		t.Fatal("the path cap did not bound the store")
	}
	// An existing path still resolves at the cap.
	if _, created, err := s.PutIfAbsent(ctx, "/a", []byte("ok")); err != nil || created {
		t.Fatalf("existing path at the cap: created=%v err=%v", created, err)
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
}

func TestGenerate(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != GeneratedValueBytes {
		t.Fatalf("len = %d, want %d", len(a), GeneratedValueBytes)
	}
	b, _ := Generate()
	if bytes.Equal(a, b) {
		t.Fatal("two generated values were identical")
	}
}
