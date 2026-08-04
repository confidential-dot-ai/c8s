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

	got, held, err := s.PutIfAbsent(ctx, "/a", []byte("first"), OriginWorkload)
	if err != nil || held.Exists || !bytes.Equal(got, []byte("first")) {
		t.Fatalf("first put: %q %+v %v", got, held, err)
	}
	got, held, err = s.PutIfAbsent(ctx, "/a", []byte("second"), OriginOperator)
	if err != nil {
		t.Fatal(err)
	}
	if !held.Exists {
		t.Fatal("second put reported that it created the value")
	}
	if held.Origin != OriginWorkload {
		t.Fatalf("held origin = %q, want the first writer's", held.Origin)
	}
	if !bytes.Equal(got, []byte("first")) {
		t.Fatalf("second put = %q, want the original value", got)
	}
}

// Put replaces whatever is there and reports what that was, which is the only
// thing the operator write path learns about a value it did not write.
func TestMemoryStorePut(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(10, 64)

	held, err := s.Put(ctx, "/a", []byte("operator"), OriginOperator)
	if err != nil || held.Exists {
		t.Fatalf("put onto an empty path: %+v %v", held, err)
	}

	if _, _, err := s.PutIfAbsent(ctx, "/b", []byte("generated"), OriginWorkload); err != nil {
		t.Fatal(err)
	}
	held, err = s.Put(ctx, "/b", []byte("operator"), OriginOperator)
	if err != nil {
		t.Fatal(err)
	}
	if !held.Exists || held.Origin != OriginWorkload {
		t.Fatalf("held = %+v, want the displaced workload value", held)
	}
	got, err := s.Get(ctx, "/b")
	if err != nil || !bytes.Equal(got, []byte("operator")) {
		t.Fatalf("after replace: %q %v", got, err)
	}

	// The replacement carries its own origin forward.
	held, err = s.Put(ctx, "/b", []byte("again"), OriginOperator)
	if err != nil || held.Origin != OriginOperator {
		t.Fatalf("held = %+v %v, want the operator value it replaced", held, err)
	}
}

// Put is bounded by the same caps as PutIfAbsent, and replacing a path does not
// consume room the store does not have.
func TestMemoryStorePutBounds(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(1, 4)

	if _, err := s.Put(ctx, "/a", []byte("toolong"), OriginOperator); err == nil {
		t.Fatal("an oversized value was stored")
	}
	if _, err := s.Put(ctx, "/a", []byte("ok"), OriginOperator); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "/b", []byte("ok"), OriginOperator); err == nil {
		t.Fatal("the path cap did not bound Put")
	}
	if _, err := s.Put(ctx, "/a", []byte("new"), OriginOperator); err != nil {
		t.Fatalf("replacing an existing path at the cap: %v", err)
	}
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1", s.Len())
	}
}

// A caller must not be able to reach into stored state through a returned
// slice.
func TestMemoryStoreCopiesValues(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(10, 64)
	original := []byte("secret")
	if _, _, err := s.PutIfAbsent(ctx, "/a", original, OriginWorkload); err != nil {
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

	if _, _, err := s.PutIfAbsent(ctx, "/big", []byte("toolong"), OriginWorkload); err == nil {
		t.Fatal("an oversized value was stored")
	}
	for _, p := range []string{"/a", "/b"} {
		if _, _, err := s.PutIfAbsent(ctx, p, []byte("ok"), OriginWorkload); err != nil {
			t.Fatalf("put %s: %v", p, err)
		}
	}
	if _, _, err := s.PutIfAbsent(ctx, "/c", []byte("ok"), OriginWorkload); err == nil {
		t.Fatal("the path cap did not bound the store")
	}
	// An existing path still resolves at the cap.
	if _, held, err := s.PutIfAbsent(ctx, "/a", []byte("ok"), OriginWorkload); err != nil || !held.Exists {
		t.Fatalf("existing path at the cap: held=%+v err=%v", held, err)
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
