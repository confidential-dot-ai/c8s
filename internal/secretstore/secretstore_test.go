package secretstore

import (
	"context"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func mustDigest(t *testing.T, hexChar byte) types.Digest {
	t.Helper()
	hex := make([]byte, 64)
	for i := range hex {
		hex[i] = hexChar
	}
	d, err := types.ParseDigest("sha256:" + string(hex))
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}
	return d
}

func TestMemStoreGetSetDelete(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	ref := Ref{Entry: "vllm-llama", Path: "/secrets/model/dek"}
	requester := mustDigest(t, 'a')

	if _, err := s.Get(ctx, ref, requester); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store: got %v, want ErrNotFound", err)
	}

	if err := s.Set(ctx, ref, []byte("key-material")); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := s.Get(ctx, ref, requester)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != "key-material" {
		t.Fatalf("got %q", got)
	}

	// Last write wins.
	if err := s.Set(ctx, ref, []byte("rotated")); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, _ = s.Get(ctx, ref, requester)
	if string(got) != "rotated" {
		t.Fatalf("after rewrite got %q", got)
	}

	if err := s.Delete(ctx, ref); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Get(ctx, ref, requester); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: got %v, want ErrNotFound", err)
	}
	// Deleting an absent ref is fine.
	if err := s.Delete(ctx, ref); err != nil {
		t.Fatalf("delete absent: %v", err)
	}
}

func TestMemStoreCopiesValues(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	ref := Ref{Entry: "e", Path: "/secrets/x"}

	in := []byte("abc")
	_ = s.Set(ctx, ref, in)
	in[0] = 'z'
	got, _ := s.Get(ctx, ref, types.Digest{})
	if string(got) != "abc" {
		t.Fatalf("store aliased the input slice: got %q", got)
	}

	got[0] = 'y'
	again, _ := s.Get(ctx, ref, types.Digest{})
	if string(again) != "abc" {
		t.Fatalf("store aliased the returned slice: got %q", again)
	}
}

func TestMemStoreEntryScoping(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	_ = s.Set(ctx, Ref{Entry: "tenant-a", Path: "/secrets/model/key"}, []byte("a"))
	_ = s.Set(ctx, Ref{Entry: "tenant-b", Path: "/secrets/model/key"}, []byte("b"))

	a, _ := s.Get(ctx, Ref{Entry: "tenant-a", Path: "/secrets/model/key"}, types.Digest{})
	b, _ := s.Get(ctx, Ref{Entry: "tenant-b", Path: "/secrets/model/key"}, types.Digest{})
	if string(a) != "a" || string(b) != "b" {
		t.Fatalf("entry scoping broken: a=%q b=%q", a, b)
	}
}

func TestMemStoreJSONRoundTrip(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()
	_ = s.Set(ctx, Ref{Entry: "e1", Path: "/secrets/a"}, []byte{1, 2, 3})
	_ = s.Set(ctx, Ref{Entry: "e1", Path: "/secrets/b"}, []byte{4})
	_ = s.Set(ctx, Ref{Entry: "e2", Path: "/secrets/c"}, []byte{})

	dump, err := s.DumpJSON()
	if err != nil {
		t.Fatalf("dump: %v", err)
	}

	restored := NewMemStore()
	if err := restored.LoadJSON(dump); err != nil {
		t.Fatalf("load: %v", err)
	}
	if restored.Len() != 3 {
		t.Fatalf("restored %d secrets, want 3", restored.Len())
	}
	got, err := restored.Get(ctx, Ref{Entry: "e1", Path: "/secrets/a"}, types.Digest{})
	if err != nil || len(got) != 3 || got[2] != 3 {
		t.Fatalf("restored value wrong: %v %v", got, err)
	}

	if err := restored.LoadJSON([]byte(`{"e": {"/p": "not-base64!!"}}`)); err == nil {
		t.Fatal("invalid base64 accepted")
	}
	if err := restored.LoadJSON([]byte(`{"e": {"/p": "AAE="}, "x-unknown": 1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}
