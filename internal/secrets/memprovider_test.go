package secrets

import (
	"context"
	"errors"
	"testing"
)

func TestMemProviderVersionsAndIsolation(t *testing.T) {
	seed := []byte("v1")
	p := NewMemProvider(map[string][]byte{"/a": seed})
	ctx := context.Background()

	// The seed is copied, so mutating the caller's slice cannot alter the store.
	seed[0] = 'X'
	got, err := p.Get(ctx, "/a", "")
	if err != nil || string(got.Data) != "v1" {
		t.Fatalf("get seeded: %+v, %v — want the original bytes", got, err)
	}

	// Nor can mutating a returned slice.
	got.Data[0] = 'Y'
	if again, _ := p.Get(ctx, "/a", ""); string(again.Data) != "v1" {
		t.Fatalf("returned data aliases the store: %q", again.Data)
	}

	if _, err := p.Put(ctx, "/a", []byte("v2")); err != nil {
		t.Fatalf("put: %v", err)
	}
	latest, _ := p.Get(ctx, "/a", "")
	if latest.Version != "2" || string(latest.Data) != "v2" {
		t.Fatalf("latest = %+v, want v2 at version 2", latest)
	}
	pinned, err := p.Get(ctx, "/a", "1")
	if err != nil || string(pinned.Data) != "v1" {
		t.Fatalf("pinned read: %+v, %v — want the first version", pinned, err)
	}
}

func TestMemProviderNotFound(t *testing.T) {
	p := NewMemProvider(nil)
	ctx := context.Background()
	if _, err := p.Get(ctx, "/missing", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing path: err = %v, want ErrNotFound", err)
	}
	if _, err := p.Get(ctx, "/missing", "7"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing version: err = %v, want ErrNotFound", err)
	}
	if _, err := p.GetMany(ctx, []Ref{{Path: "/missing"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetMany must fail whole rather than return a short list: %v", err)
	}
}

func TestMemProviderGetManyOrder(t *testing.T) {
	p := NewMemProvider(map[string][]byte{"/a": []byte("A"), "/b": []byte("B")})
	got, err := p.GetMany(context.Background(), []Ref{{Path: "/b"}, {Path: "/a"}})
	if err != nil {
		t.Fatalf("GetMany: %v", err)
	}
	if len(got) != 2 || string(got[0].Data) != "B" || string(got[1].Data) != "A" {
		t.Fatalf("got %+v, want results in request order", got)
	}
}
