package cds

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestSnapshotAllowlist(t *testing.T) {
	ca, err := issuer.NewCA("snap-test", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	valid := "sha256:" + strings.Repeat("ab", 32)
	doc := &pkgallowlist.Allowlist{
		Digests: map[string]string{valid: "registry.example/app:1"},
		Workloads: map[string]pkgallowlist.Workload{
			"web": {Label: "registry.example/app:1"},
		},
	}
	load := func() (*pkgallowlist.Allowlist, string, error) { return doc, "7", nil }

	snap, ok := snapshotAllowlist(load, ca)
	if !ok {
		t.Fatal("snapshotAllowlist returned ok=false for a healthy store")
	}
	if snap.Cert != ca.Cert || snap.Key != ca.Key {
		t.Fatal("snapshot does not carry the mesh CA keypair")
	}
	if snap.AllowlistVersion != "7" {
		t.Fatalf("AllowlistVersion = %q, want %q", snap.AllowlistVersion, "7")
	}
	pd, err := types.ParseDigest(valid)
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if got := snap.Allowlist[pd]; got != "registry.example/app:1" {
		t.Fatalf("Allowlist[%s] = %q, want the stored image ref", valid, got)
	}
	if len(snap.Allowlist) != 1 {
		t.Fatalf("Allowlist has %d entries, want 1", len(snap.Allowlist))
	}
	if _, found := snap.Workloads["web"]; !found || len(snap.Workloads) != 1 {
		t.Fatalf("Workloads = %v, want the single stored entry", snap.Workloads)
	}
}

func TestSnapshotAllowlistWithheldOnFailure(t *testing.T) {
	ca, err := issuer.NewCA("snap-test", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	tests := []struct {
		name string
		load func() (*pkgallowlist.Allowlist, string, error)
	}{
		{
			name: "load error",
			load: func() (*pkgallowlist.Allowlist, string, error) {
				return nil, "", errors.New("db closed")
			},
		},
		{
			name: "unparsable stored digest",
			load: func() (*pkgallowlist.Allowlist, string, error) {
				return &pkgallowlist.Allowlist{
					Digests: map[string]string{"not-a-digest": "img"},
				}, "3", nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap, ok := snapshotAllowlist(tt.load, ca)
			if ok {
				t.Fatal("snapshotAllowlist returned ok=true, want the snapshot withheld")
			}
			if snap.Cert != nil || snap.Key != nil {
				t.Fatal("withheld snapshot must not carry CA material")
			}
		})
	}
}
