package cache

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/whitelist"
)

func TestGetWhitelist_NilByDefault(t *testing.T) {
	c := NewPolicyCache()
	if c.GetWhitelist() != nil {
		t.Error("expected nil whitelist initially")
	}
}

func TestSetWhitelist(t *testing.T) {
	c := NewPolicyCache()
	wl := &whitelist.Whitelist{
		Version: "1.0",
		Digests: map[string]string{"sha256:" + strings.Repeat("a", 64): "test"},
	}
	c.SetWhitelist(wl)

	got := c.GetWhitelist()
	if got == nil {
		t.Fatal("expected whitelist after SetWhitelist")
	}
	if len(got.Digests) != 1 {
		t.Errorf("expected 1 digest, got %d", len(got.Digests))
	}
}

func TestClear(t *testing.T) {
	c := NewPolicyCache()
	wl := &whitelist.Whitelist{
		Version: "1.0",
		Digests: map[string]string{"sha256:" + strings.Repeat("a", 64): "test"},
	}
	c.SetWhitelist(wl)
	c.Clear()

	if c.GetWhitelist() != nil {
		t.Error("expected nil whitelist after Clear")
	}
}
