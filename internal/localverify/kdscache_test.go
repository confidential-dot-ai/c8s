package localverify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-sev-guest/verify/trust"
)

// errNotCached is what a fake getter returns to prove a cache hit never reached it.
var errNotCached = errors.New("network getter reached")

type countingGetter struct {
	calls int
	body  []byte
	err   error
}

func (g *countingGetter) Get(string) ([]byte, error) {
	g.calls++
	return g.body, g.err
}

const vcekURL = "https://kdsintf.amd.com/vcek/v1/Genoa/9277b37aaaca7412609cc472c9c59111a908021f805eca1bbe850e80f444e89901f16aef608af85bb57b0ae44f8945276a21df09d949187b8db7b71f624fd829?blSPL=12&teeSPL=0&snpSPL=28&ucodeSPL=28"

func TestCachingGetter_VCEKFetchedOnceThenServedFromDisk(t *testing.T) {
	dir := t.TempDir()
	next := &countingGetter{body: []byte("vcek-der")}
	g := newCachingGetter(dir, next)
	for i := 0; i < 3; i++ {
		b, err := g.Get(vcekURL)
		if err != nil || string(b) != "vcek-der" {
			t.Fatalf("call %d: got %q, %v", i, b, err)
		}
	}
	if next.calls != 1 {
		t.Fatalf("network getter reached %d times, want 1", next.calls)
	}
	// A fresh wrapper over the same directory (a later process) hits the disk copy.
	fresh := &countingGetter{err: errNotCached}
	if b, err := newCachingGetter(dir, fresh).Get(vcekURL); err != nil || string(b) != "vcek-der" {
		t.Fatalf("second process: got %q, %v", b, err)
	}
	if fresh.calls != 0 {
		t.Fatalf("second process reached the network %d times", fresh.calls)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || filepath.Ext(entries[0].Name()) != ".der" {
		t.Fatalf("cache dir holds %v, want one .der entry", entries)
	}
}

func TestCachingGetter_CRLsAreNeverCached(t *testing.T) {
	next := &countingGetter{body: []byte("crl")}
	g := newCachingGetter(t.TempDir(), next)
	const crl = "https://kdsintf.amd.com/vcek/v1/Genoa/crl"
	for i := 0; i < 2; i++ {
		if _, err := g.Get(crl); err != nil {
			t.Fatal(err)
		}
	}
	// The CRL sits beside the certificates under /vcek/v1/<product>/crl and is
	// only current until AMD publishes the next one.
	if next.calls != 2 {
		t.Fatalf("CRL fetched %d times, want 2 (never cached)", next.calls)
	}
}

func TestCachingGetter_FetchFailureIsNotCachedAndPropagates(t *testing.T) {
	dir := t.TempDir()
	next := &countingGetter{err: errors.New("status 429")}
	g := newCachingGetter(dir, next)
	if _, err := g.Get(vcekURL); err == nil {
		t.Fatal("want the fetch error")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a failed fetch left %v in the cache", entries)
	}
	next.err, next.body = nil, []byte("late")
	if b, err := trust.GetWith(context.Background(), g, vcekURL); err != nil || string(b) != "late" {
		t.Fatalf("after recovery: got %q, %v", b, err)
	}
}

func TestNewCachingGetter_NoDirMeansPassThrough(t *testing.T) {
	next := &countingGetter{body: []byte("x")}
	if g := newCachingGetter("", next); g != next {
		t.Fatal("empty dir must return the wrapped getter itself")
	}
	unusable := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(unusable, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if g := newCachingGetter(filepath.Join(unusable, "sub"), next); g != next {
		t.Fatal("an uncreatable dir must return the wrapped getter itself")
	}
}

func TestDefaultKDSCacheDir_EnvOverrideAndDisable(t *testing.T) {
	t.Setenv(kdsCacheDirEnv, "/tmp/c8s-kds-test")
	if got := defaultKDSCacheDir(); got != "/tmp/c8s-kds-test" {
		t.Fatalf("override: got %q", got)
	}
	t.Setenv(kdsCacheDirEnv, "")
	if got := defaultKDSCacheDir(); got != "" {
		t.Fatalf("empty override must disable the cache, got %q", got)
	}
}
