package cds

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func testStore(t *testing.T) *allowlist.Store {
	t.Helper()
	s, err := allowlist.OpenStore(filepath.Join(t.TempDir(), "allowlist.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return &s
}

// recorder captures the claims each re-issue would bind.
type recorder struct {
	mu     sync.Mutex
	claims [][]byte
	fail   error
}

func (r *recorder) swap(_ context.Context, p ratls.CertProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	ssp, ok := p.(*ratls.SelfSignedProvider)
	if !ok {
		return fmt.Errorf("unexpected provider %T", p)
	}
	r.claims = append(r.claims, append([]byte(nil), ssp.Opts.ConfigClaims.AllowlistDigest...))
	return nil
}

func (r *recorder) seen() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.claims...)
}

func newProviderFor(claims *ratls.ConfigClaims) ratls.CertProvider {
	return &ratls.SelfSignedProvider{Opts: &ratls.CertOptions{ConfigClaims: claims}}
}

func baseClaims(store *allowlist.Store, t *testing.T) ratls.ConfigClaims {
	t.Helper()
	d, err := liveAllowlistDigest(store)
	if err != nil {
		t.Fatalf("live digest: %v", err)
	}
	return ratls.ConfigClaims{
		OperatorKeysDigest: ratls.UnsetDigest(),
		SeedDigest:         ratls.UnsetDigest(),
		WorkloadDigest:     ratls.UnsetDigest(),
		MeshCADigest:       ratls.UnsetDigest(),
		AllowlistDigest:    d,
	}
}

func waitFor(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// The whole point of the design: mutating the allowlist must re-issue the
// serving certificate with the new live digest, because that is what makes a
// client's fingerprint-keyed cache invalidate exactly when policy changes.
func TestAllowlistMutationReissuesCert(t *testing.T) {
	store := testStore(t)
	rec := &recorder{}
	claims := baseClaims(store, t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchAllowlistReissue(ctx, store, rec.swap, claims, newProviderFor, 5*time.Millisecond)

	digest, err := types.ParseDigest("sha256:" + bytesHex(0xAB))
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}
	if err := store.Add(digest, "example.com/img@sha256:"+bytesHex(0xAB)); err != nil {
		t.Fatalf("add: %v", err)
	}

	if !waitFor(t, func() bool { return len(rec.seen()) > 0 }) {
		t.Fatal("allowlist mutation did not re-issue the serving certificate")
	}

	want, err := liveAllowlistDigest(store)
	if err != nil {
		t.Fatalf("live digest: %v", err)
	}
	got := rec.seen()[0]
	if !bytes.Equal(got, want) {
		t.Fatalf("re-issued with allowlist digest %x, live store is %x", got, want)
	}
	if bytes.Equal(got, claims.AllowlistDigest) {
		t.Fatal("re-issued certificate still carries the pre-mutation digest")
	}
}

// A quiet allowlist must not churn the certificate: a client caching by
// fingerprint would otherwise re-attest forever, which is the cost that made
// re-issue-per-mutation viable in the first place.
func TestNoReissueWithoutChange(t *testing.T) {
	store := testStore(t)
	rec := &recorder{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchAllowlistReissue(ctx, store, rec.swap, baseClaims(store, t), newProviderFor, 5*time.Millisecond)

	time.Sleep(200 * time.Millisecond)
	if n := len(rec.seen()); n != 0 {
		t.Fatalf("re-issued %d times with no allowlist change", n)
	}
}

// A failed swap must be retried, not swallowed. Dropping it would leave the
// certificate attesting a policy that is no longer in force, indefinitely.
func TestReissueRetriesAfterSwapFailure(t *testing.T) {
	store := testStore(t)
	rec := &recorder{fail: fmt.Errorf("attestation unavailable")}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchAllowlistReissue(ctx, store, rec.swap, baseClaims(store, t), newProviderFor, 5*time.Millisecond)

	if err := store.ReplaceAll(&pkgallowlist.Allowlist{
		Schema:  pkgallowlist.Schema,
		Digests: map[string]string{"sha256:" + bytesHex(0xCD): "example.com/x"},
	}); err != nil {
		t.Fatalf("replace: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Recover: the very next tick must re-issue, proving `last` was not
	// advanced past a change that never reached a certificate.
	rec.mu.Lock()
	rec.fail = nil
	rec.mu.Unlock()

	if !waitFor(t, func() bool { return len(rec.seen()) > 0 }) {
		t.Fatal("a change that failed to re-issue was never retried")
	}
}

func bytesHex(b byte) string {
	out := make([]byte, 0, 64)
	for i := 0; i < 32; i++ {
		out = append(out, "0123456789abcdef"[b>>4], "0123456789abcdef"[b&0xF])
	}
	return string(out)
}
