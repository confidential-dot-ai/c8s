package localverify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"regexp"

	"github.com/google/go-sev-guest/verify/trust"
)

// kdsCacheDirEnv overrides the on-disk VCEK cache location; an empty value
// disables the cache.
const kdsCacheDirEnv = "C8S_KDS_CACHE_DIR"

// cachingGetter serves AMD KDS endorsement-key certificates (VCEK/VLEK) from a
// directory before asking the wrapped getter. A VCEK URL names one chip at one
// TCB and its content never changes, so a hit is exact, and the certificate
// still has to chain to AMD's bundled roots on every verification, so a
// tampered cache can only cause a rejection. Everything else (CRLs) passes
// through: revocation data must stay fresh.
//
// AMD KDS rate-limits per client (HTTP 429). Without this, each `c8s verify`,
// `get-kubeconfig` gate and RA-TLS dial, and each router discovery behind an
// `allowlist` write fetched the same certificate again, and a lane doing five
// verifications in ten minutes was throttled into "collateral unavailable".
type cachingGetter struct {
	dir  string
	next trust.HTTPSGetter
}

// newCachingGetter wraps next with a cache under dir. An empty dir, or one that
// cannot be created, yields the wrapped getter unchanged: caching is an
// optimisation, never a precondition.
func newCachingGetter(dir string, next trust.HTTPSGetter) trust.HTTPSGetter {
	if dir == "" {
		return next
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return next
	}
	return &cachingGetter{dir: dir, next: next}
}

// defaultKDSCacheDir resolves the cache directory: the env override (empty
// disables), else the user cache dir, else none.
func defaultKDSCacheDir() string {
	if v, ok := os.LookupEnv(kdsCacheDirEnv); ok {
		return v
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "c8s", "kds")
}

// vcekPath matches the KDS endorsement-certificate path: /vcek/v1/<product>/<128 hex chip id>
// (the TCB comes in the query). The CRL lives beside it at /vcek/v1/<product>/crl
// and must never be cached.
var vcekPath = regexp.MustCompile(`^/v[cl]ek/v1/[^/]+/[0-9a-fA-F]{128}$`)

// cacheable reports whether rawURL names an immutable endorsement certificate.
func cacheable(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return vcekPath.MatchString(u.Path)
}

func (c *cachingGetter) path(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".der")
}

func (c *cachingGetter) Get(rawURL string) ([]byte, error) {
	return c.GetContext(context.Background(), rawURL)
}

func (c *cachingGetter) GetContext(ctx context.Context, rawURL string) ([]byte, error) {
	if !cacheable(rawURL) {
		return trust.GetWith(ctx, c.next, rawURL)
	}
	p := c.path(rawURL)
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
		return b, nil
	}
	b, err := trust.GetWith(ctx, c.next, rawURL)
	if err != nil {
		return nil, err
	}
	// Atomic publish so a concurrent reader never sees a partial file; a
	// failed write only costs the next caller a fetch.
	tmp, err := os.CreateTemp(c.dir, ".vcek-*")
	if err == nil {
		if _, werr := tmp.Write(b); werr == nil && tmp.Close() == nil {
			if rerr := os.Rename(tmp.Name(), p); rerr != nil {
				_ = os.Remove(tmp.Name())
			}
		} else {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}
	return b, nil
}
