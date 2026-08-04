package workloadclaims

import (
	"net/url"
	"strings"
)

// Key identifies a (digest, argv) pair for dedup in a sandbox inventory. The
// unit separator cannot appear in a digest and is not a shell-reachable argv
// byte in practice; a collision would only merge two identical-looking
// containers anyway.
func (c SandboxContainer) Key() string {
	return c.Digest + "\x1f" + strings.Join(c.Argv, "\x1f")
}

// Compare orders containers by digest, then argv — the stable order the
// digests endpoint serves, so identical sandboxes report identical
// inventories.
func (c SandboxContainer) Compare(o SandboxContainer) int {
	if c.Digest != o.Digest {
		return strings.Compare(c.Digest, o.Digest)
	}
	return strings.Compare(strings.Join(c.Argv, "\x1f"), strings.Join(o.Argv, "\x1f"))
}

// ResolveAdvertiseHostForCDS is ResolveAdvertiseHost with the CDS endpoint
// given as a URL: the URL's host is used when it parses as one, so every
// enforcer derives the digests-callback host from its pull config the same
// way.
func ResolveAdvertiseHostForCDS(host, cdsURL string) (string, error) {
	if u, err := url.Parse(cdsURL); err == nil && u.Host != "" {
		cdsURL = u.Host
	}
	return ResolveAdvertiseHost(host, cdsURL)
}
