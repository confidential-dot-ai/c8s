package workloadclaims

import (
	"cmp"
	"slices"
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
	return cmp.Or(strings.Compare(c.Digest, o.Digest), slices.Compare(c.Argv, o.Argv))
}
