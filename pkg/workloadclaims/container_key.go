package workloadclaims

import (
	"cmp"
	"slices"
	"strings"
)

// Key identifies this (digest, argv) pair in an inventory's admission
// high-water mark, where it is the deduplication key.
//
// The encoding MUST be injective, so it is /proc/cmdline's: NUL after every
// element, digest included. NUL is the one byte neither field can carry — an
// execve argument is a NUL-terminated C string and a digest is hex — and
// terminating rather than separating keeps an empty argv list distinct from a
// single empty argument.
//
// A non-injective key is not merely untidy. Two distinct admissions that
// collide onto one key erase each other from the sandbox's record, and the
// erasure is invisible to CDS: it drops the container from the digests and
// containers views alike, so the cross-check between them still agrees and the
// sandbox can then be named for a workload it did not actually run.
func (c SandboxContainer) Key() string {
	var b strings.Builder
	b.Grow(len(c.Digest) + 1 + len(c.Argv))
	b.WriteString(c.Digest)
	b.WriteByte(0)
	for _, a := range c.Argv {
		b.WriteString(a)
		b.WriteByte(0)
	}
	return b.String()
}

// Compare orders containers by digest, then argv — the stable order the
// digests endpoint serves, so identical sandboxes report identical
// inventories.
func (c SandboxContainer) Compare(o SandboxContainer) int {
	return cmp.Or(strings.Compare(c.Digest, o.Digest), slices.Compare(c.Argv, o.Argv))
}
