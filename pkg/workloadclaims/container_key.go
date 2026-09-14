package workloadclaims

import (
	"cmp"
	"encoding/binary"
	"slices"
	"strings"
)

// Key identifies a (digest, argv, env) admission in the cumulative inventory.
// The framing must be injective: a collision erases historical evidence and can
// allow a sandbox to match a workload it did not actually run.
func (c SandboxContainer) Key() string {
	// Length-prefix every field and count argv elements. Preserve arbitrary
	// argument bytes: JSON string encoding would collapse invalid UTF-8.
	var b []byte
	field := func(s string) { b = binary.AppendUvarint(b, uint64(len(s))); b = append(b, s...) }
	field(c.Digest)
	b = binary.AppendUvarint(b, uint64(len(c.Argv)))
	for _, a := range c.Argv {
		field(a)
	}
	if c.Env == nil {
		b = append(b, 0)
	} else {
		b = append(b, 1)
		field(c.Env.Format)
		field(c.Env.Digest)
	}
	return string(b)
}

// Compare orders containers by digest, argv, then env — the stable order the
// digests endpoint serves, so identical sandboxes report identical
// inventories.
func (c SandboxContainer) Compare(o SandboxContainer) int {
	return cmp.Or(strings.Compare(c.Digest, o.Digest), slices.Compare(c.Argv, o.Argv), strings.Compare(c.Key(), o.Key()))
}
