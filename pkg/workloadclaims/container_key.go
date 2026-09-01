package workloadclaims

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// Key identifies one observed container policy tuple in an inventory's
// admission high-water mark, where it is the deduplication key. It excludes
// Stopped. A restart of the same Kubernetes container replaces the stopped
// value with a live value instead of creating a false duplicate admission.
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
	b.Grow(len(c.Name) + len(c.Role) + len(c.Digest) + 3 + len(c.Argv))
	b.WriteString(c.Name)
	b.WriteByte(0)
	b.WriteString(c.Role)
	b.WriteByte(0)
	b.WriteString(c.Digest)
	b.WriteByte(0)
	for _, a := range c.Argv {
		b.WriteString(a)
		b.WriteByte(0)
	}
	b.WriteString(strconv.FormatBool(c.MountsObserved))
	b.WriteByte(0)
	for _, m := range c.BindMounts {
		b.WriteString(m)
		b.WriteByte(0)
		b.WriteString(c.BindMountKinds[m])
		b.WriteByte(0)
	}
	b.WriteString(strconv.FormatBool(c.EnvObserved))
	b.WriteByte(0)
	for _, n := range c.EnvNames {
		b.WriteString(n)
		b.WriteByte(0)
	}
	for _, name := range []string{"HOST_IP", "NODE_IP"} {
		b.WriteString(name)
		b.WriteByte(0)
		b.WriteString(c.EnvValues[name])
		b.WriteByte(0)
	}
	return b.String()
}

// Compare orders containers by the complete observed policy tuple — the stable order the
// digests endpoint serves, so identical sandboxes report identical
// inventories.
func (c SandboxContainer) Compare(o SandboxContainer) int {
	return cmp.Or(
		strings.Compare(c.Name, o.Name),
		strings.Compare(c.Role, o.Role),
		compareBool(c.Stopped, o.Stopped),
		strings.Compare(c.Digest, o.Digest),
		slices.Compare(c.Argv, o.Argv),
		compareBool(c.MountsObserved, o.MountsObserved),
		slices.Compare(c.BindMounts, o.BindMounts),
		compareMountKinds(c.BindMounts, c.BindMountKinds, o.BindMounts, o.BindMountKinds),
		compareBool(c.EnvObserved, o.EnvObserved),
		slices.Compare(c.EnvNames, o.EnvNames),
		comparePublicEnv(c.EnvValues, o.EnvValues),
	)
}

func comparePublicEnv(a, b map[string]string) int {
	for _, name := range []string{"HOST_IP", "NODE_IP"} {
		if c := strings.Compare(a[name], b[name]); c != 0 {
			return c
		}
	}
	return 0
}

func compareMountKinds(aNames []string, a map[string]string, bNames []string, b map[string]string) int {
	for i := 0; i < len(aNames) && i < len(bNames); i++ {
		if c := strings.Compare(a[aNames[i]], b[bNames[i]]); c != 0 {
			return c
		}
	}
	return 0
}

func compareBool(a, b bool) int {
	if a == b {
		return 0
	}
	if !a {
		return -1
	}
	return 1
}
