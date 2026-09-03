// Package policybundle loads and indexes a policy bundle: the flat set of
// JSON documents a static-allowlist node boots with (the policydata disk).
// The bundle's index — one "sha256:<hex>" per member over its raw bytes — is
// what the node measures into RTMR[3] (runtimemeasure.ForStaticAllowlist),
// so the node, the installer and every verifier recompute it through this
// package. The index digests the member bytes exactly as attached: a member
// that differs by one byte is a different bundle.
package policybundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// MemberStaticAllowlist is the one required member: the sealed
// c8s.allowlist/v1 document the node enforces.
const MemberStaticAllowlist = "static-allowlist.json"

// Bounds the node's measurer enforces when it reads the bundle off an
// untrusted disk; Load and FromMembers apply the same bounds so a bundle the
// client accepts is one the node accepts.
const (
	MaxMembers    = 64
	MaxMemberSize = 8 << 20
)

// knownMembers lists every member name a consumer exists for. An unknown
// name is refused rather than measured: a member nothing reads would still
// change RTMR[3], and a reviewer cannot review what nothing enforces.
var knownMembers = map[string]bool{
	MemberStaticAllowlist: true,
}

var memberNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Bundle is a validated policy bundle. Members holds the raw bytes of every
// member, keyed by name, exactly as attached to the node.
type Bundle struct {
	Members map[string][]byte
}

// Load reads a bundle from a directory (every regular file is a member, no
// subdirectories) or from a single file, which becomes the one member
// MemberStaticAllowlist whatever its basename. An ISO image is refused: no
// ISO9660 reader exists here, so pass the directory the image was built
// from.
func Load(path string) (Bundle, error) {
	if strings.EqualFold(filepath.Ext(path), ".iso") {
		return Bundle{}, fmt.Errorf("%s: ISO images cannot be read here; pass the directory the image was built from (or the static-allowlist.json alone)", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return Bundle{}, fmt.Errorf("policy bundle: %w", err)
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return Bundle{}, fmt.Errorf("policy bundle: %s is not a regular file", path)
		}
		data, err := readMember(path)
		if err != nil {
			return Bundle{}, err
		}
		return FromMembers(map[string][]byte{MemberStaticAllowlist: data})
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return Bundle{}, fmt.Errorf("policy bundle: %w", err)
	}
	if len(entries) > MaxMembers {
		return Bundle{}, fmt.Errorf("policy bundle %s has %d entries, max %d", path, len(entries), MaxMembers)
	}
	members := make(map[string][]byte, len(entries))
	for _, e := range entries {
		member := filepath.Join(path, e.Name())
		if e.IsDir() {
			return Bundle{}, fmt.Errorf("policy bundle: %s is a directory; a bundle is flat", member)
		}
		if !e.Type().IsRegular() {
			return Bundle{}, fmt.Errorf("policy bundle: %s is not a regular file", member)
		}
		data, err := readMember(member)
		if err != nil {
			return Bundle{}, err
		}
		members[e.Name()] = data
	}
	return FromMembers(members)
}

// readMember bounds the read itself, not a Stat size, so a file that grows
// after Stat or a node whose Stat size is not its content is still refused
// past MaxMemberSize instead of buffered.
func readMember(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("policy bundle: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxMemberSize+1))
	if err != nil {
		return nil, fmt.Errorf("policy bundle: read %s: %w", path, err)
	}
	if len(data) > MaxMemberSize {
		return nil, fmt.Errorf("policy bundle member %s is over %d bytes", path, MaxMemberSize)
	}
	return data, nil
}

// FromMembers validates an in-memory member set: MemberStaticAllowlist
// present, every name well-formed and known, every member within
// MaxMemberSize, at most MaxMembers. The returned Bundle owns copies of the
// input.
func FromMembers(m map[string][]byte) (Bundle, error) {
	if len(m) > MaxMembers {
		return Bundle{}, fmt.Errorf("policy bundle has %d members, max %d", len(m), MaxMembers)
	}
	if _, ok := m[MemberStaticAllowlist]; !ok {
		return Bundle{}, fmt.Errorf("policy bundle has no %s member", MemberStaticAllowlist)
	}
	members := make(map[string][]byte, len(m))
	for _, name := range slices.Sorted(maps.Keys(m)) {
		if !memberNameRe.MatchString(name) {
			return Bundle{}, fmt.Errorf("policy bundle member name %q is invalid: want %s", name, memberNameRe)
		}
		if !knownMembers[name] {
			return Bundle{}, fmt.Errorf("policy bundle member %q is unknown: no consumer exists for it (known: %s)", name, strings.Join(slices.Sorted(maps.Keys(knownMembers)), ", "))
		}
		if len(m[name]) > MaxMemberSize {
			return Bundle{}, fmt.Errorf("policy bundle member %s is %d bytes, max %d", name, len(m[name]), MaxMemberSize)
		}
		members[name] = bytes.Clone(m[name])
	}
	return Bundle{Members: members}, nil
}

// Index returns the canonical index document the node measures: the
// encoding/json form of map[string]string{name: "sha256:<hex>"} — keys
// sorted, no whitespace — over the raw bytes of every member.
func (b Bundle) Index() []byte {
	index := make(map[string]string, len(b.Members))
	for name, data := range b.Members {
		sum := sha256.Sum256(data)
		index[name] = "sha256:" + hex.EncodeToString(sum[:])
	}
	// A map[string]string always marshals: no error can occur here.
	out, _ := json.Marshal(index)
	return out
}

// IndexDigest is SHA-256 of Index(): the value the node writes to
// <policy-dir>/digest and `c8s policy-disk` prints.
func (b Bundle) IndexDigest() [32]byte {
	return sha256.Sum256(b.Index())
}

// RTMR3 is the register a node sealed to this bundle reports:
// runtimemeasure.ForStaticAllowlist(Index()).
func (b Bundle) RTMR3() [runtimemeasure.Size]byte {
	return runtimemeasure.ForStaticAllowlist(b.Index())
}
