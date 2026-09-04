package policybundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
	"golang.org/x/sys/unix"
)

// goldenMember is a minimal member whose index bytes are frozen below. A
// change to the index encoding changes RTMR[3] on every static node, so a
// failure here is a contract break, not a test to update.
var goldenMember = []byte("{}\n")

const (
	goldenIndex       = `{"static-allowlist.json":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}`
	goldenIndexDigest = "c2ac7a5e7197eb736507b69fffc9d1f5e24ebf38f709a3226a6f8bb10ffa8749"
	goldenRTMR3       = "2e2286ab174b1ef0777157d810ac762c4c1915524e113a467b651cbaea41b89e1ac80388fabae89f8108c66e3685ae1e"
)

func mustBundle(t *testing.T, m map[string][]byte) Bundle {
	t.Helper()
	b, err := FromMembers(m)
	if err != nil {
		t.Fatalf("FromMembers(%v): %v", keys(m), err)
	}
	return b
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestIndexGolden(t *testing.T) {
	b := mustBundle(t, map[string][]byte{MemberStaticAllowlist: goldenMember})
	if got := string(b.Index()); got != goldenIndex {
		t.Errorf("Index() = %s, want %s", got, goldenIndex)
	}
	d := b.IndexDigest()
	if got := hex.EncodeToString(d[:]); got != goldenIndexDigest {
		t.Errorf("IndexDigest() = %s, want %s", got, goldenIndexDigest)
	}
	r := b.RTMR3()
	if got := hex.EncodeToString(r[:]); got != goldenRTMR3 {
		t.Errorf("RTMR3() = %s, want %s", got, goldenRTMR3)
	}
}

// Key order and the multi-member layout, frozen with a hand-built Bundle:
// FromMembers cannot build one today (only one member name is known), yet
// every static node and verifier depends on the sorted, whitespace-free form.
func TestIndexGoldenMultiMember(t *testing.T) {
	b := Bundle{Members: map[string][]byte{
		"z.json":              []byte("z"),
		MemberStaticAllowlist: goldenMember,
		"a.json":              []byte("a"),
	}}
	const want = `{"a.json":"sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",` +
		`"static-allowlist.json":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",` +
		`"z.json":"sha256:594e519ae499312b29433b7dd8a97ff068defcba9755b6d5d00e84c524d67b06"}`
	if got := string(b.Index()); got != want {
		t.Errorf("Index() = %s, want %s", got, want)
	}
}

// The index is derived from Index() alone, so the three accessors cannot
// disagree.
func TestIndexDerivations(t *testing.T) {
	b := mustBundle(t, map[string][]byte{MemberStaticAllowlist: []byte(`{"apiVersion":"c8s.allowlist/v1"}`)})
	index := b.Index()
	if want := sha256.Sum256(index); b.IndexDigest() != want {
		t.Errorf("IndexDigest() = %x, want sha256(Index()) = %x", b.IndexDigest(), want)
	}
	if want := runtimemeasure.ForStaticAllowlist(index); b.RTMR3() != want {
		t.Errorf("RTMR3() = %x, want ForStaticAllowlist(Index()) = %x", b.RTMR3(), want)
	}
}

// The index digests the raw bytes: whitespace-only differences in a member
// are different bundles, because the node enforces the bytes it measured.
func TestIndexIsOverRawBytes(t *testing.T) {
	a := mustBundle(t, map[string][]byte{MemberStaticAllowlist: []byte("{}")})
	b := mustBundle(t, map[string][]byte{MemberStaticAllowlist: []byte("{ }")})
	if bytes.Equal(a.Index(), b.Index()) {
		t.Error("Index() must differ for members that differ by a byte")
	}
	if a.RTMR3() == b.RTMR3() {
		t.Error("RTMR3() must differ for members that differ by a byte")
	}
}

func TestFromMembersOwnsCopies(t *testing.T) {
	in := map[string][]byte{MemberStaticAllowlist: []byte("{}")}
	b := mustBundle(t, in)
	in[MemberStaticAllowlist][0] = '['
	if got := string(b.Members[MemberStaticAllowlist]); got != "{}" {
		t.Errorf("Members[%s] = %q after mutating the input, want %q", MemberStaticAllowlist, got, "{}")
	}
}

func TestFromMembersErrors(t *testing.T) {
	ok := []byte("{}")
	tooMany := make(map[string][]byte, MaxMembers+1)
	tooMany[MemberStaticAllowlist] = ok
	for i := 0; len(tooMany) <= MaxMembers; i++ {
		tooMany["m"+strings.Repeat("x", i)] = ok
	}
	for _, tc := range []struct {
		name string
		in   map[string][]byte
		want string
	}{
		{"nil", nil, "no static-allowlist.json member"},
		{"required member missing", map[string][]byte{"routes.json": ok}, "no static-allowlist.json member"},
		{"unknown member", map[string][]byte{MemberStaticAllowlist: ok, "routes.json": ok}, `member "routes.json" is unknown`},
		{"name with slash", map[string][]byte{MemberStaticAllowlist: ok, "a/b.json": ok}, `"a/b.json" is invalid`},
		{"name starting with dot", map[string][]byte{MemberStaticAllowlist: ok, ".hidden": ok}, `".hidden" is invalid`},
		{"name too long", map[string][]byte{MemberStaticAllowlist: ok, strings.Repeat("a", 129): ok}, "is invalid"},
		{"empty name", map[string][]byte{MemberStaticAllowlist: ok, "": ok}, `"" is invalid`},
		{"name with space", map[string][]byte{MemberStaticAllowlist: ok, "a b": ok}, `"a b" is invalid`},
		{"oversize member", map[string][]byte{MemberStaticAllowlist: make([]byte, MaxMemberSize+1)}, "max 8388608"},
		{"too many members", tooMany, "max 64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromMembers(tc.in)
			if err == nil {
				t.Fatalf("FromMembers(%s) = nil error, want %q", tc.name, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("FromMembers(%s) error = %q, want it to contain %q", tc.name, err, tc.want)
			}
		})
	}
}

// The name rule at its boundaries. Only one member name is known today, so
// the rule is tested directly: an unknown but well-formed name must fail on
// the known-set check, not the name check.
func TestMemberNameRule(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{MemberStaticAllowlist, true},
		{"a", true},
		{"A1_b-c.d", true},
		{strings.Repeat("a", 128), true},
		{strings.Repeat("a", 129), false},
		{"", false},
		{".hidden", false},
		{"-dash", false},
		{"_under", false},
		{"a/b", false},
		{"a b", false},
		{"ü.json", false},
	} {
		if got := memberNameRe.MatchString(tc.name); got != tc.ok {
			t.Errorf("memberNameRe.MatchString(%q) = %v, want %v", tc.name, got, tc.ok)
		}
	}
	_, err := FromMembers(map[string][]byte{MemberStaticAllowlist: []byte("{}"), "routes.json": []byte("{}")})
	if err == nil || !strings.Contains(err.Error(), "is unknown") {
		t.Errorf("FromMembers with a well-formed unknown name: err = %v, want an unknown-member error", err)
	}
}

func TestFromMembersAcceptsMaxMemberSize(t *testing.T) {
	b := mustBundle(t, map[string][]byte{MemberStaticAllowlist: make([]byte, MaxMemberSize)})
	if got := len(b.Members[MemberStaticAllowlist]); got != MaxMemberSize {
		t.Errorf("len(Members[%s]) = %d, want %d", MemberStaticAllowlist, got, MaxMemberSize)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, MemberStaticAllowlist), goldenMember)
	b, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(dir): %v", err)
	}
	if got := string(b.Index()); got != goldenIndex {
		t.Errorf("Load(dir).Index() = %s, want %s", got, goldenIndex)
	}
}

// A lone file is a one-member bundle named MemberStaticAllowlist, whatever
// its basename, so `verify --static-allowlist ./my-policy.json` works.
func TestLoadSingleFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "my-policy.json")
	writeFile(t, path, goldenMember)
	b, err := Load(path)
	if err != nil {
		t.Fatalf("Load(file): %v", err)
	}
	if got := string(b.Index()); got != goldenIndex {
		t.Errorf("Load(file).Index() = %s, want %s", got, goldenIndex)
	}
	if _, ok := b.Members[MemberStaticAllowlist]; !ok || len(b.Members) != 1 {
		t.Errorf("Load(file).Members = %v, want exactly [%s]", keys(b.Members), MemberStaticAllowlist)
	}
}

func TestLoadErrors(t *testing.T) {
	root := t.TempDir()
	mk := func(name string, stage func(dir string)) string {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, MemberStaticAllowlist), goldenMember)
		stage(dir)
		return dir
	}
	withSubdir := mk("subdir", func(dir string) {
		if err := os.Mkdir(filepath.Join(dir, "nested"), 0o755); err != nil {
			t.Fatal(err)
		}
	})
	withSymlink := mk("symlink", func(dir string) {
		if err := os.Symlink(filepath.Join(dir, MemberStaticAllowlist), filepath.Join(dir, "link.json")); err != nil {
			t.Fatal(err)
		}
	})
	withUnknown := mk("unknown", func(dir string) { writeFile(t, filepath.Join(dir, "routes.json"), []byte("{}")) })
	withOversize := mk("oversize", func(dir string) {
		writeFile(t, filepath.Join(dir, MemberStaticAllowlist), make([]byte, MaxMemberSize+1))
	})
	withTooMany := mk("toomany", func(dir string) {
		for i := range MaxMembers {
			writeFile(t, filepath.Join(dir, "m"+strings.Repeat("x", i)), []byte("{}"))
		}
	})
	empty := mk("empty", func(dir string) { os.Remove(filepath.Join(dir, MemberStaticAllowlist)) })
	iso := filepath.Join(root, "policydata.iso")
	writeFile(t, iso, []byte("not really an iso"))
	oversizeFile := filepath.Join(root, "big.json")
	writeFile(t, oversizeFile, make([]byte, MaxMemberSize+1))
	// A FIFO has Stat size 0 and never reaches EOF: Load must refuse it from
	// the mode alone, before any read that would block.
	fifo := filepath.Join(root, "policy.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"iso refused", iso, "ISO images cannot be read here"},
		{"iso refused even when absent", filepath.Join(root, "missing.ISO"), "ISO images cannot be read here"},
		{"missing path", filepath.Join(root, "absent"), "no such file"},
		{"subdirectory", withSubdir, "is a directory; a bundle is flat"},
		{"symlink member", withSymlink, "is not a regular file"},
		{"unknown member", withUnknown, `"routes.json" is unknown`},
		{"oversize member", withOversize, "over 8388608 bytes"},
		{"too many entries", withTooMany, "max 64"},
		{"required member missing", empty, "no static-allowlist.json member"},
		{"oversize single file", oversizeFile, "over 8388608 bytes"},
		{"fifo single file", fifo, "is not a regular file"},
		{"device node single file", "/dev/zero", "is not a regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(tc.path)
			if err == nil {
				t.Fatalf("Load(%s) = nil error, want %q", tc.name, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load(%s) error = %q, want it to contain %q", tc.name, err, tc.want)
			}
		})
	}
}
