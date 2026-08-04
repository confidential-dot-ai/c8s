package volume

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTools stands in for mkfs.erofs and veritysetup so the orchestration is
// exercised without either installed. It writes the sizes it is told to and
// records the argv it was called with.
type fakeTools struct {
	dataBytes int
	treeBytes int
	rootHash  string
	calls     [][]string
	failOn    string
}

func (f *fakeTools) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.failOn == name {
		return nil, errors.New("tool failed")
	}
	switch name {
	case "mkfs.erofs":
		// argv is [...flags, dest, source]
		dest := args[len(args)-2]
		if err := os.WriteFile(dest, bytes.Repeat([]byte{0xA5}, f.dataBytes), 0o600); err != nil {
			return nil, err
		}
		return nil, nil
	case "veritysetup":
		tree := args[2]
		if err := os.WriteFile(tree, bytes.Repeat([]byte{0x5A}, f.treeBytes), 0o600); err != nil {
			return nil, err
		}
		return []byte("VERITY header information\nRoot hash:      " + f.rootHash + "\n"), nil
	}
	return nil, errors.New("unexpected tool " + name)
}

func newFake() *fakeTools {
	return &fakeTools{
		dataBytes: 4 * VerityBlockSize,
		treeBytes: VerityBlockSize,
		rootHash:  strings.Repeat("ab", 32),
	}
}

func buildInto(t *testing.T, f *fakeTools) (Verity, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	out := filepath.Join(dir, "vol.img")
	key := testKey()

	v, err := Build(t.Context(), BuildConfig{Source: src, Out: out, Key: key, Run: f.run})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return v, out, key
}

func TestBuildProducesDecryptableConcatenation(t *testing.T) {
	f := newFake()
	v, out, key := buildInto(t, f)

	ct, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read image: %v", err)
	}
	if len(ct) != f.dataBytes+f.treeBytes {
		t.Fatalf("image is %d bytes, want %d", len(ct), f.dataBytes+f.treeBytes)
	}

	var plain bytes.Buffer
	if err := Decrypt(&plain, bytes.NewReader(ct), key); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	want := append(bytes.Repeat([]byte{0xA5}, f.dataBytes), bytes.Repeat([]byte{0x5A}, f.treeBytes)...)
	if !bytes.Equal(plain.Bytes(), want) {
		t.Fatal("decrypted image is not the erofs data followed by the hash tree")
	}

	// The geometry has to describe the layout that was actually written, or the
	// opener hashes the wrong bytes.
	if v.HashOffset != uint64(f.dataBytes) {
		t.Errorf("hash_offset = %d, want %d", v.HashOffset, f.dataBytes)
	}
	if v.DataBlocks != uint64(f.dataBytes)/VerityBlockSize {
		t.Errorf("data_blocks = %d, want %d", v.DataBlocks, f.dataBytes/VerityBlockSize)
	}
	if _, err := NewBlob(key, v); err != nil {
		t.Errorf("build produced geometry a blob rejects: %v", err)
	}
}

// The tree must be encrypted as a continuation of the data, not as its own
// stream: sector indices are the XTS tweaks, and they run continuously across
// the join when the device is read.
func TestBuildEncryptsTreeAsContinuationOfData(t *testing.T) {
	f := newFake()
	_, out, key := buildInto(t, f)
	ct, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read image: %v", err)
	}

	var whole bytes.Buffer
	plain := append(bytes.Repeat([]byte{0xA5}, f.dataBytes), bytes.Repeat([]byte{0x5A}, f.treeBytes)...)
	if err := Encrypt(&whole, bytes.NewReader(plain), key); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(ct, whole.Bytes()) {
		t.Fatal("image differs from encrypting data||tree as one stream")
	}
}

func TestBuildPassesNoSuperblockAndExplicitGeometry(t *testing.T) {
	f := newFake()
	buildInto(t, f)

	var verity []string
	for _, c := range f.calls {
		if c[0] == "veritysetup" {
			verity = c
		}
	}
	if verity == nil {
		t.Fatal("veritysetup was never invoked")
	}
	joined := strings.Join(verity, " ")
	for _, want := range []string{"--no-superblock", "--hash sha256", "--data-block-size 4096", "--salt "} {
		if !strings.Contains(joined, want) {
			t.Errorf("veritysetup argv missing %q: %s", want, joined)
		}
	}
}

// The plaintext image is what the whole design protects; it must not survive
// the build, including when the caller supplied the work directory.
func TestBuildRemovesPlaintextIntermediates(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	work := filepath.Join(dir, "work")
	f := newFake()

	if _, err := Build(t.Context(), BuildConfig{
		Source: src, Out: filepath.Join(dir, "vol.img"), Key: testKey(), WorkDir: work, Run: f.run,
	}); err != nil {
		t.Fatalf("build: %v", err)
	}
	entries, err := os.ReadDir(work)
	if err != nil {
		t.Fatalf("read work dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("work dir still holds %d file(s); the plaintext image survived the build", len(entries))
	}
}

func TestBuildRemovesIntermediatesOnFailure(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	work := filepath.Join(dir, "work")
	f := newFake()
	f.failOn = "veritysetup"

	if _, err := Build(t.Context(), BuildConfig{
		Source: src, Out: filepath.Join(dir, "vol.img"), Key: testKey(), WorkDir: work, Run: f.run,
	}); err == nil {
		t.Fatal("build succeeded despite veritysetup failing")
	}
	entries, _ := os.ReadDir(work)
	if len(entries) != 0 {
		t.Fatalf("failed build left %d file(s) behind", len(entries))
	}
}

// Replacing an existing image would destroy a volume whose key is already in
// the store, so the output is created O_EXCL.
func TestBuildRefusesToOverwriteExistingImage(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	out := filepath.Join(dir, "vol.img")
	if err := os.WriteFile(out, []byte("existing"), 0o600); err != nil {
		t.Fatalf("seed out: %v", err)
	}
	if _, err := Build(t.Context(), BuildConfig{Source: src, Out: out, Key: testKey(), Run: newFake().run}); err == nil {
		t.Fatal("build overwrote an existing image")
	}
}

func TestBuildRejectsUnalignedErofsImage(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	f := newFake()
	f.dataBytes = VerityBlockSize + 7
	if _, err := Build(t.Context(), BuildConfig{
		Source: src, Out: filepath.Join(dir, "vol.img"), Key: testKey(), Run: f.run,
	}); err == nil {
		t.Fatal("accepted an erofs image that is not block-aligned")
	}
}

func TestBuildRejectsMissingSource(t *testing.T) {
	dir := t.TempDir()
	if _, err := Build(t.Context(), BuildConfig{
		Source: filepath.Join(dir, "nope"), Out: filepath.Join(dir, "v.img"), Key: testKey(), Run: newFake().run,
	}); err == nil {
		t.Fatal("accepted a source directory that does not exist")
	}
}

func TestParseRootHash(t *testing.T) {
	good := hex.EncodeToString(mustSum("x"))
	got, err := parseRootHash([]byte("Root hash:\t" + strings.ToUpper(good) + "\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != good {
		t.Fatalf("root hash = %q, want lowercase %q", got, good)
	}
	for name, out := range map[string]string{
		"absent":    "VERITY header information\n",
		"truncated": "Root hash: abcd\n",
	} {
		if _, err := parseRootHash([]byte(out)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func mustSum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func TestBuildRejectsFileAsSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "weights.bin")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := Build(t.Context(), BuildConfig{
		Source: src, Out: filepath.Join(dir, "v.img"), Key: testKey(), Run: newFake().run,
	})
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("got %v, want a not-a-directory error", err)
	}
}

func TestBuildRejectsWrongKeyLength(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if _, err := Build(t.Context(), BuildConfig{
		Source: src, Out: filepath.Join(dir, "v.img"), Key: make([]byte, 32), Run: newFake().run,
	}); err == nil {
		t.Fatal("accepted a 32-byte key")
	}
}

// A work directory that cannot be created is reported before the build starts,
// rather than surfacing as a confusing failure from mkfs.erofs.
func TestBuildRejectsUnusableWorkDir(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Build(t.Context(), BuildConfig{
		Source: src, Out: filepath.Join(dir, "v.img"), Key: testKey(),
		WorkDir: filepath.Join(blocker, "under-a-file"), Run: newFake().run,
	}); err == nil {
		t.Fatal("accepted a work dir that cannot be created")
	}
}

func TestBuildFailsWhenErofsFails(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	f := newFake()
	f.failOn = "mkfs.erofs"
	if _, err := Build(t.Context(), BuildConfig{
		Source: src, Out: filepath.Join(dir, "v.img"), Key: testKey(), Run: f.run,
	}); err == nil {
		t.Fatal("build succeeded despite mkfs.erofs failing")
	}
}
