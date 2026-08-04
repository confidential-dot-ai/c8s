package volume

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// saltBytes is the dm-verity salt length. Fixed, and generated per build: the
// salt is not secret, but a per-image one keeps two volumes built from the same
// directory from sharing a hash tree.
const saltBytes = 32

// Runner executes one build tool. It exists so the orchestration is testable
// without erofs-utils and cryptsetup on the machine running the tests.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// execRunner runs a tool for real, with SOURCE_DATE_EPOCH pinned so mkfs.erofs
// does not stamp the current time into the image.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=0", "TZ=UTC", "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// BuildConfig describes one image build.
type BuildConfig struct {
	// Source is the directory whose contents become the volume.
	Source string
	// Out is where the encrypted image is written. It must not already exist.
	Out string
	// Key is the XTS key; GenerateKey supplies it.
	Key []byte
	// WorkDir holds the intermediate plaintext image and hash tree. Empty uses
	// a temp dir. Both intermediates are removed on the way out, whatever
	// happens — they are the plaintext this whole design exists to protect.
	WorkDir string
	// Run executes the build tools; nil uses execRunner.
	Run Runner
}

// Build packages Source into an erofs image, formats a dm-verity tree over it,
// concatenates the two, and encrypts the result to Out.
//
// The tree goes inside the encryption rather than outside it. A hash tree is a
// fingerprint of the plaintext, so leaving it in the clear would hand the host
// a way to identify the contents; and the root hash then commits to the data
// itself rather than to one encryption of it.
func Build(ctx context.Context, cfg BuildConfig) (Verity, error) {
	run := cfg.Run
	if run == nil {
		run = execRunner
	}
	if err := checkSource(cfg.Source); err != nil {
		return Verity{}, err
	}
	if len(cfg.Key) != KeyBytes {
		return Verity{}, fmt.Errorf("volume: key is %d bytes, want %d", len(cfg.Key), KeyBytes)
	}
	// O_EXCL on the output: a build that silently replaced an existing image
	// would destroy a volume whose key is already in the store.
	out, err := os.OpenFile(cfg.Out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Verity{}, fmt.Errorf("volume: create %s: %w", cfg.Out, err)
	}
	defer out.Close()

	work, cleanup, err := workDir(cfg.WorkDir)
	if err != nil {
		return Verity{}, err
	}
	defer cleanup()

	dataPath := filepath.Join(work, "data.erofs")
	treePath := filepath.Join(work, "hash.tree")
	// The erofs image is the plaintext this design exists to protect, so it goes
	// whether the build succeeds or not, and whether or not WorkDir was the
	// caller's (in which case removing the directory is not ours to do).
	defer func() {
		os.Remove(dataPath)
		os.Remove(treePath)
	}()

	if _, err := run(ctx, "mkfs.erofs", erofsArgs(dataPath, cfg.Source)...); err != nil {
		return Verity{}, err
	}
	dataSize, err := fileSize(dataPath)
	if err != nil {
		return Verity{}, err
	}
	if dataSize == 0 || dataSize%VerityBlockSize != 0 {
		return Verity{}, fmt.Errorf("volume: erofs image is %d bytes, not a multiple of %d", dataSize, VerityBlockSize)
	}

	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return Verity{}, fmt.Errorf("volume: generate verity salt: %w", err)
	}
	saltHex := hex.EncodeToString(salt)

	stdout, err := run(ctx, "veritysetup", verityArgs(dataPath, treePath, saltHex)...)
	if err != nil {
		return Verity{}, err
	}
	rootHash, err := parseRootHash(stdout)
	if err != nil {
		return Verity{}, err
	}

	v := Verity{
		RootHash:   rootHash,
		Salt:       saltHex,
		DataBlocks: dataSize / VerityBlockSize,
		HashOffset: dataSize,
	}
	if err := encryptConcat(out, cfg.Key, dataPath, treePath); err != nil {
		return Verity{}, err
	}
	return v, nil
}

// erofsArgs pins the inputs that would otherwise vary per build, so the same
// source directory yields the same image and therefore the same root hash.
//
// Ownership and mode are deliberately not normalized: they are preserved into
// the image and therefore covered by the root hash. Forcing them to root would
// make a 0600 source file unreadable to a non-root workload.
//
// Reproducibility across erofs-utils versions is NOT established — pin the tool
// version alongside this if you depend on it.
func erofsArgs(dest, source string) []string {
	return []string{
		"-U", "00000000-0000-0000-0000-000000000000",
		"-T", "0",
		dest, source,
	}
}

// verityArgs formats the tree with every parameter explicit and no superblock.
//
// --no-superblock is load-bearing: the opener passes it too and takes the
// geometry from the key blob instead. A superblock would be host-writable
// metadata read at open time, which is the thing omitting a LUKS header removed.
func verityArgs(data, tree, saltHex string) []string {
	return []string{
		"format", data, tree,
		"--no-superblock",
		"--hash", "sha256",
		"--format", "1",
		"--data-block-size", fmt.Sprint(VerityBlockSize),
		"--hash-block-size", fmt.Sprint(VerityBlockSize),
		"--salt", saltHex,
	}
}

var rootHashRE = regexp.MustCompile(`(?im)^Root hash:\s*([0-9a-fA-F]+)\s*$`)

func parseRootHash(veritysetupOutput []byte) (string, error) {
	m := rootHashRE.FindSubmatch(veritysetupOutput)
	if m == nil {
		return "", fmt.Errorf("volume: veritysetup printed no root hash: %s", strings.TrimSpace(string(veritysetupOutput)))
	}
	root := strings.ToLower(string(m[1]))
	if len(root) != verityHashBytes*2 {
		return "", fmt.Errorf("volume: veritysetup root hash is %d hex chars, want %d", len(root), verityHashBytes*2)
	}
	return root, nil
}

// encryptConcat encrypts data followed by tree as one stream, so sector indices
// — and therefore the XTS tweaks — run continuously across the join exactly as
// they will when the device is read.
func encryptConcat(out io.Writer, key []byte, dataPath, treePath string) error {
	data, err := os.Open(dataPath)
	if err != nil {
		return fmt.Errorf("volume: open erofs image: %w", err)
	}
	defer data.Close()
	tree, err := os.Open(treePath)
	if err != nil {
		return fmt.Errorf("volume: open hash tree: %w", err)
	}
	defer tree.Close()
	return Encrypt(out, io.MultiReader(data, tree), key)
}

func checkSource(source string) error {
	if source == "" {
		return fmt.Errorf("volume: --source is required")
	}
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("volume: --source: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("volume: --source %s is not a directory", source)
	}
	return nil
}

func fileSize(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("volume: stat %s: %w", path, err)
	}
	return uint64(info.Size()), nil
}

func workDir(configured string) (string, func(), error) {
	if configured != "" {
		if err := os.MkdirAll(configured, 0o700); err != nil {
			return "", nil, fmt.Errorf("volume: --work-dir: %w", err)
		}
		return configured, func() {}, nil
	}
	dir, err := os.MkdirTemp("", "c8s-volume-")
	if err != nil {
		return "", nil, fmt.Errorf("volume: create work dir: %w", err)
	}
	return dir, func() { os.RemoveAll(dir) }, nil
}
