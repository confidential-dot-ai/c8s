package volume

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// fakeConfigfs builds a configfs root with the target stack already present,
// which is what the kernel provides once the modules are loaded.
func fakeConfigfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "target", "core"), 0o755); err != nil {
		t.Fatalf("mkdir target/core: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "target", "loopback"), 0o755); err != nil {
		t.Fatalf("mkdir target/loopback: %v", err)
	}
	return root
}

// imageFile writes a stand-in ciphertext image of a whole number of blocks.
func imageFile(t *testing.T, blocks int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vol.img")
	if err := os.WriteFile(path, make([]byte, blocks*VerityBlockSize), 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}
	return path
}

// noopModprobe stands in for loading the LIO modules, which a test machine has
// no business doing.
func noopModprobe(context.Context, string, ...string) ([]byte, error) { return nil, nil }

func testAttacher(t *testing.T) Attacher {
	t.Helper()
	// RemoveAll stands in for configfs freeing a group's attributes with its
	// directory, which plain rmdir on a temp dir will not do.
	return Attacher{Root: fakeConfigfs(t), SysRoot: t.TempDir(), Run: noopModprobe, RemoveGroup: os.RemoveAll}
}

// scsiAddress is the "host:channel:target" LIO publishes for a portal group.
const scsiAddress = "2:0:1"

// attachedDisk adds what the kernel publishes once a target carries a disk: the
// portal group's SCSI address, and the disk that address resolves to, held by
// the named devices.
func attachedDisk(t *testing.T, a Attacher, name string, holders ...string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(a.tpgt(name), "address"), []byte(scsiAddress+"\n"), 0o644); err != nil {
		t.Fatalf("write address: %v", err)
	}
	dir := filepath.Join(a.SysRoot, "class", "scsi_device", scsiAddress+":0", "device", "block", "sdb", "holders")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir holders: %v", err)
	}
	for _, h := range holders {
		if err := os.Mkdir(filepath.Join(dir, h), 0o755); err != nil {
			t.Fatalf("mkdir holder %s: %v", h, err)
		}
	}
}

func TestAttachBuildsTheBackstoreAndMapsIt(t *testing.T) {
	a := testAttacher(t)
	img := imageFile(t, 2)

	serial, err := a.Attach(context.Background(), "weights", img)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if serial != "c8s-vol-weights" {
		t.Fatalf("serial = %q, want c8s-vol-weights", serial)
	}

	store := filepath.Join(a.Root, "target", "core", lioHBA, "weights")
	// The serial is the whole point: it is what volumed matches on.
	got := readFile(t, filepath.Join(store, "wwn", "vpd_unit_serial"))
	if got != "c8s-vol-weights" {
		t.Errorf("vpd_unit_serial = %q, want c8s-vol-weights", got)
	}
	if got := readFile(t, filepath.Join(store, "enable")); got != "1" {
		t.Errorf("enable = %q, want 1", got)
	}
	control := readFile(t, filepath.Join(store, "control"))
	if !strings.Contains(control, "fd_dev_name="+img) {
		t.Errorf("control = %q, want it to name %s", control, img)
	}
	// Size must be the real one; a wrong size truncates or over-reads the volume.
	if !strings.Contains(control, "fd_dev_size=8192") {
		t.Errorf("control = %q, want fd_dev_size=8192", control)
	}

	// Without a LUN pointing at the backstore no disk appears at all.
	link := filepath.Join(a.Root, "target", "loopback", loopbackWWN("weights"), lioTPGT, "lun", "lun_0", "weights")
	dest, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("readlink %s: %v", link, err)
	}
	if dest != store {
		t.Errorf("lun points at %q, want %q", dest, store)
	}
	nexus := readFile(t, filepath.Join(a.Root, "target", "loopback", loopbackWWN("weights"), lioTPGT, "nexus"))
	if nexus != loopbackWWN("weights") {
		t.Errorf("nexus = %q, want %q", nexus, loopbackWWN("weights"))
	}
}

func TestAttachRefusesAnAlreadyAttachedVolume(t *testing.T) {
	a := testAttacher(t)
	img := imageFile(t, 1)
	if _, err := a.Attach(context.Background(), "weights", img); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if _, err := a.Attach(context.Background(), "weights", img); err == nil {
		t.Fatal("attached the same volume twice")
	}
}

// Two volumes on one node must not collide on the loopback target, or the
// second attach would land in the first's portal group.
func TestAttachGivesEachVolumeItsOwnTarget(t *testing.T) {
	a := testAttacher(t)
	if _, err := a.Attach(context.Background(), "weights", imageFile(t, 1)); err != nil {
		t.Fatalf("attach weights: %v", err)
	}
	if _, err := a.Attach(context.Background(), "cache", imageFile(t, 1)); err != nil {
		t.Fatalf("attach cache: %v", err)
	}
	if loopbackWWN("weights") == loopbackWWN("cache") {
		t.Fatal("two volumes share one loopback target")
	}
}

// A truncated copy is the failure this catches: attaching it would surface as a
// verity error on first read, which says nothing about what went wrong.
func TestAttachRejectsAPartialImage(t *testing.T) {
	a := testAttacher(t)
	path := filepath.Join(t.TempDir(), "short.img")
	if err := os.WriteFile(path, make([]byte, VerityBlockSize+17), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := a.Attach(context.Background(), "weights", path); err == nil {
		t.Fatal("accepted an image that is not a whole number of blocks")
	}
}

func TestAttachRejectsAnEmptyImage(t *testing.T) {
	a := testAttacher(t)
	path := filepath.Join(t.TempDir(), "empty.img")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := a.Attach(context.Background(), "weights", path); err == nil {
		t.Fatal("accepted a zero-length image")
	}
}

func TestAttachRejectsANameTheSerialCannotHold(t *testing.T) {
	a := testAttacher(t)
	if _, err := a.Attach(context.Background(), "thirteenchars", imageFile(t, 1)); err == nil {
		t.Fatal("accepted a name longer than the serial holds")
	}
}

// A failure partway must leave nothing behind: a half-built target would occupy
// the name while carrying no device, so the retry would refuse and there would
// be nothing to detach.
func TestAttachUnwindsWhatItBuiltOnFailure(t *testing.T) {
	a := testAttacher(t)
	// A directory where the symlink goes makes the final step fail.
	name := "weights"
	lun := filepath.Join(a.Root, "target", "loopback", loopbackWWN(name), lioTPGT, "lun", "lun_0", name)
	if err := os.MkdirAll(lun, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if _, err := a.Attach(context.Background(), name, imageFile(t, 1)); err == nil {
		t.Fatal("attach succeeded despite a blocked mapping")
	}
	store := filepath.Join(a.Root, "target", "core", lioHBA, name)
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Errorf("backstore survived a failed attach: %v", err)
	}
}

// A modprobe failure has to surface as itself: the absent target tree it leads
// to says nothing about the cause.
func TestAttachReportsAModuleThatWillNotLoad(t *testing.T) {
	a := testAttacher(t)
	a.Run = func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("modprobe: module not found")
	}
	_, err := a.Attach(context.Background(), "weights", imageFile(t, 1))
	if err == nil || !strings.Contains(err.Error(), lioModules[0]) {
		t.Fatalf("attach = %v, want an error naming %s", err, lioModules[0])
	}
}

// Loading the modules does not mount configfs, so the tree is checked separately.
func TestAttachReportsAnAbsentTargetTree(t *testing.T) {
	a := Attacher{Root: t.TempDir(), Run: noopModprobe, RemoveGroup: os.RemoveAll}
	_, err := a.Attach(context.Background(), "weights", imageFile(t, 1))
	if err == nil || !strings.Contains(err.Error(), "configfs") {
		t.Fatalf("attach = %v, want an error pointing at configfs", err)
	}
}

func TestAttachRejectsAnImageThatIsNotThere(t *testing.T) {
	a := testAttacher(t)
	if _, err := a.Attach(context.Background(), "weights", filepath.Join(t.TempDir(), "absent.img")); err == nil {
		t.Fatal("accepted an image that does not exist")
	}
}

func TestAttachRejectsADirectoryAsTheImage(t *testing.T) {
	a := testAttacher(t)
	if _, err := a.Attach(context.Background(), "weights", t.TempDir()); err == nil {
		t.Fatal("accepted a directory as the image")
	}
}

func TestDetachRemovesTheBackstoreAndTarget(t *testing.T) {
	a := testAttacher(t)
	if _, err := a.Attach(context.Background(), "weights", imageFile(t, 1)); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := a.Detach(context.Background(), "weights"); err != nil {
		t.Fatalf("detach: %v", err)
	}
	store := filepath.Join(a.Root, "target", "core", lioHBA, "weights")
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Errorf("backstore survived detach: %v", err)
	}
	target := filepath.Join(a.Root, "target", "loopback", loopbackWWN("weights"))
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("loopback target survived detach: %v", err)
	}
}

// The kernel unbinds a disk that is still open, leaving whatever held it mapping
// a device that no longer exists — volumed's dm-crypt target, in practice.
func TestDetachRefusesADiskSomethingHolds(t *testing.T) {
	a := testAttacher(t)
	if _, err := a.Attach(context.Background(), "weights", imageFile(t, 1)); err != nil {
		t.Fatalf("attach: %v", err)
	}
	attachedDisk(t, a, "weights", "dm-1")

	err := a.Detach(context.Background(), "weights")
	if !errors.Is(err, ErrInUse) {
		t.Fatalf("detach = %v, want ErrInUse", err)
	}
	if !strings.Contains(err.Error(), "dm-1") {
		t.Errorf("detach = %v, want it to name the holder", err)
	}
	// Refusing has to leave the volume usable, not half torn down.
	store := filepath.Join(a.Root, "target", "core", lioHBA, "weights")
	if _, err := os.Stat(store); err != nil {
		t.Errorf("refused detach removed the backstore: %v", err)
	}
	if _, err := os.Stat(a.tpgt("weights")); err != nil {
		t.Errorf("refused detach removed the portal group: %v", err)
	}
}

// A disk nothing has opened detaches.
func TestDetachRemovesADiskNothingHolds(t *testing.T) {
	a := testAttacher(t)
	if _, err := a.Attach(context.Background(), "weights", imageFile(t, 1)); err != nil {
		t.Fatalf("attach: %v", err)
	}
	attachedDisk(t, a, "weights")

	if err := a.Detach(context.Background(), "weights"); err != nil {
		t.Fatalf("detach: %v", err)
	}
	store := filepath.Join(a.Root, "target", "core", lioHBA, "weights")
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Errorf("backstore survived detach: %v", err)
	}
}

func TestDetachReportsAVolumeThatWasNeverAttached(t *testing.T) {
	a := testAttacher(t)
	err := a.Detach(context.Background(), "weights")
	if !errors.Is(err, ErrNotAttached) {
		t.Fatalf("detach = %v, want ErrNotAttached", err)
	}
}

func TestDetachRejectsANameTheSerialCannotHold(t *testing.T) {
	a := testAttacher(t)
	if err := a.Detach(context.Background(), "thirteenchars"); err == nil {
		t.Fatal("accepted a name longer than the serial holds")
	}
}

// A backstore the kernel refuses to release must be reported: the disk is still
// on the node, and reporting success would say otherwise.
func TestDetachReportsABackstoreItCannotRemove(t *testing.T) {
	a := testAttacher(t)
	if _, err := a.Attach(context.Background(), "weights", imageFile(t, 1)); err != nil {
		t.Fatalf("attach: %v", err)
	}
	store := filepath.Join(a.Root, "target", "core", lioHBA, "weights")
	a.RemoveGroup = func(path string) error {
		if path == store {
			return errors.New("device or resource busy")
		}
		return os.RemoveAll(path)
	}
	if err := a.Detach(context.Background(), "weights"); err == nil {
		t.Fatal("detach reported success for a backstore that survived")
	}
}

// Detach is also the cleanup for a failed attach, so it has to cope with a tree
// that is only partly there.
func TestDetachToleratesAPartialTree(t *testing.T) {
	a := testAttacher(t)
	store := filepath.Join(a.Root, "target", "core", lioHBA, "weights")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := a.Detach(context.Background(), "weights"); err != nil {
		t.Fatalf("detach: %v", err)
	}
}

func TestAttachIsRoundTrippable(t *testing.T) {
	a := testAttacher(t)
	img := imageFile(t, 1)
	for i := 0; i < 3; i++ {
		if _, err := a.Attach(context.Background(), "weights", img); err != nil {
			t.Fatalf("attach %d: %v", i, err)
		}
		if err := a.Detach(context.Background(), "weights"); err != nil {
			t.Fatalf("detach %d: %v", i, err)
		}
	}
}

// runVolumeCmd drives a command through cobra so flag handling and the printed
// result run exactly as they do for an operator on the node.
func runVolumeCmd(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// The serial is the operator's handle on the disk, so attach has to print it.
func TestAttachCmdPrintsTheSerialAndHowToConfirmIt(t *testing.T) {
	a := testAttacher(t)
	out, err := runVolumeCmd(t, newAttachCmd(a),
		"weights", "--config-root="+a.Root, "--image="+imageFile(t, 1))
	if err != nil {
		t.Fatalf("attach: %v (%s)", err, out)
	}
	if !strings.Contains(out, "c8s-vol-weights") {
		t.Errorf("output = %q, want the serial", out)
	}
	if !strings.Contains(out, "vpd_pg80") {
		t.Errorf("output = %q, want the confirmation hint", out)
	}
}

func TestAttachCmdEmitsJSON(t *testing.T) {
	a := testAttacher(t)
	out, err := runVolumeCmd(t, newAttachCmd(a),
		"weights", "--config-root="+a.Root, "--image="+imageFile(t, 1), "--json")
	if err != nil {
		t.Fatalf("attach: %v (%s)", err, out)
	}
	var got struct{ Name, Serial string }
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal %q: %v", out, err)
	}
	if got.Name != "weights" || got.Serial != "c8s-vol-weights" {
		t.Errorf("json = %+v, want weights/c8s-vol-weights", got)
	}
}

func TestAttachCmdRequiresAnImage(t *testing.T) {
	a := testAttacher(t)
	_, err := runVolumeCmd(t, newAttachCmd(a), "weights", "--config-root="+a.Root)
	if err == nil || !strings.Contains(err.Error(), "--image") {
		t.Fatalf("attach = %v, want an error naming --image", err)
	}
}

func TestAttachCmdReportsAFailedAttach(t *testing.T) {
	a := testAttacher(t)
	_, err := runVolumeCmd(t, newAttachCmd(a),
		"weights", "--config-root="+a.Root, "--image="+filepath.Join(t.TempDir(), "absent.img"))
	if err == nil {
		t.Fatal("attached an image that does not exist")
	}
}

func TestDetachCmdReportsWhatItRemoved(t *testing.T) {
	a := testAttacher(t)
	if _, err := runVolumeCmd(t, newAttachCmd(a),
		"weights", "--config-root="+a.Root, "--image="+imageFile(t, 1)); err != nil {
		t.Fatalf("attach: %v", err)
	}
	out, err := runVolumeCmd(t, newDetachCmd(a), "weights", "--config-root="+a.Root)
	if err != nil {
		t.Fatalf("detach: %v (%s)", err, out)
	}
	if !strings.Contains(out, "weights detached") {
		t.Errorf("output = %q, want it to name the volume", out)
	}
}

func TestDetachCmdReportsAVolumeThatWasNeverAttached(t *testing.T) {
	a := testAttacher(t)
	_, err := runVolumeCmd(t, newDetachCmd(a), "weights", "--config-root="+a.Root)
	if !errors.Is(err, ErrNotAttached) {
		t.Fatalf("detach = %v, want ErrNotAttached", err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSpace(string(b))
}
