package volumed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPodUID = "3f4a1b2c-5d6e-7f80-9a0b-1c2d3e4f5061"

// kubeletTree builds <root>/pods/<uid>/volumes/kubernetes.io~empty-dir and
// returns the root and that directory.
func kubeletTree(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join(root, "pods", testPodUID, emptyDirSubdir)
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return root, base
}

func TestTargetDirResolvesPodEmptyDir(t *testing.T) {
	root, base := kubeletTree(t)
	if err := os.Mkdir(filepath.Join(base, "c8s-volume-weights"), 0o755); err != nil {
		t.Fatalf("mkdir volume: %v", err)
	}

	f, err := TargetDir(root, testPodUID, "c8s-volume-weights")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	defer f.Close()
	if !strings.HasSuffix(f.Name(), "c8s-volume-weights") {
		t.Errorf("resolved %q", f.Name())
	}
	if ProcPath(f) == "" {
		t.Error("no proc path for the handle")
	}
}

// The calling pod owns the contents of its own emptyDir, so it can plant a
// symlink there. Following one would mount the decrypted volume wherever the
// pod pointed — its own rootfs, or another pod's directory.
func TestTargetDirRefusesSymlinkedVolume(t *testing.T) {
	root, base := kubeletTree(t)
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatalf("mkdir elsewhere: %v", err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(base, "c8s-volume-weights")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if _, err := TargetDir(root, testPodUID, "c8s-volume-weights"); err == nil {
		t.Fatal("followed a symlink out of the pod's emptyDir")
	}
}

// RESOLVE_NO_SYMLINKS stops link traversal but not "..", so the name is
// validated as a label before it is ever resolved.
func TestTargetDirRefusesTraversalInName(t *testing.T) {
	root, _ := kubeletTree(t)
	for _, name := range []string{"..", "../..", "a/b", "/abs", "c8s-volume-weights/../.."} {
		if _, err := TargetDir(root, testPodUID, name); err == nil {
			t.Errorf("name %q: accepted", name)
		}
	}
}

func TestTargetDirRefusesMalformedPodUID(t *testing.T) {
	root, _ := kubeletTree(t)
	for _, uid := range []string{
		"", "not-a-uuid", "../../etc",
		"3F4A1B2C-5D6E-7F80-9A0B-1C2D3E4F5061", // uppercase: kubelet writes lowercase
		"3f4a1b2c_5d6e_7f80_9a0b_1c2d3e4f5061", // cgroup spelling, not the directory's
	} {
		if _, err := TargetDir(root, uid, "c8s-volume-weights"); err == nil {
			t.Errorf("uid %q: accepted", uid)
		}
	}
}

func TestTargetDirRefusesNonDirectory(t *testing.T) {
	root, base := kubeletTree(t)
	if err := os.WriteFile(filepath.Join(base, "c8s-volume-weights"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := TargetDir(root, testPodUID, "c8s-volume-weights"); err == nil {
		t.Fatal("accepted a regular file as a mount target")
	}
}

func TestTargetDirRefusesUnknownPod(t *testing.T) {
	root, _ := kubeletTree(t)
	other := "99999999-8888-7777-6666-555555555555"
	if _, err := TargetDir(root, other, "c8s-volume-weights"); err == nil {
		t.Fatal("resolved a target for a pod with no kubelet directory")
	}
}

func TestTargetDirRefusesMissingVolumeDir(t *testing.T) {
	root, _ := kubeletTree(t)
	if _, err := TargetDir(root, testPodUID, "c8s-volume-absent"); err == nil {
		t.Fatal("resolved a volume directory that does not exist")
	}
}
