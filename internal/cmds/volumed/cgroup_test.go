package volumed

import (
	"os"
	"path/filepath"
	"testing"
)

// procWith writes a fake /proc/<pid>/cgroup and returns the proc root.
func procWith(t *testing.T, pid int, content string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(content), 0o644); err != nil {
		t.Fatalf("write cgroup: %v", err)
	}
	return root
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

const wantUID = "3f4a1b2c-5d6e-7f80-9a0b-1c2d3e4f5061"

func TestPodFromSystemdDriver(t *testing.T) {
	const slice = "/kubepods.slice/kubepods-burstable.slice/" +
		"kubepods-burstable-pod3f4a1b2c_5d6e_7f80_9a0b_1c2d3e4f5061.slice"
	root := procWith(t, 42, "0::"+slice+
		"/cri-containerd-aaaabbbbccccddddeeeeffff00001111aaaabbbbccccddddeeeeffff00001111.scope\n")

	got, err := PodCandidatesForPID(root, 42)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// The systemd driver spells the UUID with underscores; the kubelet pod
	// directory uses dashes, and that directory is what the UID is for.
	if len(got) != 1 || got[0].UID != wantUID {
		t.Fatalf("got %v, want one candidate for %s", got, wantUID)
	}
	// The path stops at the pod slice: the container scope beneath it goes when
	// the container does, which is not the same as the pod going.
	if got[0].Path != slice {
		t.Fatalf("path = %q, want %q", got[0].Path, slice)
	}
}

func TestPodFromCgroupfsDriver(t *testing.T) {
	const slice = "/kubepods/besteffort/pod" + wantUID
	const scope = slice + "/aaaabbbbccccddddeeeeffff00001111aaaabbbbccccddddeeeeffff00001111"
	root := procWith(t, 7, "11:devices:"+scope+"\n0::"+scope+"\n")

	got, err := PodCandidatesForPID(root, 7)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// The same UID on every cgroup v1 controller line is one candidate.
	if len(got) != 1 || got[0].UID != wantUID {
		t.Fatalf("got %v, want one candidate for %s", got, wantUID)
	}
	if got[0].Path != slice {
		t.Fatalf("path = %q, want %q", got[0].Path, slice)
	}
}

// On a node with v1 controllers alongside the unified hierarchy, the path must
// come from the unified line: a v1 path is relative to a per-controller subtree
// and would not resolve under the single cgroup root the reaper stats.
func TestPodPrefersTheUnifiedLine(t *testing.T) {
	const unified = "/kubepods.slice/kubepods-pod3f4a1b2c_5d6e_7f80_9a0b_1c2d3e4f5061.slice"
	root := procWith(t, 21, "11:devices:/kubepods/pod"+wantUID+"\n0::"+unified+"\n")

	got, err := PodCandidatesForPID(root, 21)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 1 || got[0].Path != unified {
		t.Fatalf("got %v, want the unified path %q", got, unified)
	}
}

// A process can only move itself deeper into cgroups it creates, so its
// runtime-assigned pod slice is always the shallowest. If a nested cgroup named
// after a victim's UID came first, the agent would mount that pod's decrypted
// volume into the attacker's own directory.
func TestPodCandidatesAreShallowestFirst(t *testing.T) {
	const victim = "99999999-8888-7777-6666-555555555555"
	root := procWith(t, 9, "0::/kubepods.slice/kubepods-burstable.slice/"+
		"kubepods-burstable-pod3f4a1b2c_5d6e_7f80_9a0b_1c2d3e4f5061.slice/"+
		"cri-containerd-aaaabbbbccccddddeeeeffff00001111aaaabbbbccccddddeeeeffff00001111.scope/"+
		"pod"+victim+"/nested\n")

	got, err := PodCandidatesForPID(root, 9)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v, want two candidates", got)
	}
	if got[0].UID != wantUID {
		t.Fatalf("shallowest candidate is %q, want the runtime-assigned %q", got[0].UID, wantUID)
	}
	if got[1].UID != victim {
		t.Fatalf("second candidate is %q, want the nested %q", got[1].UID, victim)
	}
}

func TestPodRejectsProcessWithNoPodCgroup(t *testing.T) {
	root := procWith(t, 3, "0::/system.slice/sshd.service\n")
	if _, err := PodCandidatesForPID(root, 3); err == nil {
		t.Fatal("accepted a process outside any pod")
	}
}

func TestPodRejectsMissingPeer(t *testing.T) {
	if _, err := PodCandidatesForPID(t.TempDir(), 0); err == nil {
		t.Fatal("accepted a zero PID (no peer credentials)")
	}
	if _, err := PodCandidatesForPID(t.TempDir(), 1234); err == nil {
		t.Fatal("accepted a PID with no cgroup file")
	}
}

// A UID-shaped string that is not a pod slice must not be picked up: the
// pattern anchors on the "pod" prefix the runtime writes.
func TestPodIgnoresNonPodComponents(t *testing.T) {
	root := procWith(t, 11, "0::/kubepods.slice/notapod-"+wantUID+".slice\n")
	if _, err := PodCandidatesForPID(root, 11); err == nil {
		t.Fatal("matched a component that is not a pod slice")
	}
}

// A line that is not "hierarchy:controllers:path" carries no path to read.
func TestPodIgnoresAMalformedLine(t *testing.T) {
	root := procWith(t, 13, "not-a-cgroup-line\n")
	if _, err := PodCandidatesForPID(root, 13); err == nil {
		t.Fatal("read a pod out of a malformed cgroup line")
	}
}

func TestNormalizePodUID(t *testing.T) {
	for in, want := range map[string]string{
		"3F4A1B2C_5D6E_7F80_9A0B_1C2D3E4F5061": wantUID,
		wantUID:                                wantUID,
	} {
		if got := normalizePodUID(in); got != want {
			t.Errorf("normalizePodUID(%q) = %q, want %q", in, got, want)
		}
	}
}
