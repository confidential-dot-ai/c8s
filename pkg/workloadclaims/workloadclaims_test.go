package workloadclaims

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func mustDigest(t *testing.T, init, main []string) []byte {
	t.Helper()
	d, err := Digest(init, main)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Order-independent WITHIN a role, duplicate- and case-insensitive.
func TestDigestCanonicalWithinRole(t *testing.T) {
	ab := mustDigest(t, nil, []string{digestA, digestB})
	ba := mustDigest(t, nil, []string{digestB, digestA})
	if !bytes.Equal(ab, ba) {
		t.Fatal("main digest depends on order")
	}
	dup := mustDigest(t, nil, []string{digestA, digestB, digestA})
	if !bytes.Equal(ab, dup) {
		t.Fatal("digest depends on duplicates")
	}
	upper := mustDigest(t, nil, []string{"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", digestB})
	if !bytes.Equal(ab, upper) {
		t.Fatal("digest depends on hex case")
	}
	if bytes.Equal(ab, mustDigest(t, nil, []string{digestA})) {
		t.Fatal("different sets digest identically")
	}
}

// The whole point of the split: init vs main roles are distinguished, so
// {init:A, main:B} and {init:B, main:A} differ even though the image *set* is
// equal. Restart churn within a role is still absorbed (tested above).
func TestDigestRoleDistinguishing(t *testing.T) {
	ab := mustDigest(t, []string{digestA}, []string{digestB})
	ba := mustDigest(t, []string{digestB}, []string{digestA})
	if bytes.Equal(ab, ba) {
		t.Fatal("swapping init/main roles did not change the digest")
	}
	// Same images, all main vs split, must also differ.
	allMain := mustDigest(t, nil, []string{digestA, digestB})
	if bytes.Equal(ab, allMain) {
		t.Fatal("init:A/main:B collides with main:{A,B}")
	}
}

func TestDigestFailsClosed(t *testing.T) {
	if _, err := Digest(nil, nil); err == nil {
		t.Fatal("both-empty accepted")
	}
	if _, err := Digest(nil, []string{"sha256:bad"}); err == nil {
		t.Fatal("malformed digest accepted")
	}
	// One role empty is fine (a pod may have no init containers).
	if _, err := Digest(nil, []string{digestA}); err != nil {
		t.Fatalf("main-only rejected: %v", err)
	}
}

func TestPartition(t *testing.T) {
	containers := []Container{
		{Name: "setup", Digest: digestA},
		{Name: "app", Digest: digestB},
	}
	init, main := Partition(containers, map[string]struct{}{"setup": {}})
	if len(init) != 1 || init[0] != digestA || len(main) != 1 || main[0] != digestB {
		t.Fatalf("partition = init %v main %v", init, main)
	}
	// No init names ⇒ everything is main.
	init, main = Partition(containers, nil)
	if len(init) != 0 || len(main) != 2 {
		t.Fatalf("no-init partition = init %v main %v", init, main)
	}
}

// pidRecordingResolver records the peer PID the broker resolved and returns
// fixed containers.
type pidRecordingResolver struct {
	pid        int
	containers []Container
	err        error
}

func (r *pidRecordingResolver) ContainersForPeer(peerPID int) ([]Container, error) {
	r.pid = peerPID
	return r.containers, r.err
}

// TestBrokerUnixSocketBindsCaller proves the identity path: over a unix
// socket the broker sees the kernel-reported PID of the caller (this test
// process), never a caller-supplied identity.
func TestBrokerUnixSocketBindsCaller(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &pidRecordingResolver{containers: []Container{{Name: "app", Digest: digestA}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, resolver) }()

	got, err := Fetch(context.Background(), "unix://"+sock, 5*time.Second)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 1 || got[0].Digest != digestA {
		t.Fatalf("containers = %v", got)
	}
	if resolver.pid != os.Getpid() {
		t.Fatalf("broker saw peer pid %d, want caller pid %d", resolver.pid, os.Getpid())
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

func TestBrokerLoopbackHasNoPeerPID(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &pidRecordingResolver{pid: -1, containers: []Container{{Name: "app", Digest: digestB}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, l, resolver) }()

	got, err := Fetch(context.Background(), "http://"+l.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 1 || got[0].Digest != digestB {
		t.Fatalf("containers = %v", got)
	}
	if resolver.pid != 0 {
		t.Fatalf("loopback peer pid = %d, want 0 (no binding available)", resolver.pid)
	}
}

func TestBrokerResolverErrorFailsClosed(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &pidRecordingResolver{err: fmt.Errorf("unknown caller")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, l, resolver) }()

	if _, err := Fetch(context.Background(), "unix://"+sock, 5*time.Second); err == nil {
		t.Fatal("resolver error did not fail the fetch")
	}
}

func writeCgroupFile(t *testing.T, procRoot string, pid int, body string) {
	t.Helper()
	dir := filepath.Join(procRoot, itoaTest(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoaTest(i int) string {
	return fmt.Sprintf("%d", i)
}

func TestContainerIDCandidatesForPID(t *testing.T) {
	procRoot := t.TempDir()
	id := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for name, cgroup := range map[string]string{
		"systemd driver":  "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1234.slice/cri-containerd-" + id + ".scope\n",
		"cgroupfs driver": "0::/kubepods/besteffort/podcafe/" + id + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			writeCgroupFile(t, procRoot, 42, cgroup)
			got, err := ContainerIDCandidatesForPID(procRoot, 42)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0] != id {
				t.Fatalf("candidates = %v, want [%s]", got, id)
			}
		})
	}

	// CRI-O nests the (untracked) sandbox ID above the container scope; both
	// are 64-hex, sandbox first. The broker skips it by picking the shallowest
	// *tracked* container, but the resolver must surface both, sandbox first.
	t.Run("crio sandbox then container, order preserved", func(t *testing.T) {
		sandbox := "1111111111111111111111111111111111111111111111111111111111111111"
		writeCgroupFile(t, procRoot, 44, "0::/kubepods/besteffort/pod9/crio-"+sandbox+"/crio-"+id+"\n")
		got, err := ContainerIDCandidatesForPID(procRoot, 44)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0] != sandbox || got[1] != id {
			t.Fatalf("candidates = %v, want [%s %s] (shallow→deep)", got, sandbox, id)
		}
	})

	// The nesting attack: a caller in its own container scope (attackerCID)
	// creates a child cgroup named with a victim's container ID. The victim ID
	// must appear AFTER the caller's own, so a shallowest-tracked broker never
	// resolves to the victim.
	t.Run("nested victim id comes after the real scope", func(t *testing.T) {
		attacker := "aaaa000000000000000000000000000000000000000000000000000000000000"
		victim := "bbbb000000000000000000000000000000000000000000000000000000000000"
		writeCgroupFile(t, procRoot, 45, "0::/kubepods/.../cri-containerd-"+attacker+".scope/"+victim+"\n")
		got, err := ContainerIDCandidatesForPID(procRoot, 45)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0] != attacker || got[1] != victim {
			t.Fatalf("candidates = %v, want attacker scope before nested victim", got)
		}
	})

	t.Run("no container cgroup", func(t *testing.T) {
		writeCgroupFile(t, procRoot, 43, "0::/system.slice/sshd.service\n")
		if _, err := ContainerIDCandidatesForPID(procRoot, 43); err == nil {
			t.Fatal("host process resolved to a container")
		}
	})

	t.Run("zero pid fails closed", func(t *testing.T) {
		if _, err := ContainerIDCandidatesForPID(procRoot, 0); err == nil {
			t.Fatal("pid 0 accepted")
		}
	})
}

// The broker runs as root but get-cert connects non-root, so ListenUnix must
// group-own the socket (0660 + chgrp) for the caller to reach it — the exact
// permission the same-process broker tests can't exercise. Chgrp to our own gid
// (BrokerSocketGID needs root); this still proves ListenUnix applies the group.
func TestListenUnixSetsModeAndGroup(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "b.sock")
	l, err := ListenUnix(sock, os.Getgid())
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer l.Close()

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %#o, want 0660", fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t on this platform")
	}
	if int(st.Gid) != os.Getgid() {
		t.Fatalf("socket gid = %d, want %d (ListenUnix must chgrp so a non-root caller in that group can connect)", st.Gid, os.Getgid())
	}
}

func TestListenUnixNoChgrpWhenGIDNonPositive(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "b.sock")
	l, err := ListenUnix(sock, 0)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer l.Close()
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %#o, want 0660", fi.Mode().Perm())
	}
}
