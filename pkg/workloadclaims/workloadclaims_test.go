package workloadclaims

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
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

func TestIsInjectedContainer(t *testing.T) {
	for name, want := range map[string]bool{
		"c8s-cert":      true,
		"c8s-cert-wait": true,
		"app":           false,
		"":              false,
	} {
		if got := IsInjectedContainer(name); got != want {
			t.Errorf("IsInjectedContainer(%q) = %t, want %t", name, got, want)
		}
	}
}

// The broker endpoint is a compiled constant, not control-plane input.
func TestBrokerEndpointBakedPath(t *testing.T) {
	if got := BrokerEndpoint(); got != "unix:///run/c8s/workload-claims/workload-claims.sock" {
		t.Fatalf("BrokerEndpoint = %q", got)
	}
}

func TestBuildConfigClaims(t *testing.T) {
	claims, err := BuildConfigClaims([]string{digestA}, []string{digestB})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(claims.OperatorKeysDigest, ratls.UnsetDigest()) || !bytes.Equal(claims.SeedDigest, ratls.UnsetDigest()) {
		t.Fatal("workload claims must carry the unset sentinel for operator-keys and seed")
	}
	if !bytes.Equal(claims.WorkloadDigest, mustDigest(t, []string{digestA}, []string{digestB})) {
		t.Fatal("workload digest does not match Digest(init, main)")
	}
	if _, err := BuildConfigClaims(nil, nil); err == nil {
		t.Fatal("both-empty image sets accepted")
	}
}

func TestVerifyWorkloadDigest(t *testing.T) {
	claimsDER := func(t *testing.T, c *ratls.ConfigClaims) []byte {
		t.Helper()
		ext, err := c.MarshalExtension()
		if err != nil {
			t.Fatal(err)
		}
		return ext.Value
	}
	claims, err := BuildConfigClaims([]string{digestA}, []string{digestB})
	if err != nil {
		t.Fatal(err)
	}
	der := claimsDER(t, claims)

	t.Run("matching lists verify and round-trip the claims", func(t *testing.T) {
		got, err := VerifyWorkloadDigest(der, []string{digestA}, []string{digestB})
		if err != nil {
			t.Fatalf("VerifyWorkloadDigest: %v", err)
		}
		if !bytes.Equal(got.WorkloadDigest, claims.WorkloadDigest) {
			t.Fatal("returned claims do not carry the attested workload digest")
		}
	})

	t.Run("swapped roles rejected", func(t *testing.T) {
		if _, err := VerifyWorkloadDigest(der, []string{digestB}, []string{digestA}); err == nil {
			t.Fatal("role-swapped lists matched the attested digest")
		}
	})

	t.Run("different images rejected", func(t *testing.T) {
		if _, err := VerifyWorkloadDigest(der, []string{digestA}, []string{digestA}); err == nil {
			t.Fatal("different image set matched the attested digest")
		}
	})

	t.Run("unparseable claims rejected", func(t *testing.T) {
		if _, err := VerifyWorkloadDigest([]byte("not-der"), []string{digestA}, nil); err == nil {
			t.Fatal("garbage DER accepted")
		}
	})

	t.Run("claims without workload digest rejected", func(t *testing.T) {
		none := &ratls.ConfigClaims{
			OperatorKeysDigest: ratls.UnsetDigest(),
			SeedDigest:         ratls.UnsetDigest(),
			WorkloadDigest:     ratls.UnsetDigest(),
		}
		if _, err := VerifyWorkloadDigest(claimsDER(t, none), []string{digestA}, nil); err == nil {
			t.Fatal("workload-less claims accepted")
		}
	})

	t.Run("governance claims rejected", func(t *testing.T) {
		governed := &ratls.ConfigClaims{
			OperatorKeysDigest: bytes.Repeat([]byte{0xEE}, ratls.ClaimsDigestSize),
			SeedDigest:         ratls.UnsetDigest(),
			WorkloadDigest:     claims.WorkloadDigest,
		}
		if _, err := VerifyWorkloadDigest(claimsDER(t, governed), []string{digestA}, []string{digestB}); err == nil {
			t.Fatal("operator-keys digest on a workload claim accepted")
		}
		seeded := &ratls.ConfigClaims{
			OperatorKeysDigest: ratls.UnsetDigest(),
			SeedDigest:         bytes.Repeat([]byte{0xEE}, ratls.ClaimsDigestSize),
			WorkloadDigest:     claims.WorkloadDigest,
		}
		if _, err := VerifyWorkloadDigest(claimsDER(t, seeded), []string{digestA}, []string{digestB}); err == nil {
			t.Fatal("seed digest on a workload claim accepted")
		}
	})
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

// A TCP conn carries no peer credentials, so the resolver is called with pid 0
// and the node-CVM broker rejects it. Driven with a plain GET, not Fetch: Fetch
// is unix-only by construction, and this is a server-side property.
func TestBrokerLoopbackHasNoPeerPID(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &pidRecordingResolver{pid: -1, containers: []Container{{Name: "app", Digest: digestB}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, l, resolver) }()

	resp, err := http.Get("http://" + l.Addr().String() + DigestsPath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resolver.pid != 0 {
		t.Fatalf("loopback peer pid = %d, want 0 (no binding available)", resolver.pid)
	}
}

// Fetch must be unable to reach anything but the baked unix socket — that is
// what keeps the broker un-redirectable (docs/getcert-workload-binding.md,
// Corner 5).
func TestFetchRejectsNonUnixEndpoint(t *testing.T) {
	for _, ep := range []string{
		"http://127.0.0.1:8080",
		"https://broker.example",
		"/run/c8s/workload-claims/workload-claims.sock",
		"",
	} {
		if _, err := Fetch(context.Background(), ep, time.Second); err == nil {
			t.Fatalf("endpoint %q accepted; only unix:// may be dialed", ep)
		}
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
		// Even with a resolvable /proc/0/cgroup: pid 0 means "no peer
		// credential" and must never bind to a container.
		writeCgroupFile(t, procRoot, 0, "0::/kubepods/besteffort/pod0/"+id+"\n")
		if _, err := ContainerIDCandidatesForPID(procRoot, 0); err == nil {
			t.Fatal("pid 0 accepted")
		}
	})
}

// The broker runs as root but get-cert connects non-root, so ListenUnix must
// group-own the socket (0660 + chgrp) for the caller to reach it, the exact
// permission the same-process broker tests can't exercise. Root chgrps to a
// group the socket would not otherwise get (BrokerSocketGID); non-root can only
// chgrp to its own gid, which still proves ListenUnix applies the group.
func TestListenUnixSetsModeAndGroup(t *testing.T) {
	gid := os.Getgid()
	if os.Getuid() == 0 {
		gid = BrokerSocketGID
	}
	sock := filepath.Join(t.TempDir(), "b.sock")
	l, err := ListenUnix(sock, gid)
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
	if int(st.Gid) != gid {
		t.Fatalf("socket gid = %d, want %d (ListenUnix must chgrp so a non-root caller in that group can connect)", st.Gid, gid)
	}
	if int(st.Uid) != os.Getuid() {
		t.Fatalf("socket uid = %d, want %d (chgrp must not change the owner)", st.Uid, os.Getuid())
	}
}

// With gid <= 0 the socket's group must be left exactly as the filesystem
// assigned it. A setgid parent directory makes that observable even as root:
// the socket inherits the directory's group, and any chown would change it.
func TestListenUnixGidZeroLeavesGroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to set up a setgid directory with a foreign group")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, -1, BrokerSocketGID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "b.sock")
	l, err := ListenUnix(sock, 0)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer l.Close()
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t on this platform")
	}
	if int(st.Gid) != BrokerSocketGID {
		t.Fatalf("socket gid = %d, want the setgid-inherited %d (gid 0 must mean no chgrp)", st.Gid, BrokerSocketGID)
	}
}

// A listener failing for any reason other than shutdown must surface the error.
func TestServeSurfacesListenerError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Serve(ctx, l, &pidRecordingResolver{}); err == nil {
		t.Fatal("Serve on a closed listener returned nil")
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
