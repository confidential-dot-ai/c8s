package workloadclaims

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

// pidRecordingResolver records the peer PID the inventory resolved and returns
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

// TestInventoryUnixSocketBindsCaller proves the identity path: over a unix
// socket the inventory sees the kernel-reported PID of the caller (this test
// process), never a caller-supplied identity.
func TestInventoryUnixSocketBindsCaller(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &pidRecordingResolver{containers: []Container{{Name: "app", Digest: digestA}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, resolver, nil) }()

	got, err := Fetch(context.Background(), "unix://"+sock, 5*time.Second)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 1 || got[0].Digest != digestA {
		t.Fatalf("containers = %v", got)
	}
	if resolver.pid != os.Getpid() {
		t.Fatalf("inventory saw peer pid %d, want caller pid %d", resolver.pid, os.Getpid())
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

// A TCP conn carries no peer credentials, so the resolver is called with pid 0
// and the node-CVM inventory rejects it. Driven with a plain GET, not Fetch: Fetch
// is unix-only by construction, and this is a server-side property.
func TestInventoryLoopbackHasNoPeerPID(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &pidRecordingResolver{pid: -1, containers: []Container{{Name: "app", Digest: digestB}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, l, resolver, nil) }()

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

// sandboxAwareResolver is a pidRecordingResolver that additionally implements
// SandboxResolver, like the node-CVM inventory.
type sandboxAwareResolver struct {
	pidRecordingResolver
	sandboxID  string
	sandboxErr error
	digests    map[string][]string // sandboxID -> digests
}

func (r *sandboxAwareResolver) SandboxForPeer(peerPID int) (string, error) {
	r.pid = peerPID
	return r.sandboxID, r.sandboxErr
}

func (r *sandboxAwareResolver) DigestsForSandbox(sandboxID string) ([]string, bool, error) {
	d, ok := r.digests[sandboxID]
	return d, ok, nil
}

func serveInventory(t *testing.T, resolver Resolver, signer *SandboxTokenSigner) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = Serve(ctx, l, resolver, signer) }()
	return sock
}

func testSigner(t *testing.T) *SandboxTokenSigner {
	t.Helper()
	signer, err := NewSandboxTokenSigner(func(context.Context, []byte) (string, error) {
		return "test-ear", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func testRequesterKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// inventoryGetRaw GETs an inventory route over the unix socket and returns status and
// body — for routes the typed fetch helpers don't wrap (the /digests listing).
func inventoryGetRaw(t *testing.T, sock, route string) (int, string) {
	t.Helper()
	resp, err := inventoryDo(context.Background(), "unix://"+sock, http.MethodGet, route, nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// testNonce stands in for the single-use CDS challenge get-cert would pass to
// the inventory and CDS would re-check.
var testNonce = []byte("c8s-test-challenge-nonce")

// TestSandboxTokenRoute: POST /sandbox binds the kernel-reported caller to a
// signed token carrying the resolver's sandbox ID, the requester-key digest,
// the request nonce, and the inventory's EAR — verifiable against the signer's
// key and that nonce.
func TestSandboxTokenRoute(t *testing.T) {
	resolver := &sandboxAwareResolver{sandboxID: "sandbox-1"}
	signer := testSigner(t)
	sock := serveInventory(t, resolver, signer)
	requester := testRequesterKey(t)

	token, err := FetchSandboxToken(context.Background(), "unix://"+sock, 5*time.Second, &requester.PublicKey, testNonce)
	if err != nil {
		t.Fatalf("fetch sandbox token: %v", err)
	}
	if resolver.pid != os.Getpid() {
		t.Fatalf("inventory saw peer pid %d, want caller pid %d", resolver.pid, os.Getpid())
	}
	if token.EAR != "test-ear" {
		t.Fatalf("EAR = %q, want the inventory credential", token.EAR)
	}
	sandboxID, err := token.Verify(signer.PublicKey(), &requester.PublicKey, testNonce)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if sandboxID != "sandbox-1" {
		t.Fatalf("sandbox = %q, want sandbox-1", sandboxID)
	}

	// The token is bound to the requester key: any other key must fail.
	other := testRequesterKey(t)
	if _, err := token.Verify(signer.PublicKey(), &other.PublicKey, testNonce); err == nil {
		t.Fatal("token verified for a different requester key")
	}
	// And to the inventory key: any other signer must fail.
	if _, err := token.Verify(testSigner(t).PublicKey(), &requester.PublicKey, testNonce); err == nil {
		t.Fatal("token verified against a different inventory key")
	}
	// And to the request nonce: a token minted for one challenge must not
	// verify against another (freshness / anti-replay).
	if _, err := token.Verify(signer.PublicKey(), &requester.PublicKey, []byte("some-other-challenge")); err == nil {
		t.Fatal("token verified against a different challenge nonce")
	}
	// A missing challenge fails closed rather than skipping the freshness check.
	if _, err := token.Verify(signer.PublicKey(), &requester.PublicKey, nil); err == nil {
		t.Fatal("token verified with no challenge")
	}
}

// A tampered token body fails the signature; a correctly-signed token whose
// embedded nonce differs from the request's challenge fails the freshness
// check even with a valid signature.
func TestSandboxTokenVerifyFailsClosed(t *testing.T) {
	signer := testSigner(t)
	requester := testRequesterKey(t)
	keyDigest, err := RequesterKeyDigest(&requester.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.Sign(context.Background(), "sandbox-1", keyDigest, testNonce)
	if err != nil {
		t.Fatal(err)
	}

	tampered := *token
	tampered.Token = append([]byte(nil), token.Token...)
	tampered.Token[len(tampered.Token)-1] ^= 0xff
	if _, err := tampered.Verify(signer.PublicKey(), &requester.PublicKey, testNonce); err == nil {
		t.Fatal("tampered token verified")
	}

	// A validly-signed token carrying a stale nonce must be rejected when
	// checked against the current request's challenge.
	der, err := asn1.Marshal(sandboxTokenASN1{
		Version:   sandboxTokenVersion,
		SandboxID: "sandbox-1",
		KeyDigest: keyDigest,
		Nonce:     []byte("stale-challenge"),
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, signer.key, sandboxTokenSigningHash(der))
	if err != nil {
		t.Fatal(err)
	}
	stale := &SignedSandboxToken{Token: der, Signature: sig, EAR: "test-ear"}
	if _, err := stale.Verify(signer.PublicKey(), &requester.PublicKey, testNonce); err == nil {
		t.Fatal("token carrying a stale nonce verified against the current challenge")
	}
}

// Sign rejects an empty or over-long nonce so a hostile POST /sandbox body
// cannot mint a nonce-free token or bloat the signed structure.
func TestSignRejectsBadNonce(t *testing.T) {
	signer := testSigner(t)
	keyDigest := []byte("00000000000000000000000000000000")
	if _, err := signer.Sign(context.Background(), "sandbox-1", keyDigest, nil); err == nil {
		t.Fatal("signed a token with an empty nonce")
	}
	if _, err := signer.Sign(context.Background(), "sandbox-1", keyDigest, make([]byte, maxNonceLen+1)); err == nil {
		t.Fatal("signed a token with an over-long nonce")
	}
}

// An inventory without SandboxResolver has no sandbox routes; FetchSandboxToken
// maps that to ErrSandboxUnsupported so get-cert can issue without a sandbox
// ID instead of failing closed. A SandboxResolver without a signer serves the
// digests route but not the token route (an unverifiable token is worse than
// none).
func TestSandboxRouteAbsentWithoutResolverOrSigner(t *testing.T) {
	requester := testRequesterKey(t)
	sock := serveInventory(t, &pidRecordingResolver{}, testSigner(t))
	if _, err := FetchSandboxToken(context.Background(), "unix://"+sock, 5*time.Second, &requester.PublicKey, testNonce); !errors.Is(err, ErrSandboxUnsupported) {
		t.Fatalf("err = %v, want ErrSandboxUnsupported (no sandbox resolver)", err)
	}
	if status, _ := inventoryGetRaw(t, sock, SandboxDigestsPrefix+"any"); status != http.StatusNotFound {
		t.Fatalf("digests route status = %d, want 404 when resolver has no sandbox surface", status)
	}

	sock = serveInventory(t, &sandboxAwareResolver{sandboxID: "sandbox-1"}, nil)
	if _, err := FetchSandboxToken(context.Background(), "unix://"+sock, 5*time.Second, &requester.PublicKey, testNonce); !errors.Is(err, ErrSandboxUnsupported) {
		t.Fatalf("err = %v, want ErrSandboxUnsupported (no signer)", err)
	}
}

// A resolution failure (unknown caller) and a failing EAR source must stay
// fail-closed, distinct from the route-absent case above.
func TestSandboxTokenFailuresAreClosed(t *testing.T) {
	requester := testRequesterKey(t)

	sock := serveInventory(t, &sandboxAwareResolver{sandboxErr: fmt.Errorf("unknown caller")}, testSigner(t))
	_, err := FetchSandboxToken(context.Background(), "unix://"+sock, 5*time.Second, &requester.PublicKey, testNonce)
	if err == nil || errors.Is(err, ErrSandboxUnsupported) {
		t.Fatalf("err = %v, want a hard failure (resolver error)", err)
	}

	noEAR, err := NewSandboxTokenSigner(func(context.Context, []byte) (string, error) {
		return "", fmt.Errorf("CDS unreachable")
	})
	if err != nil {
		t.Fatal(err)
	}
	sock = serveInventory(t, &sandboxAwareResolver{sandboxID: "sandbox-1"}, noEAR)
	_, err = FetchSandboxToken(context.Background(), "unix://"+sock, 5*time.Second, &requester.PublicKey, testNonce)
	if err == nil || errors.Is(err, ErrSandboxUnsupported) {
		t.Fatalf("err = %v, want a hard failure (EAR source error)", err)
	}
}

// A caller that sends no nonce is rejected at the route, before signing.
func TestSandboxTokenRouteRejectsMissingNonce(t *testing.T) {
	requester := testRequesterKey(t)
	sock := serveInventory(t, &sandboxAwareResolver{sandboxID: "sandbox-1"}, testSigner(t))
	if _, err := FetchSandboxToken(context.Background(), "unix://"+sock, 5*time.Second, &requester.PublicKey, nil); err == nil {
		t.Fatal("inventory signed a token for a request with no nonce")
	}
}

func TestSandboxDigestsRoute(t *testing.T) {
	resolver := &sandboxAwareResolver{digests: map[string][]string{
		"sandbox-1": {digestA, digestB},
		"sandbox-2": nil,
	}}
	sock := serveInventory(t, resolver, nil)

	status, body := inventoryGetRaw(t, sock, SandboxDigestsPrefix+"sandbox-1")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var out SandboxDigestsResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Digests) != 2 || out.Digests[0] != digestA || out.Digests[1] != digestB {
		t.Fatalf("digests = %v", out.Digests)
	}

	// A known sandbox with no containers answers {"digests": []}, never null.
	status, body = inventoryGetRaw(t, sock, SandboxDigestsPrefix+"sandbox-2")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if want := "{\"digests\":[]}\n"; body != want {
		t.Fatalf("body = %q, want %q", body, want)
	}

	if status, _ := inventoryGetRaw(t, sock, SandboxDigestsPrefix+"nope"); status != http.StatusNotFound {
		t.Fatalf("unknown sandbox status = %d, want 404", status)
	}
}

// Fetch must be unable to reach anything but the baked unix socket — that is
// what keeps the inventory un-redirectable (docs/getcert-workload-binding.md,
// Corner 5).
func TestFetchRejectsNonUnixEndpoint(t *testing.T) {
	for _, ep := range []string{
		"http://127.0.0.1:8080",
		"https://inventory.example",
		"/run/c8s/workload-claims/workload-claims.sock",
		"",
	} {
		if _, err := Fetch(context.Background(), ep, time.Second); err == nil {
			t.Fatalf("endpoint %q accepted; only unix:// may be dialed", ep)
		}
	}
}

func TestInventoryResolverErrorFailsClosed(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &pidRecordingResolver{err: fmt.Errorf("unknown caller")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, l, resolver, nil) }()

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
	// are 64-hex, sandbox first. The inventory skips it by picking the shallowest
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
	// must appear AFTER the caller's own, so a shallowest-tracked inventory never
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

// The inventory runs as root but get-cert connects non-root, so ListenUnix must
// group-own the socket (0660 + chgrp) for the caller to reach it — the exact
// permission the same-process inventory tests can't exercise. Chgrp to our own gid
// (InventorySocketGID needs root); this still proves ListenUnix applies the group.
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
