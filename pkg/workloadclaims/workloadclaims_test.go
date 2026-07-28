package workloadclaims

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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

// testAddr is a syntactically valid advertise address; the tests never dial it.
const testAddr = "10.0.0.7:9443"

// fakeResolver is a SandboxResolver test double that records the peer PID the
// inventory resolved.
type fakeResolver struct {
	pid        int
	sandboxID  string
	sandboxErr error
	digests    map[string][]string // sandboxID -> digests
}

func (r *fakeResolver) SandboxForPeer(peer Peer) (string, error) {
	r.pid = peer.PID()
	return r.sandboxID, r.sandboxErr
}

func (r *fakeResolver) DigestsForSandbox(sandboxID string) ([]string, bool, error) {
	d, ok := r.digests[sandboxID]
	return d, ok, nil
}

// serveTokens runs the token socket and returns its path.
func serveTokens(t *testing.T, resolver SandboxResolver, signer *SandboxTokenSigner) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ServeTokens(ctx, l, resolver, signer) }()
	return sock
}

// serveDigestsOnUnix runs the digests endpoint over a unix socket so the tests
// can exercise the handler without standing up RA-TLS. In production the
// listener is a mutually-attested TLS listener (see ServeDigests).
func serveDigestsOnUnix(t *testing.T, resolver SandboxResolver) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "digests.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ServeDigests(ctx, l, resolver) }()
	return sock
}

func testSigner(t *testing.T) *SandboxTokenSigner {
	t.Helper()
	signer, err := NewSandboxTokenSigner(func(context.Context, []byte) (string, error) {
		return "test-ear", nil
	}, testAddr)
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

// inventoryGetRaw GETs an inventory route over a unix socket and returns status
// and body — for routes the typed fetch helpers don't wrap (the /digests listing).
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
// signed token carrying the resolver's sandbox ID, the inventory address, the
// requester-key digest, the request nonce, and the inventory's EAR — verifiable
// against the signer's key and that nonce.
func TestSandboxTokenRoute(t *testing.T) {
	resolver := &fakeResolver{sandboxID: "sandbox-1"}
	signer := testSigner(t)
	sock := serveTokens(t, resolver, signer)
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
	sandbox, err := token.Verify(signer.PublicKey(), &requester.PublicKey, testNonce)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if sandbox.SandboxID != "sandbox-1" {
		t.Fatalf("sandbox = %q, want sandbox-1", sandbox.SandboxID)
	}
	// CDS reaches the inventory back at the address inside the signature, so a
	// hostile host cannot redirect the callback.
	if sandbox.InventoryAddr != testAddr {
		t.Fatalf("inventory addr = %q, want %q", sandbox.InventoryAddr, testAddr)
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

// A TCP conn carries no peer credentials, so the resolver is called with pid 0
// and the node-CVM inventory rejects it. This is why the token socket must stay
// unix-only.
func TestTokenRouteLoopbackHasNoPeerPID(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{pid: -1, sandboxID: "sandbox-1"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ServeTokens(ctx, l, resolver, testSigner(t)) }()

	requester := testRequesterKey(t)
	pubDER, err := x509.MarshalPKIXPublicKey(&requester.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(SandboxTokenRequest{PublicKey: pubDER, Nonce: testNonce})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post("http://"+l.Addr().String()+SandboxPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resolver.pid != 0 {
		t.Fatalf("loopback peer pid = %d, want 0 (no binding available)", resolver.pid)
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
		Version:       sandboxTokenVersion,
		SandboxID:     "sandbox-1",
		KeyDigest:     keyDigest,
		Nonce:         []byte("stale-challenge"),
		InventoryAddr: testAddr,
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

	// A signed token naming an unusable callback address is rejected: CDS would
	// have nowhere to resolve the sandbox's digests.
	bad, err := asn1.Marshal(sandboxTokenASN1{
		Version:       sandboxTokenVersion,
		SandboxID:     "sandbox-1",
		KeyDigest:     keyDigest,
		Nonce:         testNonce,
		InventoryAddr: "not-a-host-port",
	})
	if err != nil {
		t.Fatal(err)
	}
	badSig, err := ecdsa.SignASN1(rand.Reader, signer.key, sandboxTokenSigningHash(bad))
	if err != nil {
		t.Fatal(err)
	}
	badToken := &SignedSandboxToken{Token: bad, Signature: badSig, EAR: "test-ear"}
	if _, err := badToken.Verify(signer.PublicKey(), &requester.PublicKey, testNonce); err == nil {
		t.Fatal("token with a malformed inventory address verified")
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

// NewSandboxTokenSigner refuses an address CDS could not dial, so the failure
// surfaces at startup rather than as an unreachable callback at issuance.
func TestNewSandboxTokenSignerValidatesAddr(t *testing.T) {
	for _, addr := range []string{"", "nohost", "host:0", "host:99999", ":9443"} {
		if _, err := NewSandboxTokenSigner(func(context.Context, []byte) (string, error) {
			return "test-ear", nil
		}, addr); err == nil {
			t.Fatalf("addr %q accepted", addr)
		}
	}
}

// An inventory without a signer serves no token route; FetchSandboxToken maps
// that to ErrSandboxUnsupported so get-cert can issue without a sandbox ID
// instead of failing closed (an unverifiable token is worse than none).
func TestSandboxRouteAbsentWithoutSigner(t *testing.T) {
	requester := testRequesterKey(t)
	sock := serveTokens(t, &fakeResolver{sandboxID: "sandbox-1"}, nil)
	if _, err := FetchSandboxToken(context.Background(), "unix://"+sock, 5*time.Second, &requester.PublicKey, testNonce); !errors.Is(err, ErrSandboxUnsupported) {
		t.Fatalf("err = %v, want ErrSandboxUnsupported (no signer)", err)
	}
}

// The token socket must not serve the digests route: it is peer-credential
// bound for one caller, and answering for arbitrary sandboxes there would let
// any pod enumerate the node.
func TestTokenSocketDoesNotServeDigests(t *testing.T) {
	sock := serveTokens(t, &fakeResolver{sandboxID: "sandbox-1", digests: map[string][]string{"sandbox-1": {digestA}}}, testSigner(t))
	if status, _ := inventoryGetRaw(t, sock, SandboxDigestsPrefix+"sandbox-1"); status != http.StatusNotFound {
		t.Fatalf("digests route on the token socket = %d, want 404", status)
	}
}

// A resolution failure (unknown caller) and a failing EAR source must stay
// fail-closed, distinct from the route-absent case above.
func TestSandboxTokenFailuresAreClosed(t *testing.T) {
	requester := testRequesterKey(t)

	sock := serveTokens(t, &fakeResolver{sandboxErr: fmt.Errorf("unknown caller")}, testSigner(t))
	_, err := FetchSandboxToken(context.Background(), "unix://"+sock, 5*time.Second, &requester.PublicKey, testNonce)
	if err == nil || errors.Is(err, ErrSandboxUnsupported) {
		t.Fatalf("err = %v, want a hard failure (resolver error)", err)
	}

	noEAR, err := NewSandboxTokenSigner(func(context.Context, []byte) (string, error) {
		return "", fmt.Errorf("CDS unreachable")
	}, testAddr)
	if err != nil {
		t.Fatal(err)
	}
	sock = serveTokens(t, &fakeResolver{sandboxID: "sandbox-1"}, noEAR)
	_, err = FetchSandboxToken(context.Background(), "unix://"+sock, 5*time.Second, &requester.PublicKey, testNonce)
	if err == nil || errors.Is(err, ErrSandboxUnsupported) {
		t.Fatalf("err = %v, want a hard failure (EAR source error)", err)
	}
}

// A caller that sends no nonce is rejected at the route, before signing.
func TestSandboxTokenRouteRejectsMissingNonce(t *testing.T) {
	requester := testRequesterKey(t)
	sock := serveTokens(t, &fakeResolver{sandboxID: "sandbox-1"}, testSigner(t))
	if _, err := FetchSandboxToken(context.Background(), "unix://"+sock, 5*time.Second, &requester.PublicKey, nil); err == nil {
		t.Fatal("inventory signed a token for a request with no nonce")
	}
}

func TestSandboxDigestsRoute(t *testing.T) {
	resolver := &fakeResolver{digests: map[string][]string{
		"sandbox-1": {digestA, digestB},
		"sandbox-2": nil,
	}}
	sock := serveDigestsOnUnix(t, resolver)

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

// The digests endpoint must not mint tokens: it answers for any sandbox and is
// reachable over the network, so identity issuance there would be unbound.
func TestDigestsEndpointDoesNotServeTokens(t *testing.T) {
	sock := serveDigestsOnUnix(t, &fakeResolver{sandboxID: "sandbox-1"})
	requester := testRequesterKey(t)
	if _, err := FetchSandboxToken(context.Background(), "unix://"+sock, 5*time.Second, &requester.PublicKey, testNonce); !errors.Is(err, ErrSandboxUnsupported) {
		t.Fatalf("err = %v, want ErrSandboxUnsupported (digests endpoint mints no tokens)", err)
	}
}

// FetchSandboxToken must be unable to reach anything but the baked unix socket
// — that is what keeps the inventory un-redirectable
// (docs/getcert-workload-binding.md, Corner 5).
func TestFetchRejectsNonUnixEndpoint(t *testing.T) {
	requester := testRequesterKey(t)
	for _, ep := range []string{
		"http://127.0.0.1:8080",
		"https://inventory.example",
		"/run/c8s/workload-claims/workload-claims.sock",
		"",
	} {
		if _, err := FetchSandboxToken(context.Background(), ep, time.Second, &requester.PublicKey, testNonce); err == nil {
			t.Fatalf("endpoint %q accepted; only unix:// may be dialed", ep)
		}
	}
}

func TestValidateInventoryAddr(t *testing.T) {
	for _, ok := range []string{"10.0.0.1:9443", "node.example:443", "[::1]:9443"} {
		if err := ValidateInventoryAddr(ok); err != nil {
			t.Fatalf("addr %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "10.0.0.1", ":9443", "10.0.0.1:0", "10.0.0.1:70000", "10.0.0.1:http"} {
		if err := ValidateInventoryAddr(bad); err == nil {
			t.Fatalf("addr %q accepted", bad)
		}
	}
}

func TestResolveAdvertiseAddrPrefersExplicitHost(t *testing.T) {
	addr, err := ResolveAdvertiseAddr("10.1.2.3", 9443, "cds.invalid:8443")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "10.1.2.3:9443" {
		t.Fatalf("addr = %q, want 10.1.2.3:9443", addr)
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

// Both ends of the callback need an attestation-api URL to verify their peer
// against; without one ratls fails closed per connection, so it is rejected at
// construction instead of at the first issuance.
func TestDigestsCallbackRequiresAttestationApi(t *testing.T) {
	attest := func(context.Context, string) (string, error) { return "", nil }
	if _, _, err := DigestsServerTLSConfig("sev-snp", attest, "", nil, 0); err == nil {
		t.Fatal("server config built with no attestation-api URL")
	}
	if _, err := NewDigestsClient(context.Background(), "sev-snp", attest, "", nil, 0); err == nil {
		t.Fatal("client built with no attestation-api URL")
	}
}

// An empty measurement list is the dev opt-out, not a construction error: it
// yields a working, unpinned-but-attested peer on both ends.
func TestDigestsCallbackAcceptsEmptyMeasurements(t *testing.T) {
	attest := func(context.Context, string) (string, error) { return "", nil }
	if _, _, err := DigestsServerTLSConfig("sev-snp", attest, "http://127.0.0.1:8400", nil, 0); err != nil {
		t.Fatalf("server config rejected empty measurements: %v", err)
	}
}
