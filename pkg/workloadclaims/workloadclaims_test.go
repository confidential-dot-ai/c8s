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
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"unicode/utf8"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// testHost is a syntactically valid advertise host; the tests never dial it.
const testHost = "10.0.0.7"

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

func (r *fakeResolver) DigestsForSandbox(sandboxID string) ([]string, []SandboxContainer, bool, error) {
	d, ok := r.digests[sandboxID]
	cs := make([]SandboxContainer, 0, len(d))
	for _, dg := range d {
		cs = append(cs, SandboxContainer{Digest: dg})
	}
	return d, cs, ok, nil
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
	go func() { _ = ServeTokens(ctx, l, resolver, NewSignerHolder(signer)) }()
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
	go func() { _ = ServeDigests(ctx, l, resolver, []byte("test-identity")) }()
	return sock
}

func testSigner(t *testing.T) *SandboxTokenSigner {
	t.Helper()
	signer, err := NewSandboxTokenSigner(testHost)
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
	sandbox, err := token.Verify(signer.PublicKey(), &requester.PublicKey, testNonce)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if sandbox.SandboxID != "sandbox-1" {
		t.Fatalf("sandbox = %q, want sandbox-1", sandbox.SandboxID)
	}
	// CDS reaches the inventory back at the address inside the signature, so a
	// hostile host cannot redirect the callback.
	if sandbox.InventoryHost != testHost {
		t.Fatalf("inventory addr = %q, want %q", sandbox.InventoryHost, testHost)
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
	go func() { _ = ServeTokens(ctx, l, resolver, NewSignerHolder(testSigner(t))) }()

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
	token, err := signer.Sign("sandbox-1", keyDigest, testNonce)
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
		InventoryHost: testHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, signer.key, sandboxTokenSigningHash(der))
	if err != nil {
		t.Fatal(err)
	}
	stale := &SignedSandboxToken{Token: der, Signature: sig}
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
		InventoryHost: "not-an-ip",
	})
	if err != nil {
		t.Fatal(err)
	}
	badSig, err := ecdsa.SignASN1(rand.Reader, signer.key, sandboxTokenSigningHash(bad))
	if err != nil {
		t.Fatal(err)
	}
	badToken := &SignedSandboxToken{Token: bad, Signature: badSig}
	if _, err := badToken.Verify(signer.PublicKey(), &requester.PublicKey, testNonce); err == nil {
		t.Fatal("token with a malformed inventory address verified")
	}
}

// Sign rejects an empty or over-long nonce so a hostile POST /sandbox body
// cannot mint a nonce-free token or bloat the signed structure.
func TestSignRejectsBadNonce(t *testing.T) {
	signer := testSigner(t)
	keyDigest := []byte("00000000000000000000000000000000")
	if _, err := signer.Sign("sandbox-1", keyDigest, nil); err == nil {
		t.Fatal("signed a token with an empty nonce")
	}
	if _, err := signer.Sign("sandbox-1", keyDigest, make([]byte, maxNonceLen+1)); err == nil {
		t.Fatal("signed a token with an over-long nonce")
	}
}

// NewSandboxTokenSigner refuses a host CDS could not dial, so the failure
// surfaces at startup rather than as an unreachable callback at issuance.
func TestNewSandboxTokenSignerValidatesHost(t *testing.T) {
	for _, host := range []string{"", "nohost", "127.0.0.1", "10.0.0.1:9443"} {
		if _, err := NewSandboxTokenSigner(host); err == nil {
			t.Fatalf("host %q accepted", host)
		}
	}
}

// The identity route serves the signing key CDS resolves the token against.
// Serving it on the same privileged-port listener as the digests is what makes
// it an identity: a workload cannot bind the node's netns to answer here.
func TestServeDigestsServesIdentity(t *testing.T) {
	signer := testSigner(t)
	sock := serveDigestsOnUnix(t, &fakeResolver{sandboxID: "sandbox-1"})
	status, body := inventoryGetRaw(t, sock, IdentityPath)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var out InventoryIdentity
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.PublicKey, []byte("test-identity")) {
		t.Fatalf("identity = %x, want the served key", out.PublicKey)
	}
	_ = signer
}

// An inventory constructed without a signer answers the token route 404;
// FetchSandboxToken maps that to ErrSandboxUnsupported so get-cert can issue
// without a sandbox ID instead of failing closed (an unverifiable token is
// worse than none).
func TestSandboxRouteUnsupportedWithoutSigner(t *testing.T) {
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

// A resolution failure (unknown caller) stays fail-closed, distinct from the
// route-absent case above.
func TestSandboxTokenFailuresAreClosed(t *testing.T) {
	requester := testRequesterKey(t)

	sock := serveTokens(t, &fakeResolver{sandboxErr: fmt.Errorf("unknown caller")}, testSigner(t))
	_, err := FetchSandboxToken(context.Background(), "unix://"+sock, 5*time.Second, &requester.PublicKey, testNonce)
	if err == nil || errors.Is(err, ErrSandboxUnsupported) {
		t.Fatalf("err = %v, want a hard failure (resolver error)", err)
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

// refreshResolver is a fakeResolver that also reports a refresh posture.
type refreshResolver struct {
	fakeResolver
	refresh  AllowlistRefresh
	reported bool
}

func (r *refreshResolver) AllowlistRefresh() (AllowlistRefresh, bool) {
	return r.refresh, r.reported
}

// A guest enforcing a frozen allowlist must say so on the one channel that
// leaves it: its journal is unreadable, so without this the state is invisible.
func TestSandboxDigestsReportsFrozenAllowlist(t *testing.T) {
	resolver := &refreshResolver{
		fakeResolver: fakeResolver{digests: map[string][]string{"sandbox-1": {digestA}}},
		refresh:      AllowlistRefresh{Enabled: false, Reason: "no measurement pinned", Entries: 3},
		reported:     true,
	}
	status, body := inventoryGetRaw(t, serveDigestsOnUnix(t, resolver), SandboxDigestsPrefix+"sandbox-1")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var out SandboxDigestsResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.AllowlistRefresh == nil {
		t.Fatal("allowlist_refresh absent; the frozen state never leaves the guest")
	}
	if out.AllowlistRefresh.Enabled || out.AllowlistRefresh.Reason != "no measurement pinned" || out.AllowlistRefresh.Entries != 3 {
		t.Fatalf("allowlist_refresh = %+v", *out.AllowlistRefresh)
	}
}

// An inventory with nothing to report must leave the field off the wire, so
// "cannot say" never serializes as "refresh disabled".
func TestSandboxDigestsOmitsUnreportedRefresh(t *testing.T) {
	for name, resolver := range map[string]SandboxResolver{
		"no reporter":    &fakeResolver{digests: map[string][]string{"sandbox-1": {digestA}}},
		"reports absent": &refreshResolver{fakeResolver: fakeResolver{digests: map[string][]string{"sandbox-1": {digestA}}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, body := inventoryGetRaw(t, serveDigestsOnUnix(t, resolver), SandboxDigestsPrefix+"sandbox-1")
			if strings.Contains(body, "allowlist_refresh") {
				t.Fatalf("body = %q, want no allowlist_refresh field", body)
			}
		})
	}
}

// The reason crosses a trust boundary from an inventory the client may not pin,
// so it must not be able to forge log lines or blow up a record.
func TestSafeReasonBoundsRemoteString(t *testing.T) {
	if got := safeReason("clean reason"); got != "clean reason" {
		t.Fatalf("safeReason mangled a clean string: %q", got)
	}
	if got := safeReason("a\nlevel=ERROR msg=forged\rb\x00c"); strings.ContainsAny(got, "\n\r\x00") {
		t.Fatalf("control characters survived: %q", got)
	}
	long := safeReason(strings.Repeat("é", 5000))
	if n := len([]rune(long)); n != maxReasonLen+1 {
		t.Fatalf("truncated to %d runes, want %d plus ellipsis", n, maxReasonLen)
	}
	if !utf8.ValidString(long) {
		t.Fatalf("truncation split a rune: %q", long)
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

// FetchSandboxToken must reach nothing but the two compiled endpoints, the
// baked unix socket and the guest loopback: that is what keeps the inventory
// un-redirectable (docs/getcert-workload-binding.md, Corner 5). Each of these
// must lose to the endpoint check, not to a failed connection.
func TestFetchRejectsNonCompiledEndpoint(t *testing.T) {
	requester := testRequesterKey(t)
	for _, ep := range []string{
		"http://127.0.0.1:9999",
		"http://localhost:8401",
		"https://inventory.example",
		"/run/c8s/workload-claims/workload-claims.sock",
		"",
	} {
		_, err := FetchSandboxToken(context.Background(), ep, time.Second, &requester.PublicKey, testNonce)
		if err == nil || !strings.Contains(err.Error(), "endpoint must be") {
			t.Fatalf("endpoint %q not refused by the compiled-endpoint check: %v", ep, err)
		}
	}
}

func TestValidateInventoryHost(t *testing.T) {
	for _, ok := range []string{"10.0.0.1", "192.0.2.5", "2001:db8::1"} {
		if err := ValidateInventoryHost(ok); err != nil {
			t.Fatalf("host %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "10.0.0.1:9443", "not-an-ip"} {
		if err := ValidateInventoryHost(bad); err == nil {
			t.Fatalf("host %q accepted", bad)
		}
	}
}

// A sandbox token is mintable by anything holding an /attest-key EAR, so the
// address it carries is attacker-chosen. These are the request-forgery targets
// that must never be dialable: the cloud metadata service, CDS's own loopback,
// and names that let DNS pick the destination after the check.
func TestInventoryAddrRejectsRequestForgeryTargets(t *testing.T) {
	for _, bad := range []string{
		"169.254.169.254", // cloud metadata (IMDS)
		"fe80::1",         // IPv6 link-local
		"127.0.0.1",       // CDS's own loopback
		"::1",             // IPv6 loopback
		"0.0.0.0",         // unspecified
		"::",              // IPv6 unspecified
		"224.0.0.1",       // multicast
		"metadata.google.internal",
		"localhost",
		"inventory.example", // any name: DNS could resolve anywhere
	} {
		if err := ValidateInventoryHost(bad); err == nil {
			t.Fatalf("request-forgery target %q accepted as an inventory host", bad)
		}
	}
}

// What gets dialed is rebuilt from the parsed IP and port, not passed through
// from the caller's bytes.
func TestParseInventoryHostNormalizes(t *testing.T) {
	got, err := parseInventoryHost("2001:0db8:0000::1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "2001:db8::1" {
		t.Fatalf("normalized host = %q, want the re-serialized form", got)
	}
}

// The node CIDRs are the boundary that stops a workload answering as its own
// node's inventory: a pod IP is outside them, so CDS never dials it.
func TestInventoryHostsBoundsTheCallback(t *testing.T) {
	hosts, err := ParseInventoryHosts([]string{"10.0.0.0/24", "192.168.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if !hosts.Contains("10.0.0.7") || !hosts.Contains("192.168.1.9") {
		t.Fatal("node address rejected")
	}
	for _, outside := range []string{"10.244.1.5", "172.16.0.1", "not-an-ip", ""} {
		if hosts.Contains(outside) {
			t.Fatalf("address %q outside the node CIDRs was accepted", outside)
		}
	}
	// Empty contains nothing, so an unconfigured CDS dials nowhere.
	if (CIDRHosts{}).Contains("10.0.0.7") {
		t.Fatal("empty CIDR set accepted an address")
	}
	if _, err := ParseInventoryHosts([]string{"nonsense"}); err == nil {
		t.Fatal("malformed CIDR accepted")
	}
}

// Fetch must reject a forged address before it opens any connection.
func TestFetchRejectsForgedAddrBeforeDialing(t *testing.T) {
	c := &DigestsClient{timeout: time.Second}
	if _, err := c.Fetch(context.Background(), "169.254.169.254", "sandbox-1"); err == nil {
		t.Fatal("Fetch dialed the metadata service")
	}
	if _, err := c.Fetch(context.Background(), "10.0.0.1", "../../etc/passwd"); err == nil {
		t.Fatal("Fetch accepted a sandbox ID that is not a sandbox ID")
	}
}

func TestResolveAdvertiseHostPrefersExplicitHost(t *testing.T) {
	host, err := ResolveAdvertiseHost(context.Background(), "10.1.2.3", "cds.invalid:8443")
	if err != nil {
		t.Fatal(err)
	}
	if host != "10.1.2.3" {
		t.Fatalf("host = %q, want 10.1.2.3", host)
	}
}

// An address CDS could never dial back is rejected where it is configured, so
// the inventory fails at startup instead of minting tokens that steer CDS
// somewhere useless.
func TestResolveAdvertiseHostRejectsUnreachableHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "169.254.169.254", "inventory.example"} {
		if _, err := ResolveAdvertiseHost(context.Background(), host, "cds.invalid:8443"); err == nil {
			t.Fatalf("advertise host %q accepted", host)
		}
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
		// Even with a resolvable /proc/0/cgroup: pid 0 means "no peer
		// credential" and must never bind to a container.
		writeCgroupFile(t, procRoot, 0, "0::/kubepods/besteffort/pod0/"+id+"\n")
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
	gid := os.Getgid()
	if os.Getuid() == 0 {
		gid = InventorySocketGID
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
	if err := os.Chown(dir, -1, InventorySocketGID); err != nil {
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
	if int(st.Gid) != InventorySocketGID {
		t.Fatalf("socket gid = %d, want the setgid-inherited %d (gid 0 must mean no chgrp)", st.Gid, InventorySocketGID)
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
	if err := ServeDigests(ctx, l, &fakeResolver{}, nil); err == nil {
		t.Fatal("ServeDigests on a closed listener returned nil")
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
	if _, _, err := DigestsServerTLSConfig("sev-snp", attest, "", ratls.Pins{}, 0); err == nil {
		t.Fatal("server config built with no attestation-api URL")
	}
	if _, err := NewDigestsClient(context.Background(), "sev-snp", attest, "", ratls.Pins{}, 0); err == nil {
		t.Fatal("client built with no attestation-api URL")
	}
}

// An empty measurement list is the dev opt-out, not a construction error: it
// yields a working, unpinned-but-attested peer on both ends.
func TestDigestsCallbackAcceptsEmptyMeasurements(t *testing.T) {
	attest := func(context.Context, string) (string, error) { return "", nil }
	if _, _, err := DigestsServerTLSConfig("sev-snp", attest, "http://127.0.0.1:8400", ratls.Pins{}, 0); err != nil {
		t.Fatalf("server config rejected empty measurements: %v", err)
	}
}

// ListenUnix must leave the socket reachable by the non-root get-cert sidecar
// and must not fail on a stale socket file from a previous run.
func TestListenUnixReplacesStaleSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "wc.sock")
	first, err := ListenUnix(sock, 0)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()

	// The file survives the close; a restart must reclaim it rather than
	// fail with EADDRINUSE.
	second, err := ListenUnix(sock, 0)
	if err != nil {
		t.Fatalf("stale socket not reclaimed: %v", err)
	}
	defer second.Close()

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v, want 0660", fi.Mode().Perm())
	}
}

// An unwritable directory fails closed rather than leaving the inventory
// silently unreachable.
func TestListenUnixFailsOnBadPath(t *testing.T) {
	if _, err := ListenUnix(filepath.Join(t.TempDir(), "no-such-dir", "wc.sock"), 0); err == nil {
		t.Fatal("listen succeeded on a nonexistent directory")
	}
}

// The host is read from unverified bytes purely to pick a dial target, so it
// must fail rather than return garbage when the token does not parse.
func TestUnverifiedInventoryHostRejectsGarbage(t *testing.T) {
	if _, err := UnverifiedInventoryHost([]byte("not-der")); err == nil {
		t.Fatal("garbage token yielded a host")
	}
}

// The token route rejects every malformed request before it reaches the
// resolver, so a hostile caller cannot drive the signer with garbage.
func TestServeTokensRejectsMalformedRequests(t *testing.T) {
	sock := serveTokens(t, &fakeResolver{sandboxID: "sandbox-1"}, testSigner(t))
	for _, tc := range []struct {
		name string
		body string
	}{
		{"not JSON", "{"},
		{"public key is not PKIX", `{"public_key":"bm90LWtleQ==","nonce":"AAAA"}`},
		{"missing nonce", `{"public_key":"","nonce":""}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := inventoryDo(context.Background(), "unix://"+sock, http.MethodPost, SandboxPath,
				bytes.NewReader([]byte(tc.body)), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("malformed request accepted (status %d)", resp.StatusCode)
			}
		})
	}
}

// The kata guest reaches its inventory on loopback, which is the second of the
// two compiled endpoints inventoryDo accepts. Nothing else is dialable, so no
// control-plane value can redirect the request.
func TestGuestInventoryEndpointIsDialable(t *testing.T) {
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoaTest(GuestTokenPort)))
	if err != nil {
		t.Skipf("guest token port %d unavailable here: %v", GuestTokenPort, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ServeTokens(ctx, l, &fakeResolver{sandboxID: "sandbox-1"}, NewSignerHolder(testSigner(t))) }()

	requester := testRequesterKey(t)
	token, err := FetchSandboxToken(ctx, GuestInventoryEndpoint(), 5*time.Second, &requester.PublicKey, testNonce)
	if err != nil {
		t.Fatalf("guest loopback fetch: %v", err)
	}
	sandbox, err := token.Verify(testSignerKeyFor(t, token), &requester.PublicKey, testNonce)
	if err == nil && sandbox.SandboxID != "sandbox-1" {
		t.Fatalf("sandbox = %q", sandbox.SandboxID)
	}
}

// testSignerKeyFor is a stand-in: the guest test only needs a key to drive
// Verify's signature branch, not a real inventory identity.
func testSignerKeyFor(t *testing.T, _ *SignedSandboxToken) *ecdsa.PublicKey {
	t.Helper()
	return testSigner(t).PublicKey()
}

// The high-water mark deduplicates on SandboxContainer.Key, so the key must be
// injective over (digest, argv): two distinct admissions that collide onto one
// key erase each other from the sandbox's record, and the erasure is invisible
// to CDS because it removes the container from both the digests and the
// containers view at once.
func TestSandboxContainerKeyIsInjective(t *testing.T) {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const other = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	argvs := [][]string{
		nil,
		{},
		{""},
		{"", ""},
		{"/app"},
		{"/app", "--serve"},
		// Separator smuggling: every byte an argv may legally carry, including
		// the unit and record separators an earlier key used.
		{"/app\x1f--serve"},
		{"/app\x1f", "-serve"},
		{"/app\x1e--serve"},
		{"/app --serve"},
		{"/app\t--serve"},
		{"/app\n--serve"},
		{"/app", "", "--serve"},
	}

	seen := map[string][]string{}
	for _, d := range []string{digest, other} {
		for _, argv := range argvs {
			c := SandboxContainer{Digest: d, Argv: argv}
			key := c.Key()
			if prev, dup := seen[key]; dup && !slices.Equal(prev, argv) {
				t.Fatalf("argv %q and %q collide on key %q", prev, argv, key)
			}
			seen[key] = argv
		}
	}
	// A digest change must move the key too.
	a := SandboxContainer{Digest: digest, Argv: []string{"/app"}}
	b := SandboxContainer{Digest: other, Argv: []string{"/app"}}
	if a.Key() == b.Key() {
		t.Fatal("two digests share one key")
	}
	// nil and empty argv are the same admission (json omits an empty list).
	if (SandboxContainer{Digest: digest}).Key() != (SandboxContainer{Digest: digest, Argv: []string{}}).Key() {
		t.Fatal("nil and empty argv must key alike")
	}
}

// serveTokensWithHolder runs the token route against a holder the test drives,
// so the pending window can be exercised the way a booting guest hits it.
func serveTokensWithHolder(t *testing.T, resolver SandboxResolver, signers *SignerHolder) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "wc.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ServeTokens(ctx, l, resolver, signers) }()
	return sock
}

// The route exists before its signer does, because under kata the listener has
// to claim the port before any workload container could. "Not yet" must be
// distinguishable from "never": issuing without a sandbox ID binds the sandbox
// in CDS's ledger first-write-wins, so a caller that gives up early is stuck
// with that binding.
func TestPendingSignerIsRetryableNotUnsupported(t *testing.T) {
	signers := NewPendingSignerHolder()
	sock := serveTokensWithHolder(t, &fakeResolver{sandboxID: "sandbox-1"}, signers)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = FetchSandboxToken(context.Background(), "unix://"+sock, time.Second, key.Public(), []byte("nonce"))
	if !errors.Is(err, ErrSandboxNotReady) {
		t.Fatalf("err = %v, want ErrSandboxNotReady while the signer is pending", err)
	}

	// Once installed, the same route answers without the caller reconnecting
	// to anything new.
	signers.Set(testSigner(t))
	token, err := FetchSandboxToken(context.Background(), "unix://"+sock, time.Second, key.Public(), []byte("nonce"))
	if err != nil {
		t.Fatalf("after Set: %v", err)
	}
	if len(token.Token) == 0 {
		t.Fatal("empty token after the signer was installed")
	}
}

// A deployment that issues no tokens at all keeps answering 404, so a caller
// proceeds without a sandbox ID instead of waiting for a signer that is not
// coming. This is the node-CVM posture and must not change.
func TestDisabledSignerStaysUnsupported(t *testing.T) {
	signers := NewPendingSignerHolder()
	signers.Disable()
	sock := serveTokensWithHolder(t, &fakeResolver{sandboxID: "sandbox-1"}, signers)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = FetchSandboxToken(context.Background(), "unix://"+sock, time.Second, key.Public(), []byte("nonce"))
	if !errors.Is(err, ErrSandboxUnsupported) {
		t.Fatalf("err = %v, want ErrSandboxUnsupported for a disabled signer", err)
	}
}

// NewSignerHolder(nil) is the node-CVM construction path: no signer configured
// means unsupported, never pending.
func TestNilSignerHolderIsUnsupported(t *testing.T) {
	if h := NewSignerHolder(nil); h.Ready() {
		t.Fatal("nil signer reported ready")
	} else if _, state := h.current(); state != signerUnsupported {
		t.Fatalf("state = %v, want signerUnsupported", state)
	}
}
