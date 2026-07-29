package volumed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

type fakeIdentity struct {
	podUID, sandboxID string
	err               error
}

func (f fakeIdentity) Resolve(workloadclaims.Peer) (string, string, error) {
	return f.podUID, f.sandboxID, f.err
}

type fakeDevices struct {
	err error
}

func (f fakeDevices) Device(name string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return "/dev/disk/by-id/virtio-c8s-vol-" + name, nil
}

// serverFixture wires a server over a real unix socket, so the connection and
// peer-credential plumbing is exercised rather than stubbed.
type serverFixture struct {
	client *http.Client
	ops    *fakeOps
	opener *Opener
	srv    *Server
}

func newServerFixture(t *testing.T, ident Identity, grant *pkgallowlist.SecretsPolicy) *serverFixture {
	t.Helper()
	ops := newOps()
	opener := testOpener(t, ops)
	srv := &Server{
		Identity:   ident,
		Authorizer: authorizerFor(runningApp(), grant),
		Opener:     opener,
		Devices:    fakeDevices{},
	}

	sock := filepath.Join(t.TempDir(), "volumed.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx, l)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	return &serverFixture{client: client, ops: ops, opener: opener, srv: srv}
}

func (f *serverFixture) post(t *testing.T, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := f.client.Post("http://volumed"+VolumePath, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func openBody(t *testing.T) OpenRequest {
	t.Helper()
	req := testRequest(t)
	return OpenRequest{Name: req.Name, Path: storePath, Blob: req.Blob}
}

func resolvedIdentity() fakeIdentity {
	return fakeIdentity{podUID: testPodUID, sandboxID: sandboxID}
}

func TestServerOpensForAnAuthorizedCaller(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity(), readGrant(storePath))
	resp := f.post(t, openBody(t))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if f.opener.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want 1", f.opener.Len())
	}
}

// The grant is checked before anything privileged happens, so a caller with no
// claim never reaches device-mapper.
func TestServerRefusesUngrantedPathBeforeOpening(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity(), readGrant("/tenant-b/volumes/other"))
	resp := f.post(t, openBody(t))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if f.ops.sequence() != "" {
		t.Fatalf("an unauthorized request reached the privileged steps: %q", f.ops.sequence())
	}
	if f.opener.Len() != 0 {
		t.Fatal("an unauthorized request produced a mount")
	}
}

// A caller the kernel cannot place in a pod is refused outright.
func TestServerRefusesUnresolvableCaller(t *testing.T) {
	f := newServerFixture(t, fakeIdentity{err: errors.New("no pod cgroup")}, readGrant(storePath))
	resp := f.post(t, openBody(t))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if f.ops.sequence() != "" {
		t.Fatalf("an unresolved caller reached the privileged steps: %q", f.ops.sequence())
	}
}

// A wrong key for an already-open volume answers exactly as a failed grant
// check does; a distinct status would tell an unentitled pod what is mounted.
func TestServerGivesOneAnswerForBothRefusals(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity(), readGrant(storePath))
	if got := f.post(t, openBody(t)).StatusCode; got != http.StatusNoContent {
		t.Fatalf("first open: status %d", got)
	}

	body := openBody(t)
	blob, err := volume.NewBlob(make([]byte, volume.KeyBytes), body.Blob.Verity)
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	body.Blob = blob

	wrongKey := f.post(t, body).StatusCode

	g := newServerFixture(t, resolvedIdentity(), readGrant("/elsewhere"))
	ungranted := g.post(t, openBody(t)).StatusCode

	if wrongKey != ungranted {
		t.Fatalf("wrong key answers %d but an ungranted path answers %d", wrongKey, ungranted)
	}
}

// The caller never names its own pod; a body field claiming to is rejected
// rather than ignored.
func TestServerRejectsUnknownRequestFields(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity(), readGrant(storePath))
	raw := map[string]any{"name": "weights", "path": storePath, "pod_uid": "someone-else"}
	resp := f.post(t, raw)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestServerReportsAMissingDevice(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity(), readGrant(storePath))
	f.srv.Devices = fakeDevices{err: errors.New("no such serial")}
	resp := f.post(t, openBody(t))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if f.ops.sequence() != "" {
		t.Fatalf("a missing device reached the privileged steps: %q", f.ops.sequence())
	}
}

func TestServerReportsAFailedOpen(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity(), readGrant(storePath))
	f.ops.failOn = "CryptOpen"
	resp := f.post(t, openBody(t))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	if c, v, m := f.ops.leaked(); c != 0 || v != 0 || m != 0 {
		t.Fatalf("a failed open leaked crypt=%d verity=%d mounts=%d", c, v, m)
	}
}

// A restarted sidecar re-sends its request; the repeat must not open a second
// mapping or fail.
func TestServerIsIdempotentForARepeatedRequest(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity(), readGrant(storePath))
	for i := 0; i < 3; i++ {
		if got := f.post(t, openBody(t)).StatusCode; got != http.StatusNoContent {
			t.Fatalf("attempt %d: status %d", i, got)
		}
	}
	if f.opener.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want 1", f.opener.Len())
	}
	if got := f.ops.sequence(); got != "CryptOpen,VerityOpen,MountRO" {
		t.Fatalf("repeats re-ran privileged steps: %q", got)
	}
}

// Only POST is served; the route exists for one verb.
func TestServerServesOnlyPost(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity(), readGrant(storePath))
	resp, err := f.client.Get("http://volumed" + VolumePath)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("GET was served")
	}
}

func TestServerBoundsTheRequestBody(t *testing.T) {
	f := newServerFixture(t, resolvedIdentity(), readGrant(storePath))
	body := openBody(t)
	body.Path = "/" + strings.Repeat("a", maxRequestBytes)
	if got := f.post(t, body).StatusCode; got != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d for an oversized body", got, http.StatusBadRequest)
	}
}

func TestAcquireBoundsConcurrentOpensPerPod(t *testing.T) {
	s := &Server{}
	var releases []func()
	for i := 0; i < maxInFlightPerPod; i++ {
		release, ok := s.acquire(testPodUID)
		if !ok {
			t.Fatalf("slot %d refused below the cap", i)
		}
		releases = append(releases, release)
	}
	if _, ok := s.acquire(testPodUID); ok {
		t.Fatal("acquired past the per-pod cap")
	}
	// A different pod has its own budget.
	if _, ok := s.acquire("99999999-8888-7777-6666-555555555555"); !ok {
		t.Fatal("one pod's load blocked another")
	}
	for _, r := range releases {
		r()
	}
	if _, ok := s.acquire(testPodUID); !ok {
		t.Fatal("slots were not released")
	}
}

func TestAcquireIsRaceFree(t *testing.T) {
	s := &Server{}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if release, ok := s.acquire(testPodUID); ok {
				release()
			}
		}()
	}
	wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inFlight) != 0 {
		t.Fatalf("in-flight table leaked %d entries", len(s.inFlight))
	}
}

func TestKernelIdentityNeedsASandboxResolver(t *testing.T) {
	if _, _, err := (KernelIdentity{}).Resolve(workloadclaims.PeerForPID(1)); err == nil {
		t.Fatal("resolved with no sandbox resolver")
	}
}

func TestKernelIdentityTakesTheShallowestPodUID(t *testing.T) {
	root := procWith(t, 4242, "0::/kubepods.slice/kubepods-burstable.slice/"+
		"kubepods-burstable-pod3f4a1b2c_5d6e_7f80_9a0b_1c2d3e4f5061.slice/"+
		"cri-containerd-aaaabbbbccccddddeeeeffff00001111aaaabbbbccccddddeeeeffff00001111.scope/"+
		"pod99999999-8888-7777-6666-555555555555/nested\n")

	k := KernelIdentity{ProcRoot: root, Sandboxes: fakeSandboxes{id: sandboxID}}
	podUID, gotSandbox, err := k.Resolve(workloadclaims.PeerForPID(4242))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if podUID != testPodUID {
		t.Fatalf("pod uid = %q, want the runtime-assigned %q", podUID, testPodUID)
	}
	if gotSandbox != sandboxID {
		t.Fatalf("sandbox = %q", gotSandbox)
	}
}

func TestKernelIdentitySurfacesSandboxFailure(t *testing.T) {
	k := KernelIdentity{ProcRoot: t.TempDir(), Sandboxes: fakeSandboxes{err: errors.New("unknown")}}
	if _, _, err := k.Resolve(workloadclaims.PeerForPID(1)); err == nil {
		t.Fatal("resolved despite an unknown sandbox")
	}
}

type fakeSandboxes struct {
	id  string
	err error
}

func (f fakeSandboxes) SandboxForPeer(workloadclaims.Peer) (string, error) {
	return f.id, f.err
}

func (f fakeSandboxes) DigestsForSandbox(string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	return nil, nil, false, nil
}
