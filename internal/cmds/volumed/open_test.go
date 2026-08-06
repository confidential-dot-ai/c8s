package volumed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
)

// fakeOps records every privileged call and can be told to fail one step.
type fakeOps struct {
	mu     sync.Mutex
	calls  []string
	failOn string

	cryptOpen, verityOpen, mounted map[string]bool
}

func newOps() *fakeOps {
	return &fakeOps{
		cryptOpen:  map[string]bool{},
		verityOpen: map[string]bool{},
		mounted:    map[string]bool{},
	}
}

func (f *fakeOps) record(op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op)
	if f.failOn == op {
		return errors.New(op + " failed")
	}
	return nil
}

func (f *fakeOps) CryptOpen(_ context.Context, _, mapper string, key []byte) error {
	if len(key) != volume.KeyBytes {
		return errors.New("wrong key length")
	}
	if err := f.record("CryptOpen"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cryptOpen[mapper] = true
	return nil
}

func (f *fakeOps) CryptClose(_ context.Context, mapper string) error {
	if err := f.record("CryptClose"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.cryptOpen, mapper)
	return nil
}

func (f *fakeOps) VerityOpen(_ context.Context, _, mapper string, _ volume.Verity) error {
	if err := f.record("VerityOpen"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verityOpen[mapper] = true
	return nil
}

func (f *fakeOps) VerityClose(_ context.Context, mapper string) error {
	if err := f.record("VerityClose"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.verityOpen, mapper)
	return nil
}

func (f *fakeOps) MountRO(_ context.Context, _ string, target *os.File) error {
	if err := f.record("MountRO"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// The kernel resolves /proc/self/fd/N to the directory it names, so the
	// mount lands at the real path — which is what teardown unmounts.
	f.mounted[target.Name()] = true
	return nil
}

func (f *fakeOps) Unmount(_ context.Context, target string) error {
	if err := f.record("Unmount"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.mounted, target)
	return nil
}

// leaked reports device-mapper targets or mounts left behind. A leaked crypt
// target holds the key in kernel memory with nothing owning it.
func (f *fakeOps) leaked() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cryptOpen), len(f.verityOpen), len(f.mounted)
}

func (f *fakeOps) sequence() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, ",")
}

func testOpener(t *testing.T, ops DeviceOps) *Opener {
	t.Helper()
	root, base := kubeletTree(t)
	if err := os.Mkdir(filepath.Join(base, KubeVolumeName("weights")), 0o755); err != nil {
		t.Fatalf("mkdir volume dir: %v", err)
	}
	return &Opener{Ops: ops, Targets: KubeletTargets{Root: root}}
}

func testRequest(t *testing.T) Request {
	t.Helper()
	blob, err := volume.NewBlob(volumeKey(), volume.Verity{
		RootHash:   strings.Repeat("ab", 32),
		Salt:       strings.Repeat("cd", 16),
		DataBlocks: 4,
		HashOffset: 4 * volume.VerityBlockSize,
	})
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	return Request{Pod: testPod(testPodUID), Name: "weights", Device: "/dev/disk/by-id/virtio-c8s-vol-weights", Blob: blob}
}

// testPod is a pod as the kernel would report it: the UID naming its kubelet
// directory, and the systemd-driver slice that disappears when it goes.
func testPod(uid string) PodCgroup {
	return PodCgroup{
		UID:  uid,
		Path: "/kubepods.slice/kubepods-pod" + strings.ReplaceAll(uid, "-", "_") + ".slice",
	}
}

func volumeKey() []byte {
	k := make([]byte, volume.KeyBytes)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestOpenRunsTheStepsInOrder(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	if err := o.Open(t.Context(), testRequest(t)); err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := ops.sequence(); got != "CryptOpen,VerityOpen,MountRO" {
		t.Fatalf("sequence = %q", got)
	}
	if o.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want 1", o.Len())
	}
}

// Every step that completed must be undone when a later one fails, or the
// device-mapper targets are left holding the key with no owner.
func TestOpenUnwindsEveryCompletedStepOnFailure(t *testing.T) {
	for _, tc := range []struct{ failOn, wantSeq string }{
		{"CryptOpen", "CryptOpen"},
		{"VerityOpen", "CryptOpen,VerityOpen,CryptClose"},
		{"MountRO", "CryptOpen,VerityOpen,MountRO,VerityClose,CryptClose"},
	} {
		ops := newOps()
		ops.failOn = tc.failOn
		o := testOpener(t, ops)

		if err := o.Open(t.Context(), testRequest(t)); err == nil {
			t.Fatalf("%s: open succeeded despite failure", tc.failOn)
		}
		if got := ops.sequence(); got != tc.wantSeq {
			t.Errorf("%s: sequence = %q, want %q", tc.failOn, got, tc.wantSeq)
		}
		if c, v, m := ops.leaked(); c != 0 || v != 0 || m != 0 {
			t.Errorf("%s: leaked crypt=%d verity=%d mounts=%d", tc.failOn, c, v, m)
		}
		if o.Len() != 0 {
			t.Errorf("%s: a failed open was recorded as a mount", tc.failOn)
		}
	}
}

// kubelet restarts a native sidecar for the pod's life, so it re-sends its
// request; an identical one must not open a second mapping.
func TestOpenIsIdempotentForAnIdenticalRequest(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	req := testRequest(t)

	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("repeat open: %v", err)
	}
	if got := ops.sequence(); got != "CryptOpen,VerityOpen,MountRO" {
		t.Fatalf("repeat re-ran privileged steps: %q", got)
	}
	if o.Len() != 1 {
		t.Fatalf("opener holds %d mounts, want 1", o.Len())
	}
}

// Without this the volume NAME is the credential — and a name is a label in a
// host-written annotation, so any pod reaching the socket would be handed the
// plaintext once one entitled pod had opened it.
func TestOpenRefusesAWrongKeyForAnOpenVolume(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	if err := o.Open(t.Context(), testRequest(t)); err != nil {
		t.Fatalf("first open: %v", err)
	}

	other := testRequest(t)
	wrong := make([]byte, volume.KeyBytes)
	blob, err := volume.NewBlob(wrong, other.Blob.Verity)
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	other.Blob = blob

	if err := o.Open(t.Context(), other); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("got %v, want ErrNotAuthorized", err)
	}
	if got := ops.sequence(); got != "CryptOpen,VerityOpen,MountRO" {
		t.Fatalf("a refused caller reached the privileged steps: %q", got)
	}
}

// The root hash is half the commitment: same key, different integrity anchor is
// a different volume.
func TestOpenRefusesADifferentRootHashForAnOpenVolume(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	req := testRequest(t)
	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("first open: %v", err)
	}

	other := testRequest(t)
	v := other.Blob.Verity
	v.RootHash = strings.Repeat("cd", 32)
	blob, err := volume.NewBlob(volumeKey(), v)
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	other.Blob = blob

	if err := o.Open(t.Context(), other); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("got %v, want ErrNotAuthorized", err)
	}
}

func TestOpenCapsLiveMounts(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	o.MaxMounts = 1
	if err := o.Open(t.Context(), testRequest(t)); err != nil {
		t.Fatalf("first open: %v", err)
	}

	// A different pod, so it is not the idempotent path.
	other := testRequest(t)
	other.Pod = testPod("99999999-8888-7777-6666-555555555555")
	if err := o.Open(t.Context(), other); !errors.Is(err, ErrTooManyMounts) {
		t.Fatalf("got %v, want ErrTooManyMounts", err)
	}
}

func TestCloseTearsDownInReverse(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	req := testRequest(t)
	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("open: %v", err)
	}

	o.Close(t.Context(), req.Pod.UID, req.Name)
	if got := ops.sequence(); !strings.HasSuffix(got, "Unmount,VerityClose,CryptClose") {
		t.Fatalf("teardown order = %q", got)
	}
	if c, v, m := ops.leaked(); c != 0 || v != 0 || m != 0 {
		t.Fatalf("leaked crypt=%d verity=%d mounts=%d", c, v, m)
	}
	if o.Len() != 0 {
		t.Fatal("mount still recorded after close")
	}
}

// Teardown races kubelet removing the pod directory, so closing something
// already gone is not an error.
func TestCloseIsIdempotent(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	req := testRequest(t)
	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("open: %v", err)
	}
	o.Close(t.Context(), req.Pod.UID, req.Name)
	before := ops.sequence()
	o.Close(t.Context(), req.Pod.UID, req.Name)
	if ops.sequence() != before {
		t.Fatal("closing an absent volume issued more privileged calls")
	}
}

// A failed unmount must not stop the device-mapper targets being removed: they
// are what holds the key.
func TestTeardownContinuesPastAFailedUnmount(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	req := testRequest(t)
	if err := o.Open(t.Context(), req); err != nil {
		t.Fatalf("open: %v", err)
	}
	ops.failOn = "Unmount"

	o.Close(t.Context(), req.Pod.UID, req.Name)
	if c, v, _ := ops.leaked(); c != 0 || v != 0 {
		t.Fatalf("a failed unmount left crypt=%d verity=%d behind", c, v)
	}
}

func TestClosePodTearsDownEveryVolumeItHolds(t *testing.T) {
	ops := newOps()
	root, base := kubeletTree(t)
	for _, n := range []string{"weights", "datasets"} {
		if err := os.Mkdir(filepath.Join(base, KubeVolumeName(n)), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", n, err)
		}
	}
	o := &Opener{Ops: ops, Targets: KubeletTargets{Root: root}}

	for _, n := range []string{"weights", "datasets"} {
		req := testRequest(t)
		req.Name = n
		if err := o.Open(t.Context(), req); err != nil {
			t.Fatalf("open %s: %v", n, err)
		}
	}
	if o.Len() != 2 {
		t.Fatalf("opener holds %d mounts, want 2", o.Len())
	}

	o.ClosePod(t.Context(), testPodUID)
	if o.Len() != 0 {
		t.Fatalf("opener holds %d mounts after pod teardown", o.Len())
	}
	if c, v, m := ops.leaked(); c != 0 || v != 0 || m != 0 {
		t.Fatalf("leaked crypt=%d verity=%d mounts=%d", c, v, m)
	}
}

func TestOpenRejectsMalformedRequests(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)

	bad := testRequest(t)
	bad.Name = "Weights"
	if err := o.Open(t.Context(), bad); err == nil {
		t.Error("accepted a name that is not a label")
	}

	bad = testRequest(t)
	bad.Blob.Verity.RootHash = "short"
	if err := o.Open(t.Context(), bad); err == nil {
		t.Error("accepted a blob that fails validation")
	}

	bad = testRequest(t)
	bad.Blob.Key = "not base64"
	if err := o.Open(t.Context(), bad); err == nil {
		t.Error("accepted a blob with an unusable key")
	}

	if ops.sequence() != "" {
		t.Errorf("a malformed request reached the privileged steps: %q", ops.sequence())
	}
}

// Two pods opening the same volume get their own mappings, so one pod's
// teardown cannot remove the other's.
func TestMapperNamesAreScopedPerPod(t *testing.T) {
	a := mapperName("crypt", testPodUID, "weights")
	b := mapperName("crypt", "99999999-8888-7777-6666-555555555555", "weights")
	if a == b {
		t.Fatal("two pods share a mapper name")
	}
	if !strings.HasPrefix(a, "c8s-crypt-") {
		t.Fatalf("mapper name = %q", a)
	}
}

func TestCommitmentCoversKeyAndRootHash(t *testing.T) {
	key := volumeKey()
	base := commitmentFor(key, "aa")
	if commitmentFor(key, "bb") == base {
		t.Error("commitment ignores the root hash")
	}
	other := make([]byte, volume.KeyBytes)
	if commitmentFor(other, "aa") == base {
		t.Error("commitment ignores the key")
	}
}

func TestZeroClearsTheBuffer(t *testing.T) {
	b := []byte{1, 2, 3}
	zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %d", i, v)
		}
	}
}
