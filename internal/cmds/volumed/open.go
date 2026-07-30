package volumed

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
)

// DeviceOps are the privileged steps. Behind an interface so the orchestration
// and every unwind path are exercised without device-mapper.
//
// Each Open has a matching Close, and the orchestration calls Close for every
// step it completed when a later one fails.
type DeviceOps interface {
	CryptOpen(ctx context.Context, device, mapper string, key []byte) error
	CryptClose(ctx context.Context, mapper string) error
	VerityOpen(ctx context.Context, dataDev, mapper string, v volume.Verity) error
	VerityClose(ctx context.Context, mapper string) error
	// MountRO takes the resolved target as an open handle rather than a path:
	// the implementation mounts through /proc/self/fd so nothing can be swapped
	// between resolving the target and using it. Unmount takes a path, because
	// by teardown that handle is long closed.
	MountRO(ctx context.Context, source string, target *os.File) error
	Unmount(ctx context.Context, target string) error
}

// ErrNotAuthorized is returned when a caller presents the wrong key for a
// volume already open under its pod.
var ErrNotAuthorized = errors.New("volumed: not authorized for this volume")

// ErrTooManyMounts reports the per-node cap. Each mount costs two device-mapper
// devices and a mount, and every cw pod can reach the socket.
var ErrTooManyMounts = errors.New("volumed: too many open volumes on this node")

// Request is one open, after the caller has been resolved.
type Request struct {
	// Pod is the calling pod, as the kernel placed it. Its cgroup path is held
	// so teardown can ask whether the pod still exists.
	Pod    PodCgroup
	Name   string
	Device string
	Blob   volume.Blob
}

// mount is a live volume. The commitment is what a second caller must reproduce
// to be handed the same mapping.
type mount struct {
	pod        PodCgroup
	name       string
	commitment [sha256.Size]byte
	cryptDev   string
	verityDev  string
	target     string
}

// Opener opens volumes and remembers what it has open.
type Opener struct {
	Ops DeviceOps
	// KubeletRoot is where kubelet keeps pod directories.
	KubeletRoot string
	// MaxMounts caps live volumes; zero means DefaultMaxMounts.
	MaxMounts int

	mu     sync.Mutex
	mounts map[string]*mount
}

// DefaultMaxMounts bounds live volumes when MaxMounts is unset.
const DefaultMaxMounts = 64

// Open makes the volume readable at the calling pod's mount target, and is
// idempotent for a caller repeating an identical request — which a restarted
// sidecar does, since kubelet restarts it for the pod's life.
//
// A request naming a volume already open must present the same key and root
// hash. Without that check the volume *name* would be the credential, and a
// name is a label in a host-written annotation: any pod reaching the socket
// would be handed the plaintext once one entitled pod had opened it.
func (o *Opener) Open(ctx context.Context, req Request) error {
	key, err := req.Blob.DecodeKey()
	if err != nil {
		return err
	}
	defer zero(key)
	if err := req.Blob.Validate(); err != nil {
		return err
	}
	if !volumeNameRE.MatchString(req.Name) {
		return fmt.Errorf("volumed: volume name %q is not a dns-1123 label", req.Name)
	}

	commitment := commitmentFor(key, req.Blob.Verity.RootHash)

	o.mu.Lock()
	if o.mounts == nil {
		o.mounts = map[string]*mount{}
	}
	if existing, ok := o.mounts[mountKey(req.Pod.UID, req.Name)]; ok {
		o.mu.Unlock()
		if subtle.ConstantTimeCompare(existing.commitment[:], commitment[:]) != 1 {
			return ErrNotAuthorized
		}
		return nil
	}
	if len(o.mounts) >= o.maxMounts() {
		o.mu.Unlock()
		return ErrTooManyMounts
	}
	o.mu.Unlock()

	m, err := o.open(ctx, req, key, commitment)
	if err != nil {
		return err
	}

	// A concurrent identical request may have won the race; keep one mapping
	// and tear the loser down outside the lock.
	o.mu.Lock()
	existing, lost := o.mounts[mountKey(req.Pod.UID, req.Name)]
	if !lost {
		o.mounts[mountKey(req.Pod.UID, req.Name)] = m
	}
	o.mu.Unlock()
	if !lost {
		return nil
	}
	o.teardown(ctx, m)
	if subtle.ConstantTimeCompare(existing.commitment[:], commitment[:]) != 1 {
		return ErrNotAuthorized
	}
	return nil
}

// open runs the privileged steps, undoing everything it completed if a later
// step fails. A half-open volume leaves a device-mapper target holding the key
// in kernel memory with nothing owning it.
func (o *Opener) open(ctx context.Context, req Request, key []byte, commitment [sha256.Size]byte) (*mount, error) {
	target, err := TargetDir(o.KubeletRoot, req.Pod.UID, KubeVolumeName(req.Name))
	if err != nil {
		return nil, err
	}
	defer target.Close()

	var undo []func()
	fail := func(err error) (*mount, error) {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		return nil, err
	}

	cryptMapper := mapperName("crypt", req.Pod.UID, req.Name)
	if err := o.Ops.CryptOpen(ctx, req.Device, cryptMapper, key); err != nil {
		return fail(fmt.Errorf("volumed: open dm-crypt: %w", err))
	}
	undo = append(undo, func() { _ = o.Ops.CryptClose(ctx, cryptMapper) })

	verityMapper := mapperName("verity", req.Pod.UID, req.Name)
	if err := o.Ops.VerityOpen(ctx, devPath(cryptMapper), verityMapper, req.Blob.Verity); err != nil {
		return fail(fmt.Errorf("volumed: open dm-verity: %w", err))
	}
	undo = append(undo, func() { _ = o.Ops.VerityClose(ctx, verityMapper) })

	if err := o.Ops.MountRO(ctx, devPath(verityMapper), target); err != nil {
		return fail(fmt.Errorf("volumed: mount: %w", err))
	}

	return &mount{
		pod:        req.Pod,
		name:       req.Name,
		commitment: commitment,
		cryptDev:   cryptMapper,
		verityDev:  verityMapper,
		target:     target.Name(),
	}, nil
}

// Close tears down one volume. Idempotent: a volume already gone is not an
// error, because teardown races kubelet removing the pod directory.
func (o *Opener) Close(ctx context.Context, podUID, name string) {
	o.mu.Lock()
	m, ok := o.mounts[mountKey(podUID, name)]
	if ok {
		delete(o.mounts, mountKey(podUID, name))
	}
	o.mu.Unlock()
	if ok {
		o.teardown(ctx, m)
	}
}

// ClosePod tears down every volume a pod holds, for when the pod goes away, and
// reports how many it closed.
func (o *Opener) ClosePod(ctx context.Context, podUID string) int {
	if podUID == "" {
		return 0
	}
	o.mu.Lock()
	var doomed []*mount
	for k, m := range o.mounts {
		if m.pod.UID == podUID {
			doomed = append(doomed, m)
			delete(o.mounts, k)
		}
	}
	o.mu.Unlock()
	for _, m := range doomed {
		o.teardown(ctx, m)
	}
	return len(doomed)
}

// teardown unwinds in reverse and does not stop at the first failure: the
// device-mapper targets hold the key, so a failed unmount must not leave them
// behind.
func (o *Opener) teardown(ctx context.Context, m *mount) {
	_ = o.Ops.Unmount(ctx, m.target)
	_ = o.Ops.VerityClose(ctx, m.verityDev)
	_ = o.Ops.CryptClose(ctx, m.cryptDev)
}

// Pods returns the distinct pods holding a volume, so teardown can ask which of
// them still exist.
func (o *Opener) Pods() []PodCgroup {
	o.mu.Lock()
	defer o.mu.Unlock()
	seen := map[string]struct{}{}
	var out []PodCgroup
	for _, m := range o.mounts {
		if _, dup := seen[m.pod.UID]; dup {
			continue
		}
		seen[m.pod.UID] = struct{}{}
		out = append(out, m.pod)
	}
	return out
}

// Len reports live volumes, for metrics and tests.
func (o *Opener) Len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.mounts)
}

func (o *Opener) maxMounts() int {
	if o.MaxMounts > 0 {
		return o.MaxMounts
	}
	return DefaultMaxMounts
}

// commitmentFor binds a mapping to the exact key and root hash that opened it.
func commitmentFor(key []byte, rootHash string) [sha256.Size]byte {
	h := sha256.New()
	h.Write(key)
	h.Write([]byte(rootHash))
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func mountKey(podUID, name string) string { return podUID + "/" + name }

// mapperName is scoped by pod so two pods opening the same volume get their own
// mappings, and one pod's teardown cannot remove another's.
func mapperName(kind, podUID, name string) string {
	return fmt.Sprintf("c8s-%s-%s-%s", kind, podUID, name)
}

// mapperDir is where device-mapper publishes its nodes. A mapper name is a bare
// name beneath it, never a path.
const mapperDir = "/dev/mapper"

func devPath(mapper string) string { return mapperDir + "/" + mapper }

// zero best-effort clears a key buffer. The blob arrived as JSON, so copies
// exist that cannot be reached; this clears the one that was used.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
