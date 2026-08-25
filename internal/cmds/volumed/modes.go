package volumed

import (
	"context"
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
)

// A volumeMode is how one mode builds the device stack above the dm-crypt
// mapping: an immutable volume stacks dm-verity and mounts erofs read-only,
// a mutable one mounts the crypt device itself, writable ext4.
type volumeMode interface {
	// open builds the layers above cryptMapper and returns what to mount.
	open(ctx context.Context, ops DeviceOps, podUID, name, cryptMapper string, b volume.Blob) (mountSpec, error)
	// close unwinds what open built — a no-op for a mode with no layers.
	close(ctx context.Context, ops DeviceOps, podUID, name string)
}

// mountSpec is where a stack's top is mounted and how.
type mountSpec struct {
	source   string
	fsType   string
	readOnly bool
}

// modeFor selects the stack a mode builds.
func modeFor(mutable bool) volumeMode {
	if mutable {
		return mutableMode{}
	}
	return immutableMode{}
}

// immutableMode stacks dm-verity over the crypt mapping and mounts the
// verified device, read-only erofs.
type immutableMode struct{}

func (immutableMode) open(ctx context.Context, ops DeviceOps, podUID, name, cryptMapper string, b volume.Blob) (mountSpec, error) {
	verityMapper := mapperName(verityKind, podUID, name)
	if err := ops.VerityOpen(ctx, devPath(cryptMapper), verityMapper, *b.Verity); err != nil {
		return mountSpec{}, fmt.Errorf("volumed: open dm-verity: %w", err)
	}
	return mountSpec{source: devPath(verityMapper), fsType: fsTypeErofs, readOnly: true}, nil
}

func (immutableMode) close(ctx context.Context, ops DeviceOps, podUID, name string) {
	_ = ops.VerityClose(ctx, mapperName(verityKind, podUID, name))
}

// mutableMode mounts the crypt device itself, writable ext4: there is no
// integrity layer to build or unwind.
type mutableMode struct{}

func (mutableMode) open(_ context.Context, _ DeviceOps, _, _, cryptMapper string, _ volume.Blob) (mountSpec, error) {
	return mountSpec{source: devPath(cryptMapper), fsType: fsTypeExt4, readOnly: false}, nil
}

func (mutableMode) close(context.Context, DeviceOps, string, string) {}
