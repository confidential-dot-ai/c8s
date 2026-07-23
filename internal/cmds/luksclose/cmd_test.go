package luksclose

import (
	"os"
	"strings"
	"testing"
)

func TestRunRequiresVolumes(t *testing.T) {
	if err := Run(Config{}); err == nil || !strings.Contains(err.Error(), "no --volume") {
		t.Fatalf("Run with no volumes = %v, want 'no --volume' error", err)
	}
}

func TestCloseOneNoOpOnMissingMount(t *testing.T) {
	// closeOne's mapper branch opens /dev/mapper/control, which needs root
	// (DM_DEV_REMOVE is a privileged ioctl). Init containers running this
	// subcommand ARE root; CI and devcontainers are not. Skip when we can't
	// meaningfully exercise the branch — the missing-device case (absent
	// /dev/mapper/control) is subsumed by the not-root case.
	if os.Geteuid() != 0 {
		t.Skip("skip: needs root to open /dev/mapper/control (test-env limitation, not a code path)")
	}
	if _, err := os.Stat("/dev/mapper/control"); os.IsNotExist(err) {
		t.Skip("skip: /dev/mapper/control absent (not a node with device-mapper)")
	}
	cfg := Config{MountRoot: "/tmp/c8s-luksclose-test-does-not-exist", Names: []string{"absent"}}
	if err := closeOne(cfg, "absent"); err != nil {
		t.Fatalf("closeOne(missing mount + missing mapper) = %v, want nil (idempotent)", err)
	}
}

func TestUnmountIfMountedNoOpOnUnmountedPath(t *testing.T) {
	// The isolated unmount branch — testable everywhere. An unmounted path is a
	// no-op (nil), matching the "already closed" idempotent contract.
	if err := unmountIfMounted("/tmp/c8s-luksclose-test-really-not-mounted"); err != nil {
		t.Fatalf("unmountIfMounted(unmounted) = %v, want nil", err)
	}
}
