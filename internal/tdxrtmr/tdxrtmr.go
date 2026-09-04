// Package tdxrtmr reads and extends the TDX runtime measurement registers
// through the kernel TSM sysfs nodes (mainline >= 6.16):
// /sys/devices/virtual/misc/tdx_guest/measurements/rtmr<N>:sha384. A read
// returns the raw 48-byte register; a write of 48 bytes performs
// TDG.MR.RTMR.EXTEND. Every in-guest c8s component that touches a register
// (cred-release, policy-measure, the NRI plugin, the kata workload measurer)
// goes through this package so the sysfs contract lives in one place. The
// arithmetic the register commits is pkg/runtimemeasure.
package tdxrtmr

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

// SysfsRoot is the directory holding the rtmr<N>:sha384 nodes. A var so
// tests point it at a temp dir.
var SysfsRoot = "/sys/devices/virtual/misc/tdx_guest/measurements"

// Path returns the sysfs node of register index under SysfsRoot.
func Path(index int) string {
	return filepath.Join(SysfsRoot, fmt.Sprintf("rtmr%d:sha384", index))
}

// Read returns the current value of RTMR[index] (0..3). A node that is
// absent or not exactly 48 bytes is an error, never a truncated value.
func Read(index int) ([runtimemeasure.Size]byte, error) {
	var reg [runtimemeasure.Size]byte
	if index < 0 || index > 3 {
		return reg, fmt.Errorf("RTMR[%d] does not exist: TDX has RTMR[0..3]", index)
	}
	path := Path(index)
	b, err := os.ReadFile(path)
	if err != nil {
		return reg, fmt.Errorf("read %s: %w (is this a TDX guest with runtime measurement?)", path, err)
	}
	if len(b) != runtimemeasure.Size {
		return reg, fmt.Errorf("read %s: got %d bytes, want %d", path, len(b), runtimemeasure.Size)
	}
	copy(reg[:], b)
	return reg, nil
}

// Extend folds event into RTMR[index]: RTMR = SHA384(RTMR ‖ event). Only
// RTMR[2] and RTMR[3] are guest-extendable; the TDX module owns 0 and 1 and
// the kernel exposes them read-only, so other indices are refused here rather
// than by an opaque EACCES.
func Extend(index int, event [runtimemeasure.Size]byte) error {
	if index != 2 && index != 3 {
		return fmt.Errorf("RTMR[%d] is not guest-extendable: only RTMR[2] and RTMR[3] are", index)
	}
	path := Path(index)
	// No O_CREATE: a mis-pointed SysfsRoot or a kernel without the TSM node
	// must fail, not leave a regular file that reads back as a register.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("extend %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(event[:]); err != nil {
		return fmt.Errorf("extend %s: %w", path, err)
	}
	return nil
}
