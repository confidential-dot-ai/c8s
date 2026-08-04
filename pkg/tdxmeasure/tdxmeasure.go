// Package tdxmeasure computes the Intel TDX build-time measurement (MRTD) of a
// kata confidential guest offline, from the TDVF firmware image, before the
// guest is ever started.
//
// MRTD is an iterative SHA-384 the TDX module builds while the VMM adds the
// TD's initial pages: TDH.MEM.PAGE.ADD extends it with a page's GPA,
// TDH.MR.EXTEND with 256-byte chunks of that page's contents, and
// TDH.MR.FINALIZE completes it. The pages added pre-finalize are exactly those
// named by TDVF's metadata section table, so MRTD is a function of the TDVF
// binary alone.
//
// It therefore does NOT cover the guest kernel, initrd, kernel command line,
// vCPU count or guest RAM size — those reach RTMR[0..2], which c8s does not pin
// (see pkg/ratls.VerifyPolicy). One MRTD covers every pod shape booting the
// same TDVF; this was confirmed against two live kata-qemu-tdx pods of
// different vCPU shapes. See docs/kata-launch-measurement.md.
//
// The digest itself comes from github.com/google/gce-tcb-verifier/tdx rather
// than a local reimplementation of the TDX Module Base Architecture
// Specification.
package tdxmeasure

import (
	"fmt"

	gcetdx "github.com/google/gce-tcb-verifier/tdx"
)

// DigestLen is the length of an MRTD, in bytes.
const DigestLen = 48

// launchOptions returns the only option set valid for a kata-qemu-tdx guest.
//
// LaunchOptions is a GCE-shaped API and its other presets do NOT describe our
// VMM: MeasureAllRegions (LaunchOptionsDefaultTDHOBBug) models a Google
// hypervisor bug, and DisableUnacceptedMemory changes the TD HOB. Both produce
// a different, wrong digest here — see docs/kata-launch-measurement.md.
// The machine-type argument is unused by the library.
func launchOptions() *gcetdx.LaunchOptions { return gcetdx.LaunchOptionsDefault("") }

// MRTD returns the 48-byte TDX build-time measurement of a TDVF image.
func MRTD(firmware []byte) ([]byte, error) {
	d, err := gcetdx.MRTD(launchOptions(), firmware)
	if err != nil {
		return nil, fmt.Errorf("compute MRTD: %w", err)
	}
	return d[:], nil
}
