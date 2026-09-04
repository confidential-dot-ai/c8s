//go:build !linux

package policymeasure

import "errors"

// The command only ever runs inside the Linux node image; the CLI build for
// other platforms carries the subcommand but cannot mount a disk.
var (
	mountISO = func(dev, target string) error {
		return errors.New("policy-measure: mounting the policydata ISO needs Linux")
	}
	unmountISO = func(target string) error { return nil }
)
