// Package probefile implements the probe-file subcommand: a tiny kubelet
// exec-probe helper for distroless containers. gcr.io/distroless/static has no
// shell or coreutils, so a startup/liveness probe that needs to wait for a
// file to appear has no `test -s` available.
package probefile

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// NewCmd returns the cobra subcommand. Registered as a child of `c8s`.
func NewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "probe-file <path>",
		Short: "Exit 0 if <path> exists and is non-empty",
		Long: `probe-file is an exec-probe helper for distroless containers,
where /bin/test is not available. It exits 0 when <path> exists and is
non-empty, and non-zero otherwise.

The non-empty check rules out a probe passing on a half-written file. Writers
of files probed this way should still use atomic rename (write to a temp file
and rename into place) so the probe never sees a torn write.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return probe(args[0])
		},
	}
}

func probe(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s: does not exist", path)
		}
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s: is a directory", path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("%s: empty", path)
	}
	return nil
}
