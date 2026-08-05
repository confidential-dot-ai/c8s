package cmdsutil

import (
	"context"

	"github.com/spf13/cobra"
)

// CmdCtx returns the command context or a background context as a fallback.
func CmdCtx(cmd *cobra.Command) context.Context {
	if c := cmd.Context(); c != nil {
		return c
	}
	return context.Background()
}
