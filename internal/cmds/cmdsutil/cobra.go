package cmdsutil

import (
	"context"

	"github.com/spf13/cobra"
)

// TrimSlash removes trailing slashes from a base URL so path joins cannot
// produce a double slash the server would reject as non-canonical.
func TrimSlash(u string) string {
	for len(u) > 0 && u[len(u)-1] == '/' {
		u = u[:len(u)-1]
	}
	return u
}

// CmdCtx returns the command context or a background context as a fallback.
func CmdCtx(cmd *cobra.Command) context.Context {
	if c := cmd.Context(); c != nil {
		return c
	}
	return context.Background()
}
