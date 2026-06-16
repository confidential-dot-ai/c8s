//go:build linux

// Command ratls-mesh is a thin wrapper around the `c8s ratls-mesh` cobra
// subcommand.
package main

import (
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/ratlsmesh"
)

func main() { cmdsutil.RunMain(ratlsmesh.Run) }
