//go:build linux

// Command volumed is the thin wrapper around the `c8s volumed` cobra
// subcommand, for the copy baked into the kata guest rootfs. The node-side
// DaemonSet runs `c8s volumed` from the multi-mode binary instead (see the
// Dockerfile beside this file); a guest cannot, because the whole `c8s` binary
// would have to sit on the dm-verity root and in the launch measurement.
// Mirrors the shape of cmd/policy-monitor/main.go.
package main

import (
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/volumed"
)

func main() { cmdsutil.RunMain(volumed.Run) }
