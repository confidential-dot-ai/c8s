//go:build linux

// Command policy-monitor is the thin wrapper around the
// `c8s policy-monitor` cobra subcommand. The actual entry point lives
// in internal/cmds/policymonitor so the same code can be embedded in
// the multi-mode `c8s` binary if a future PR wants to. Mirrors the
// shape of cmd/ratls-mesh/main.go.
package main

import (
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/policymonitor"
)

func main() { cmdsutil.RunMain(policymonitor.Run) }
