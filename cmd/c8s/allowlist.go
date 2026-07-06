package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/allowlist"

func init() {
	rootCmd.AddCommand(allowlist.NewCmd())
}
