//go:build !c8s_node

package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/policydisk"

func init() {
	rootCmd.AddCommand(policydisk.NewCmd())
}
