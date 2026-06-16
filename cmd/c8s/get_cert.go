package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/getcert"

func init() {
	rootCmd.AddCommand(getcert.NewCmd())
}
