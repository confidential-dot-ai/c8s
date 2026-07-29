package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/volumed"

func init() {
	rootCmd.AddCommand(volumed.NewCmd())
}
