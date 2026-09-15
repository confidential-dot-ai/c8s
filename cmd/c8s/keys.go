package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/keys"

func init() {
	rootCmd.AddCommand(keys.NewCmd())
}
