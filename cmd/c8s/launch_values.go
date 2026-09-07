package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/launchvalues"

func init() {
	rootCmd.AddCommand(launchvalues.NewCmd())
}
