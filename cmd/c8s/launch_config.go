package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"

func init() {
	rootCmd.AddCommand(launchconfig.NewCmd())
}
