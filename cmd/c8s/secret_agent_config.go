package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/secretbroker"

func init() {
	rootCmd.AddCommand(secretbroker.NewAgentConfigCmd())
}
