package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/getsecret"

func init() {
	rootCmd.AddCommand(getsecret.NewCmd())
}
