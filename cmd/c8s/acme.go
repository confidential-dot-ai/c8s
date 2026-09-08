package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/acme"

func init() {
	rootCmd.AddCommand(acme.NewCmd())
}
