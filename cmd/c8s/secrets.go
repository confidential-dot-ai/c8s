package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/secrets"

func init() {
	rootCmd.AddCommand(secrets.NewCmd())
}
