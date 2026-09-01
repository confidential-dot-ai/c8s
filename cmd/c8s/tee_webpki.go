package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/teewebpki"

func init() {
	rootCmd.AddCommand(teewebpki.NewCmd())
}
