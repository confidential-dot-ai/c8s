package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/attestproxy"

func init() {
	rootCmd.AddCommand(attestproxy.NewCmd())
}
