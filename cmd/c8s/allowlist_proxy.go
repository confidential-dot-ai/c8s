package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/allowlistproxy"

func init() {
	rootCmd.AddCommand(allowlistproxy.NewCmd())
}
