package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/workloadproxy"

func init() {
	rootCmd.AddCommand(workloadproxy.NewCmd())
}
