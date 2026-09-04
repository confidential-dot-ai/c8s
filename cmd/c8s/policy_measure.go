package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/policymeasure"

func init() {
	rootCmd.AddCommand(policymeasure.NewCmd())
}
