package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/probefile"

func init() {
	rootCmd.AddCommand(probefile.NewCmd())
}
