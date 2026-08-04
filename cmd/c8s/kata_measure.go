package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/katameasure"

func init() {
	rootCmd.AddCommand(katameasure.NewCmd())
}
