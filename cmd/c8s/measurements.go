package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/measurements"

func init() {
	rootCmd.AddCommand(measurements.NewCmd())
}
