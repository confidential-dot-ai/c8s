package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/volume"

func init() {
	rootCmd.AddCommand(volume.NewCmd())
}
