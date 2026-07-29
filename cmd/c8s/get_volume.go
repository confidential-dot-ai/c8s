package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/getvolume"

func init() {
	rootCmd.AddCommand(getvolume.NewCmd())
}
