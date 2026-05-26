package main

import "github.com/lunal-dev/c8s/internal/cmds/cds"

func init() {
	rootCmd.AddCommand(cds.NewCmd())
}
