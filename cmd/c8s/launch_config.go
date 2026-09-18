package main

import (
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

func init() {
	rootCmd.AddCommand(newNodeCmd())
	rootCmd.AddCommand(launchconfig.NewCmd())
}

func newNodeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "node", Short: "Prepare measured node launches"}
	cmd.AddCommand(launchconfig.NewCmd())
	return cmd
}
