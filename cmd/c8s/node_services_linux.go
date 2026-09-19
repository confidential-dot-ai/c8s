package main

import (
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/spf13/cobra"
)

func init() {
	staged := func() (*launchconfig.Document, error) {
		return launchconfig.LoadStaged(launchconfig.DefaultStagedPath)
	}
	cmd := &cobra.Command{Use: "node-services", Short: "Prepare the image's authenticated bootstrap inputs"}
	cmd.AddCommand(&cobra.Command{Use: "prepare", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := staged()
		if err != nil {
			return err
		}
		return nodeservices.Prepare("", doc)
	}})
	cmd.AddCommand(&cobra.Command{Use: "node-ip", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := staged()
		if err != nil {
			return err
		}
		return nodeservices.PublishNodeIP("", doc)
	}})
	rootCmd.AddCommand(cmd)
}
