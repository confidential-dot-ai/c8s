package main

import (
	"os"
	"syscall"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/spf13/cobra"
)

func init() {
	staged := func() (*launchconfig.Document, error) {
		return launchconfig.LoadStaged(launchconfig.DefaultStagedPath)
	}
	cmd := &cobra.Command{Use: "node-services", Short: "Run the image's authenticated host services"}
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
	cmd.AddCommand(&cobra.Command{Use: "run SERVICE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := staged()
		if err != nil {
			return err
		}
		var ip string
		if nodeservices.NeedsNodeIP(args[0]) {
			ip, err = nodeservices.NodeIP()
			if err != nil {
				return err
			}
		}
		argv, err := nodeservices.Arguments(args[0], doc, ip)
		if err != nil {
			return err
		}
		return syscall.Exec("/usr/local/bin/c8s", append([]string{"c8s"}, argv...), os.Environ())
	}})
	rootCmd.AddCommand(cmd)
}
