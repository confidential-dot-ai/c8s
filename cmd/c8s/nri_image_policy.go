package main

import nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"

func init() {
	rootCmd.AddCommand(wrapFlagBinary(
		"nri-image-policy [flags]",
		"Run the NRI image-policy plugin",
		nriimagepolicy.Run,
	))
}
