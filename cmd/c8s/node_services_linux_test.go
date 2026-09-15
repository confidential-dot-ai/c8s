package main

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
)

// Exercise the real command registry: a typo in a fixed service argument must
// fail CI rather than leave the measured image in a systemd restart loop.
func TestNodeServiceArgumentsMatchCommands(t *testing.T) {
	doc := &launchconfig.Document{Role: launchconfig.Leader, Image: launchconfig.Image{Platform: "tdx"}, Leader: launchconfig.LeaderConfig{Address: "192.0.2.10"}, TLSSAN: "c8s.local"}
	for _, name := range []string{"cds", "mesh", "mesh-sync", "get-cert", "cds-attest", "allowlist-proxy", "attest-proxy", "join-release", "join"} {
		t.Run(name, func(t *testing.T) {
			roleDoc := *doc
			roleDoc.FollowerOperatorPublicKeys = []string{"authorized follower"}
			if name == "join" {
				roleDoc.Role = launchconfig.Follower
			}
			args, err := nodeservices.Arguments(name, &roleDoc, "192.0.2.10")
			if err != nil {
				t.Fatal(err)
			}
			cmd, rest, err := rootCmd.Find(args)
			if err != nil {
				t.Fatal(err)
			}
			if cmd == rootCmd {
				t.Fatalf("no command for %v", args)
			}
			if cmd.DisableFlagParsing {
				// The wrapper delegates parsing to RunE. Its --help path
				// parses every flag without starting the service.
				helpArgs := append(append([]string(nil), rest...), "--help")
				if err := cmd.RunE(cmd, helpArgs); err != nil {
					t.Fatal(err)
				}
				// Prove the delegated parser runs even with --help present.
				badArgs := append(helpArgs, "--not-a-node-service-flag=true")
				if err := cmd.RunE(cmd, badArgs); err == nil || !strings.Contains(err.Error(), "unknown flag") {
					t.Fatalf("delegated parser did not reject an unknown flag: %v", err)
				}
				return
			}
			if err := cmd.ParseFlags(rest); err != nil {
				t.Fatal(err)
			}
			if err := cmd.ValidateRequiredFlags(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
